/*
 * s3_jbof_mpu.c — JBOF multipart upload (MPU) implementation (Task B4).
 *
 * Three-phase flow per part (same as single-part PUT):
 *   placement → pwrite → commit
 *
 * Control plane calls (CreateMultipartUpload, CompleteMultipartUpload,
 * AbortMultipartUpload) use plain HTTP/1.0 to the metadata server, following
 * the same TCP helper pattern established in s3_jbof_put.c.
 *
 * When JBOF_MOCK_MPU_STUB is defined at compile time the CreateMultipartUpload
 * HTTP call is replaced with a synthetic upload_id so the code can be exercised
 * without a server that understands the MPU control plane.
 */

#ifdef AWS_ENABLE_JBOF

#define _GNU_SOURCE
#include <aws/s3/s3_jbof_mpu.h>
#include <aws/s3/s3_jbof_put.h>

#include <aws/common/allocator.h>
#include <aws/common/error.h>
#include <aws/http/http.h>
#include <aws/s3/s3.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ── buffer sizes ─────────────────────────────────────────────────────── */

#define JBOF_MPU_HDR_BUF    65536
#define JBOF_MPU_BODY_BUF   131072
#define JBOF_MPU_XML_BUF    524288   /* 512 KiB: up to 10000 parts × ~50 bytes */
#define JBOF_MPU_KEY_MAX    1024     /* max key length including query suffix */

/* ── opaque handle ────────────────────────────────────────────────────── */

struct aws_s3_jbof_mpu {
    struct aws_allocator       *allocator;
    struct aws_s3_jbof_mpu_options options;   /* deep copy of caller options */
    char                        upload_id[256];
    size_t                      part_size;
    double                      t_create;    /* wall clock at create time */

    /* Storage for deep copies of aws_byte_cursor string fields. */
    char  _host[64];
    char  _bucket[256];
    char  _key[JBOF_MPU_KEY_MAX];
    char  _access_key[256];
    char  _secret_key[256];
    char  _session_token[1024];
    char  _region[64];
    char  _service[32];
};

/* ── minimal TCP / HTTP helpers (mirror s3_jbof_put.c static helpers) ── */

static double jbof_mpu_now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static int jbof_mpu_tcp_connect(const char *ip, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int jbof_mpu_send_all(int fd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

/* Read until \r\n\r\n or buffer full.  Returns bytes consumed. */
static int jbof_mpu_recv_headers(int fd, char *buf, int bufsz) {
    int total = 0;
    while (total < bufsz - 1) {
        ssize_t n = recv(fd, buf + total, 1, 0);
        if (n <= 0) break;
        total++;
        if (total >= 4 && memcmp(buf + total - 4, "\r\n\r\n", 4) == 0) break;
    }
    buf[total] = '\0';
    return total;
}

static int jbof_mpu_recv_body(int fd, char *buf, int content_len) {
    int total = 0;
    while (total < content_len) {
        ssize_t n = recv(fd, buf + total, content_len - total, 0);
        if (n <= 0) break;
        total += (int)n;
    }
    buf[total] = '\0';
    return total;
}

/* Extract the value of a response header by name (case-insensitive). */
static void jbof_mpu_header_value(const char *hdr, const char *name,
                                  char *out, size_t outsz) {
    out[0] = '\0';
    size_t name_len = strlen(name);
    const char *p = hdr;
    while (*p) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;
        if ((size_t)(eol - p) > name_len + 1 &&
            strncasecmp(p, name, name_len) == 0 && p[name_len] == ':') {
            const char *v = p + name_len + 1;
            while (*v == ' ' || *v == '\t') v++;
            size_t vlen = (size_t)(eol - v);
            if (vlen >= outsz) vlen = outsz - 1;
            memcpy(out, v, vlen);
            out[vlen] = '\0';
            return;
        }
        p = eol + 2;
    }
}

/* Find "upload_id" : "<value>" in a JSON response body (simple scan,
 * no full parser dependency). */
static void jbof_mpu_parse_upload_id(const char *body, char *out, size_t outsz) {
    out[0] = '\0';
    const char *p = strstr(body, "\"upload_id\"");
    if (!p) p = strstr(body, "\"UploadId\"");
    if (!p) return;
    p = strchr(p, ':');
    if (!p) return;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != '"') return;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < outsz - 1)
        out[i++] = *p++;
    out[i] = '\0';
}

/* Extract the final ETag from the CompleteMultipartUpload XML response.
 * Looks for <ETag>...</ETag> at the top level (not inside <Part>). */
static void jbof_mpu_parse_final_etag(const char *body, char *out, size_t outsz) {
    out[0] = '\0';
    /* Skip past any <Part> sections to find the top-level <ETag>. */
    const char *search = body;
    const char *last_match = NULL;
    while ((search = strstr(search, "<ETag>")) != NULL) {
        last_match = search;
        search += 6;
    }
    if (!last_match) return;
    const char *start = last_match + 6;
    const char *end   = strstr(start, "</ETag>");
    if (!end) return;
    size_t len = (size_t)(end - start);
    if (len >= outsz) len = outsz - 1;
    memcpy(out, start, len);
    out[len] = '\0';
}

/* ── cursor → fixed buffer helper ────────────────────────────────────── */

static void jbof_mpu_cursor_to_buf(struct aws_byte_cursor cur,
                                   char *buf, size_t bufsz) {
    size_t n = cur.len < bufsz - 1 ? cur.len : bufsz - 1;
    if (n) memcpy(buf, cur.ptr, n);
    buf[n] = '\0';
}

/* ── aws_s3_jbof_mpu_create ──────────────────────────────────────────── */

struct aws_s3_jbof_mpu *aws_s3_jbof_mpu_create(
        struct aws_allocator *allocator,
        const struct aws_s3_jbof_mpu_options *options) {

    if (!allocator || !options) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }
    if (!options->bucket.len || !options->key.len) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }
    if (!options->target_devices || options->target_device_count == 0) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_s3_jbof_mpu *mpu =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_s3_jbof_mpu));
    if (!mpu) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    mpu->allocator = allocator;
    mpu->t_create  = jbof_mpu_now_sec();
    mpu->part_size = options->part_size > 0
                   ? options->part_size
                   : JBOF_MPU_DEFAULT_PART_SIZE;

    /* Deep-copy options: copy string cursors into private buffers, then
     * rebuild cursors to point into those buffers. */
    jbof_mpu_cursor_to_buf(options->meta_server_host, mpu->_host,    sizeof(mpu->_host));
    jbof_mpu_cursor_to_buf(options->bucket,           mpu->_bucket,  sizeof(mpu->_bucket));
    jbof_mpu_cursor_to_buf(options->key,              mpu->_key,     sizeof(mpu->_key));
    jbof_mpu_cursor_to_buf(options->access_key,       mpu->_access_key,    sizeof(mpu->_access_key));
    jbof_mpu_cursor_to_buf(options->secret_key,       mpu->_secret_key,    sizeof(mpu->_secret_key));
    jbof_mpu_cursor_to_buf(options->session_token,    mpu->_session_token, sizeof(mpu->_session_token));
    jbof_mpu_cursor_to_buf(options->region,           mpu->_region,  sizeof(mpu->_region));
    jbof_mpu_cursor_to_buf(options->service,          mpu->_service, sizeof(mpu->_service));

    mpu->options = *options;
    mpu->options.meta_server_host = aws_byte_cursor_from_c_str(mpu->_host);
    mpu->options.bucket           = aws_byte_cursor_from_c_str(mpu->_bucket);
    mpu->options.key              = aws_byte_cursor_from_c_str(mpu->_key);
    mpu->options.access_key       = aws_byte_cursor_from_c_str(mpu->_access_key);
    mpu->options.secret_key       = aws_byte_cursor_from_c_str(mpu->_secret_key);
    mpu->options.session_token    = aws_byte_cursor_from_c_str(mpu->_session_token);
    mpu->options.region           = aws_byte_cursor_from_c_str(mpu->_region);
    mpu->options.service          = aws_byte_cursor_from_c_str(mpu->_service);
    /* target_devices pointer is borrowed from caller for the lifetime of mpu */

    /* Ensure verify_crc defaults to 1 */
    if (!mpu->options.verify_crc) mpu->options.verify_crc = 1;

#ifdef JBOF_MOCK_MPU_STUB
    /* ── MOCK PATH: generate a synthetic upload_id without HTTP ───── */
    snprintf(mpu->upload_id, sizeof(mpu->upload_id), "MOCK-MPU-001");
    return mpu;
#else
    /* ── REAL PATH: POST /<bucket>/<key>?uploads ──────────────────── */
    char host_port[96];
    snprintf(host_port, sizeof(host_port), "%s:%u",
             mpu->_host, (unsigned)options->meta_server_port);

    char req[2048];
    int reqlen = snprintf(req, sizeof(req),
        "POST /%s/%s?uploads HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        mpu->_bucket, mpu->_key,
        host_port);

    int fd = jbof_mpu_tcp_connect(mpu->_host, options->meta_server_port);
    if (fd < 0) {
        aws_mem_release(allocator, mpu);
        aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
        return NULL;
    }
    if (jbof_mpu_send_all(fd, req, (size_t)reqlen) < 0) {
        close(fd);
        aws_mem_release(allocator, mpu);
        aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
        return NULL;
    }

    char hdr_buf[JBOF_MPU_HDR_BUF];
    int hdrlen = jbof_mpu_recv_headers(fd, hdr_buf, sizeof(hdr_buf));
    if (hdrlen < 12 || (!strstr(hdr_buf, " 200 ") && !strstr(hdr_buf, " 201 "))) {
        close(fd);
        aws_mem_release(allocator, mpu);
        aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
        return NULL;
    }

    const char *cl_hdr = strstr(hdr_buf, "Content-Length:");
    int content_len = cl_hdr ? atoi(cl_hdr + 15) : 0;
    char body_buf[JBOF_MPU_BODY_BUF];
    if (content_len > 0 && content_len < (int)sizeof(body_buf) - 1) {
        jbof_mpu_recv_body(fd, body_buf, content_len);
    } else {
        /* Read whatever arrived (chunked or unknown length). */
        int n = recv(fd, body_buf, sizeof(body_buf) - 1, 0);
        body_buf[n > 0 ? n : 0] = '\0';
    }
    close(fd);

    /* Try JSON "upload_id" field first, then X-Upload-ID header. */
    jbof_mpu_parse_upload_id(body_buf, mpu->upload_id, sizeof(mpu->upload_id));
    if (!mpu->upload_id[0]) {
        jbof_mpu_header_value(hdr_buf, "X-Upload-ID",
                              mpu->upload_id, sizeof(mpu->upload_id));
    }
    if (!mpu->upload_id[0]) {
        aws_mem_release(allocator, mpu);
        aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
        return NULL;
    }

    return mpu;
#endif /* JBOF_MOCK_MPU_STUB */
}

/* ── aws_s3_jbof_mpu_upload_part ─────────────────────────────────────── */

int aws_s3_jbof_mpu_upload_part(
        struct aws_s3_jbof_mpu *mpu,
        int                     part_number,
        const void             *source_buffer,
        size_t                  source_length,
        struct aws_s3_jbof_mpu_part_result *part_result) {

    if (!mpu || !source_buffer || source_length == 0 || !part_result) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (part_number < 1 || part_number > JBOF_MPU_MAX_PARTS) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* Build the part key: "<original_key>?partNumber=<N>&uploadId=<id>" */
    char part_key[JBOF_MPU_KEY_MAX];
    int pk_len = snprintf(part_key, sizeof(part_key),
                          "%s?partNumber=%d&uploadId=%s",
                          mpu->_key, part_number, mpu->upload_id);
    if (pk_len < 0 || (size_t)pk_len >= sizeof(part_key)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    struct aws_s3_jbof_put_options put_opts;
    memset(&put_opts, 0, sizeof(put_opts));
    put_opts.meta_server_host   = mpu->options.meta_server_host;
    put_opts.meta_server_port   = mpu->options.meta_server_port;
    put_opts.bucket             = mpu->options.bucket;
    put_opts.key                = aws_byte_cursor_from_array(
                                      (const uint8_t *)part_key, (size_t)pk_len);
    put_opts.source_buffer      = source_buffer;
    put_opts.source_length      = source_length;
    put_opts.target_devices     = mpu->options.target_devices;
    put_opts.target_device_count = mpu->options.target_device_count;
    put_opts.workers_per_target = mpu->options.workers_per_target;
    put_opts.access_key         = mpu->options.access_key;
    put_opts.secret_key         = mpu->options.secret_key;
    put_opts.session_token      = mpu->options.session_token;
    put_opts.region             = mpu->options.region;
    put_opts.service            = mpu->options.service;

    struct aws_s3_jbof_put_result put_result;
    memset(&put_result, 0, sizeof(put_result));

    int rc = aws_s3_jbof_put_object(mpu->allocator, &put_opts, &put_result);
    if (rc != AWS_OP_SUCCESS) {
        aws_s3_jbof_put_result_clean_up(mpu->allocator, &put_result);
        return rc;
    }

    part_result->part_number = part_number;
    part_result->etag[0]     = '\0';
    if (put_result.etag) {
        size_t elen = strlen(put_result.etag);
        if (elen >= sizeof(part_result->etag))
            elen = sizeof(part_result->etag) - 1;
        memcpy(part_result->etag, put_result.etag, elen);
        part_result->etag[elen] = '\0';
    }

    aws_s3_jbof_put_result_clean_up(mpu->allocator, &put_result);
    return AWS_OP_SUCCESS;
}

/* ── aws_s3_jbof_mpu_complete ────────────────────────────────────────── */

int aws_s3_jbof_mpu_complete(
        struct aws_s3_jbof_mpu *mpu,
        const struct aws_s3_jbof_mpu_part_result *part_results,
        size_t part_count,
        struct aws_s3_jbof_mpu_result *out_result) {

    if (!mpu || !part_results || part_count == 0 || !out_result) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    memset(out_result, 0, sizeof(*out_result));

    /* Build the CompleteMultipartUpload XML body. */
    char *xml = aws_mem_calloc(mpu->allocator, 1, JBOF_MPU_XML_BUF);
    if (!xml) return aws_raise_error(AWS_ERROR_OOM);

    int xml_off = snprintf(xml, JBOF_MPU_XML_BUF,
                           "<CompleteMultipartUpload>");
    for (size_t i = 0; i < part_count; i++) {
        xml_off += snprintf(xml + xml_off, JBOF_MPU_XML_BUF - xml_off,
                            "<Part>"
                            "<PartNumber>%d</PartNumber>"
                            "<ETag>%s</ETag>"
                            "</Part>",
                            part_results[i].part_number,
                            part_results[i].etag);
        if (xml_off >= JBOF_MPU_XML_BUF - 64) {
            aws_mem_release(mpu->allocator, xml);
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }
    }
    xml_off += snprintf(xml + xml_off, JBOF_MPU_XML_BUF - xml_off,
                        "</CompleteMultipartUpload>");

    char host_port[96];
    snprintf(host_port, sizeof(host_port), "%s:%u",
             mpu->_host, (unsigned)mpu->options.meta_server_port);

    char req_hdr[1024];
    int hdrlen = snprintf(req_hdr, sizeof(req_hdr),
        "POST /%s/%s?uploadId=%s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Content-Type: application/xml\r\n"
        "Content-Length: %d\r\n"
        "\r\n",
        mpu->_bucket, mpu->_key, mpu->upload_id,
        host_port,
        xml_off);

    int fd = jbof_mpu_tcp_connect(mpu->_host, mpu->options.meta_server_port);
    if (fd < 0) {
        aws_mem_release(mpu->allocator, xml);
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }
    if (jbof_mpu_send_all(fd, req_hdr, (size_t)hdrlen) < 0 ||
        jbof_mpu_send_all(fd, xml, (size_t)xml_off) < 0) {
        close(fd);
        aws_mem_release(mpu->allocator, xml);
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }
    aws_mem_release(mpu->allocator, xml);

    char hdr_buf[JBOF_MPU_HDR_BUF];
    int resp_hdrlen = jbof_mpu_recv_headers(fd, hdr_buf, sizeof(hdr_buf));
    if (resp_hdrlen < 12 ||
        (!strstr(hdr_buf, " 200 ") && !strstr(hdr_buf, " 201 "))) {
        close(fd);
        return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
    }

    const char *cl_hdr = strstr(hdr_buf, "Content-Length:");
    int content_len = cl_hdr ? atoi(cl_hdr + 15) : 0;
    char body_buf[JBOF_MPU_BODY_BUF];
    body_buf[0] = '\0';
    if (content_len > 0 && content_len < (int)sizeof(body_buf) - 1) {
        jbof_mpu_recv_body(fd, body_buf, content_len);
    } else {
        int n = recv(fd, body_buf, sizeof(body_buf) - 1, 0);
        body_buf[n > 0 ? n : 0] = '\0';
    }
    close(fd);

    /* Extract final ETag from XML response body. */
    char final_etag[256];
    jbof_mpu_parse_final_etag(body_buf, final_etag, sizeof(final_etag));
    if (!final_etag[0]) {
        /* Fall back to ETag response header. */
        jbof_mpu_header_value(hdr_buf, "ETag", final_etag, sizeof(final_etag));
    }

    if (final_etag[0]) {
        size_t elen = strlen(final_etag);
        out_result->etag = aws_mem_calloc(mpu->allocator, 1, elen + 1);
        if (out_result->etag) memcpy(out_result->etag, final_etag, elen);
    }
    out_result->elapsed_seconds = jbof_mpu_now_sec() - mpu->t_create;
    /* bytes_written is not tracked here — caller sums part sizes if needed. */

    return AWS_OP_SUCCESS;
}

/* ── aws_s3_jbof_mpu_abort ───────────────────────────────────────────── */

void aws_s3_jbof_mpu_abort(struct aws_s3_jbof_mpu *mpu) {
    if (!mpu) return;

    /* Send DELETE /<bucket>/<key>?uploadId=<id>.
     * Best-effort: ignore errors (we are already on the failure path). */
    char host_port[96];
    snprintf(host_port, sizeof(host_port), "%s:%u",
             mpu->_host, (unsigned)mpu->options.meta_server_port);

    char req[1024];
    int reqlen = snprintf(req, sizeof(req),
        "DELETE /%s/%s?uploadId=%s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        mpu->_bucket, mpu->_key, mpu->upload_id,
        host_port);

    int fd = jbof_mpu_tcp_connect(mpu->_host, mpu->options.meta_server_port);
    if (fd >= 0) {
        jbof_mpu_send_all(fd, req, (size_t)reqlen);
        /* Drain response (best-effort). */
        char tmp[4096];
        recv(fd, tmp, sizeof(tmp) - 1, 0);
        close(fd);
    }

    aws_s3_jbof_mpu_destroy(mpu);
}

/* ── aws_s3_jbof_mpu_destroy ─────────────────────────────────────────── */

void aws_s3_jbof_mpu_destroy(struct aws_s3_jbof_mpu *mpu) {
    if (!mpu) return;
    aws_mem_release(mpu->allocator, mpu);
}

#endif /* AWS_ENABLE_JBOF */
