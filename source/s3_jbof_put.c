/*
 * s3_jbof_put.c — three-phase disaggregated PUT (placement → write → commit).
 *
 * Reuses HTTP plumbing from s3_jbof_get.c via the linker — but to keep
 * dependencies minimal we duplicate the small TCP helpers here. (The
 * production refactor extracts them into a shared TU; see
 * docs/remaining_for_complete_client.md task A1/B1 notes.)
 */

#ifdef AWS_ENABLE_JBOF

#define _GNU_SOURCE
#include <aws/s3/s3_jbof_put.h>

#include <aws/common/byte_buf.h>
#include <aws/common/error.h>
#include <aws/common/json.h>
#include <aws/common/string.h>
#include <aws/http/http.h>
#include <aws/io/io.h>
#include <aws/s3/s3.h>
#include <aws/s3/s3_jbof_sigv4.h>

#include "object_rdma/read_planner.h"
#include "object_rdma/write_planner.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define JBOF_PUT_MAX_EXTENTS    64
#define JBOF_PUT_HDR_BUF        65536
#define JBOF_PUT_BODY_BUF       131072

/* ── small HTTP / time helpers (mirror s3_jbof_get.c) ──────────────── */

static double jbof_put_now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static int jbof_put_tcp_connect(const char *ip, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    return fd;
}

static int jbof_put_send_all(int fd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int jbof_put_recv_headers(int fd, char *buf, int bufsz) {
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

static int jbof_put_recv_body(int fd, char *buf, int content_len) {
    int total = 0;
    while (total < content_len) {
        ssize_t n = recv(fd, buf + total, content_len - total, 0);
        if (n <= 0) break;
        total += (int)n;
    }
    buf[total] = '\0';
    return total;
}

static void jbof_put_header_value(const char *hdr, const char *name,
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

/* Emit signed headers when access_key/secret_key are non-empty.
 * Writes the header block (terminated with \r\n after each header) into
 * out. NOTE: Custom headers (X-S3RDMA-*, x-amz-checksum-crc32c) are NOT
 * included in the canonical signature today — see the C1 commit message
 * for the rationale. */
static void jbof_put_emit_sig_block(const struct aws_s3_jbof_put_options *o,
                                    const char *method, const char *path,
                                    const char *query, const char *host_port,
                                    char *out, size_t cap) {
    out[0] = '\0';
    if (!o->access_key.len || !o->secret_key.len) return;
    char ak[256], sk[256], st[1024], rg[64], sv[32];
    /* Mini reusable copier (same logic as get-side). */
    #define CUR(c,b) ((c).len ? (memcpy((b), (c).ptr, (c).len < sizeof(b)-1 ? (c).len : sizeof(b)-1), \
                                 (b)[(c).len < sizeof(b)-1 ? (c).len : sizeof(b)-1] = '\0', (b)) : "")
    struct aws_s3_jbof_sigv4_input in = {
        .method = method, .canonical_uri = path, .canonical_query = query,
        .host_header = host_port,
        .region  = o->region.len  ? CUR(o->region,  rg) : "us-east-1",
        .service = o->service.len ? CUR(o->service, sv) : "s3",
        .access_key = CUR(o->access_key, ak),
        .secret_key = CUR(o->secret_key, sk),
        .session_token = o->session_token.len ? CUR(o->session_token, st) : NULL,
    };
    #undef CUR
    struct aws_s3_jbof_sigv4_output svo = {0};
    if (aws_s3_jbof_sigv4_sign(&in, &svo) != AWS_OP_SUCCESS) return;

    int n = snprintf(out, cap,
        "X-Amz-Date: %s\r\n"
        "X-Amz-Content-SHA256: %s\r\n"
        "Authorization: %s\r\n",
        svo.amz_date, svo.content_sha256, svo.authorization);
    if (o->session_token.len) {
        char st2[1024];
        size_t nt = o->session_token.len < sizeof(st2) - 1
                  ? o->session_token.len : sizeof(st2) - 1;
        memcpy(st2, o->session_token.ptr, nt);
        st2[nt] = '\0';
        snprintf(out + n, cap - n, "X-Amz-Security-Token: %s\r\n", st2);
    }
}

/* ── target-device → fd resolver (open RDWR for PUT) ───────────────── */

struct jbof_put_target_map {
    const struct aws_s3_jbof_target_device *entries;
    size_t                                  count;
};

static int jbof_put_open_target(const rp_target_t *target, void *user) {
    const struct jbof_put_target_map *map = user;
    for (size_t i = 0; i < map->count; i++) {
        const struct aws_s3_jbof_target_device *e = &map->entries[i];
        if (target->nsid != e->nsid) continue;
        if (e->subnqn.len != strlen(target->subnqn)) continue;
        if (memcmp(target->subnqn, e->subnqn.ptr, e->subnqn.len) != 0) continue;
        char path[256];
        size_t n = e->device_path.len < sizeof(path) - 1
                 ? e->device_path.len : sizeof(path) - 1;
        memcpy(path, e->device_path.ptr, n);
        path[n] = '\0';
        return open(path, O_WRONLY);
    }
    return -1;
}

/* ── Phase 1: placement parse ──────────────────────────────────────── */

static int jbof_put_parse_placement_extent(struct aws_json_value *eo,
                                           wp_extent_t *out) {
    memset(out, 0, sizeof(*out));
    struct aws_json_value *v;
    struct aws_byte_cursor s;
    double d;

    v = aws_json_value_get_from_object(eo, aws_byte_cursor_from_c_str("object_offset"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) out->object_offset = (uint64_t)d;

    v = aws_json_value_get_from_object(eo, aws_byte_cursor_from_c_str("length"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) out->length = (uint64_t)d;

    v = aws_json_value_get_from_object(eo, aws_byte_cursor_from_c_str("nsid"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) out->nsid = (uint32_t)d;

    v = aws_json_value_get_from_object(eo, aws_byte_cursor_from_c_str("start_lba"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) out->start_lba = (uint64_t)d;

    v = aws_json_value_get_from_object(eo, aws_byte_cursor_from_c_str("lba_size"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) out->lba_size = (uint32_t)d;
    if (out->lba_size == 0) out->lba_size = 4096;

    v = aws_json_value_get_from_object(eo, aws_byte_cursor_from_c_str("block_count"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) out->block_count = (uint32_t)d;

    struct aws_json_value *tg = aws_json_value_get_from_object(eo,
        aws_byte_cursor_from_c_str("target"));
    if (tg) {
        v = aws_json_value_get_from_object(tg, aws_byte_cursor_from_c_str("subnqn"));
        if (v && aws_json_value_get_string(v, &s) == AWS_OP_SUCCESS) {
            size_t n = s.len < sizeof(out->subnqn) - 1 ? s.len : sizeof(out->subnqn) - 1;
            memcpy(out->subnqn, s.ptr, n);
            out->subnqn[n] = '\0';
        }
    }
    return out->length > 0 ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

/* ── Public entry: placement → write → commit ──────────────────────── */

int aws_s3_jbof_put_object(struct aws_allocator *allocator,
                           const struct aws_s3_jbof_put_options *options,
                           struct aws_s3_jbof_put_result *out_result) {
    if (!allocator || !options || !out_result) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (!options->source_buffer || options->source_length == 0) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (!options->target_devices || options->target_device_count == 0) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    memset(out_result, 0, sizeof(*out_result));

    char host_z[64];
    size_t hlen = options->meta_server_host.len < sizeof(host_z) - 1
                ? options->meta_server_host.len : sizeof(host_z) - 1;
    memcpy(host_z, options->meta_server_host.ptr, hlen);
    host_z[hlen] = '\0';

    double t0 = jbof_put_now_sec();

    /* ── Phase 1: placement request ────────────────────────────────── */
    int sock = jbof_put_tcp_connect(host_z, options->meta_server_port);
    if (sock < 0) return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);

    char path[512];
    snprintf(path, sizeof(path), "/%.*s/%.*s",
             (int)options->bucket.len, options->bucket.ptr,
             (int)options->key.len, options->key.ptr);
    char host_port[96];
    snprintf(host_port, sizeof(host_port), "%s:%u",
             host_z, (unsigned)options->meta_server_port);
    char sig_block[1536];
    jbof_put_emit_sig_block(options, "PUT", path, "", host_port,
                            sig_block, sizeof(sig_block));

    char req[2048];
    int reqlen = snprintf(req, sizeof(req),
        "PUT /%.*s/%.*s HTTP/1.0\r\n"
        "Host: %s:%u\r\n"
        "Accept: application/vnd.s3rdma.placement+json\r\n"
        "X-S3RDMA-Object-Size: %zu\r\n"
        "Content-Length: 0\r\n"
        "%s"
        "\r\n",
        (int)options->bucket.len, options->bucket.ptr,
        (int)options->key.len,    options->key.ptr,
        host_z, (unsigned)options->meta_server_port,
        options->source_length,
        sig_block);
    if (jbof_put_send_all(sock, req, (size_t)reqlen) < 0) {
        close(sock);
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }

    char hdr_buf[JBOF_PUT_HDR_BUF];
    int hdrlen = jbof_put_recv_headers(sock, hdr_buf, sizeof(hdr_buf));
    /* Accept 200 or 202 for placement. */
    if (hdrlen < 12 || (!strstr(hdr_buf, " 200 ") && !strstr(hdr_buf, " 202 "))) {
        close(sock);
        return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
    }
    const char *cl = strstr(hdr_buf, "Content-Length:");
    int content_len = cl ? atoi(cl + 15) : 0;
    if (content_len <= 0 || content_len >= JBOF_PUT_BODY_BUF - 1) {
        close(sock);
        return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
    }
    char *body = aws_mem_calloc(allocator, 1, (size_t)content_len + 1);
    if (!body) { close(sock); return aws_raise_error(AWS_ERROR_OOM); }
    int body_len = jbof_put_recv_body(sock, body, content_len);
    close(sock);
    if (body_len < content_len) {
        aws_mem_release(allocator, body);
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }

    char write_token[128];
    jbof_put_header_value(hdr_buf, "X-S3RDMA-Write-Token",
                          write_token, sizeof(write_token));
    if (!write_token[0]) {
        aws_mem_release(allocator, body);
        return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
    }

    /* Parse placement extents. */
    struct aws_byte_cursor bc = aws_byte_cursor_from_array(body, (size_t)body_len);
    struct aws_json_value *root = aws_json_value_new_from_string(allocator, bc);
    aws_mem_release(allocator, body);
    if (!root) return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);

    struct aws_json_value *exts = aws_json_value_get_from_object(
        root, aws_byte_cursor_from_c_str("extents"));
    if (!exts || !aws_json_value_is_array(exts)) {
        aws_json_value_destroy(root);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    size_t n_extents = aws_json_get_array_size(exts);
    if (n_extents == 0 || n_extents > JBOF_PUT_MAX_EXTENTS) {
        aws_json_value_destroy(root);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    wp_extent_t *placement = aws_mem_calloc(allocator, n_extents, sizeof(wp_extent_t));
    if (!placement) {
        aws_json_value_destroy(root);
        return aws_raise_error(AWS_ERROR_OOM);
    }
    size_t total_bytes = 0;
    for (size_t i = 0; i < n_extents; i++) {
        struct aws_json_value *eo = aws_json_get_array_element(exts, i);
        if (!eo || jbof_put_parse_placement_extent(eo, &placement[i]) != AWS_OP_SUCCESS) {
            aws_mem_release(allocator, placement);
            aws_json_value_destroy(root);
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }
        total_bytes += (size_t)placement[i].length;
    }
    aws_json_value_destroy(root);

    if (total_bytes != options->source_length) {
        aws_mem_release(allocator, placement);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* ── Phase 2: pwrite via write_planner ─────────────────────────── */
    wp_write_work_t *work = NULL;
    int n_work = 0;
    int rc = wp_plan_build(placement, (int)n_extents, options->source_buffer,
                           &work, &n_work);
    aws_mem_release(allocator, placement);
    if (rc != RP_OK) return aws_raise_error(AWS_ERROR_UNKNOWN);

    struct jbof_put_target_map map = {
        .entries = options->target_devices,
        .count   = options->target_device_count,
    };
    rp_planner_config_t pcfg = {
        .worker_threads   = options->workers_per_target,
        .open_target      = jbof_put_open_target,
        .open_target_user = &map,
        /* skip_crc is irrelevant for write; we compute CRC inline if host
         * build provides cpu_crc32c. CUDA build: helper computes a full-
         * buffer CRC32C on commit; per-extent CRCs not needed yet. */
        .skip_crc         = 1,
    };
    wp_write_result_t wr = {0};
    int prc = wp_execute(work, n_work, &pcfg, &wr);
    free(work);
    if (prc != RP_OK) {
        wp_write_result_clean_up(&wr);
        return aws_raise_error(AWS_ERROR_S3_INTERNAL_ERROR);
    }

    /* Full-object CRC32C: try GPU (nvcomp) first; fall back to CPU when
     * the source isn't CUDA-reachable (or nvcomp fails). */
    extern uint32_t jbof_put_full_crc_cuda(const void *src, size_t len);
    uint32_t full_crc = jbof_put_full_crc_cuda(options->source_buffer,
                                                options->source_length);
    if (full_crc == 0) {
        /* CPU fallback (also taken when CRC happens to be 0). */
        static uint32_t table[256];
        static int built = 0;
        if (!built) {
            for (uint32_t i = 0; i < 256; i++) {
                uint32_t c = i;
                for (int k = 0; k < 8; k++)
                    c = (c >> 1) ^ (0x82F63B78u & -(int32_t)(c & 1));
                table[i] = c;
            }
            built = 1;
        }
        full_crc = 0xFFFFFFFFu;
        const uint8_t *p = options->source_buffer;
        for (size_t i = 0; i < options->source_length; i++)
            full_crc = (full_crc >> 8) ^ table[(full_crc ^ p[i]) & 0xFF];
        full_crc ^= 0xFFFFFFFFu;
    }
    wp_write_result_clean_up(&wr);

    /* ── Phase 3: commit ──────────────────────────────────────────── */
    int csock = jbof_put_tcp_connect(host_z, options->meta_server_port);
    if (csock < 0) return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);

    char csig[1536];
    jbof_put_emit_sig_block(options, "PUT", path, "rdma-commit=", host_port,
                            csig, sizeof(csig));

    char creq[2048];
    int crlen = snprintf(creq, sizeof(creq),
        "PUT /%.*s/%.*s?rdma-commit HTTP/1.0\r\n"
        "Host: %s:%u\r\n"
        "X-S3RDMA-Write-Token: %s\r\n"
        "x-amz-checksum-crc32c: %u\r\n"
        "Content-Length: 0\r\n"
        "%s"
        "\r\n",
        (int)options->bucket.len, options->bucket.ptr,
        (int)options->key.len,    options->key.ptr,
        host_z, (unsigned)options->meta_server_port,
        write_token,
        full_crc,
        csig);
    if (jbof_put_send_all(csock, creq, (size_t)crlen) < 0) {
        close(csock);
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }
    char chdr[JBOF_PUT_HDR_BUF];
    int chlen = jbof_put_recv_headers(csock, chdr, sizeof(chdr));
    close(csock);
    if (chlen < 12 || !strstr(chdr, " 200 ")) {
        return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
    }
    char etag_v[256];
    jbof_put_header_value(chdr, "ETag", etag_v, sizeof(etag_v));
    if (etag_v[0]) {
        size_t l = strlen(etag_v);
        out_result->etag = aws_mem_calloc(allocator, 1, l + 1);
        if (out_result->etag) memcpy(out_result->etag, etag_v, l);
    }
    out_result->bytes_written       = options->source_length;
    out_result->elapsed_seconds     = jbof_put_now_sec() - t0;
    out_result->full_object_crc32c  = full_crc;
    return AWS_OP_SUCCESS;
}

void aws_s3_jbof_put_result_clean_up(struct aws_allocator *allocator,
                                     struct aws_s3_jbof_put_result *result) {
    if (!allocator || !result) return;
    if (result->etag) {
        aws_mem_release(allocator, result->etag);
        result->etag = NULL;
    }
}

#endif /* AWS_ENABLE_JBOF */
