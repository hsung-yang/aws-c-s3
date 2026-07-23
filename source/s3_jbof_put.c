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
#include <aws/common/encoding.h>
#include <aws/common/error.h>
#include <aws/common/json.h>
#include <aws/common/string.h>
#include <aws/http/http.h>
#include <aws/io/io.h>
#include <aws/s3/s3.h>
#include <aws/s3/s3_jbof_sigv4.h>

#include "object_rdma/read_planner.h"
#include "object_rdma/write_planner.h"
#ifdef WITH_SPDK_BYPASS
#include "object_rdma/spdk_bypass.h"
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define JBOF_PUT_MAX_EXTENTS    8192
#define JBOF_PUT_HDR_BUF        65536
#define JBOF_PUT_BODY_BUF       1048576
/* URI-encoding scratch sizes: S3 keys are capped at 1024 raw bytes, but
 * percent-encoding can triple that in the worst case (every byte -> "%XX");
 * bucket names are capped at 63 raw bytes. Generous vs. both limits. */
#define JBOF_PUT_BUCKET_ENC_BUF 256
#define JBOF_PUT_KEY_ENC_BUF    4096
#define JBOF_PUT_PATH_BUF       (JBOF_PUT_BUCKET_ENC_BUF + JBOF_PUT_KEY_ENC_BUF + 512)

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

static int jbof_put_recv_headers(int fd, char *buf, int bufsz, int *body_preread) {
    *body_preread = 0;
    int total = 0;
    while (total < bufsz - 1) {
        ssize_t n = recv(fd, buf + total, bufsz - 1 - total, 0);
        if (n <= 0) break;
        total += (int)n;
        int scan_from = total - (int)n - 3;
        if (scan_from < 0) scan_from = 0;
        for (int i = scan_from; i <= total - 4; i++) {
            if (memcmp(buf + i, "\r\n\r\n", 4) == 0) {
                int hdr_end = i + 4;
                *body_preread = total - hdr_end;
                /* Caller must null-terminate at buf[hdr_end] if needed;
                 * we don't do it here to avoid clobbering pre-read body
                 * bytes that start at buf[hdr_end]. */
                return hdr_end;
            }
        }
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
    if (n < 0 || (size_t)n >= cap) {
        /* Truncated (or encoding error). Bail out to an empty sig block
         * rather than let the session-token append below compute
         * `out + n` / `cap - n` with n >= cap -- that pointer/size pair
         * would be out of bounds and the subsequent snprintf would write
         * past the end of `out`. */
        out[0] = '\0';
        return;
    }
    if (o->session_token.len) {
        char st2[1024];
        size_t nt = o->session_token.len < sizeof(st2) - 1
                  ? o->session_token.len : sizeof(st2) - 1;
        memcpy(st2, o->session_token.ptr, nt);
        st2[nt] = '\0';
        snprintf(out + n, cap - n, "X-Amz-Security-Token: %s\r\n", st2);
    }
}

/* ── URI encoding (object keys/bucket names may contain reserved bytes) ── */

/* Percent-encode every byte of `in` except the unreserved set
 * [A-Za-z0-9-._~] and '/' (kept raw since keys are path segments and
 * routinely contain '/'). Mirrors snprintf()'s truncation convention:
 * returns the number of bytes that WOULD have been written (excluding
 * the NUL), so the caller can detect truncation via `return >= out_cap`
 * exactly like the snprintf() call sites elsewhere in this file. Always
 * NUL-terminates within out_cap when out_cap > 0. */
static size_t jbof_put_uri_encode(const char *in, size_t in_len,
                                  char *out, size_t out_cap) {
    static const char hex[] = "0123456789ABCDEF";
    size_t needed = 0;
    size_t oi = 0;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];
        int unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                         (c >= '0' && c <= '9') ||
                         c == '-' || c == '.' || c == '_' || c == '~' || c == '/';
        if (unreserved) {
            needed += 1;
            if (out_cap > 0 && oi + 1 < out_cap) out[oi++] = (char)c;
        } else {
            needed += 3;
            if (out_cap > 0 && oi + 3 < out_cap) {
                out[oi++] = '%';
                out[oi++] = hex[(c >> 4) & 0xF];
                out[oi++] = hex[c & 0xF];
            }
        }
    }
    if (out_cap > 0) out[oi < out_cap ? oi : out_cap - 1] = '\0';
    return needed;
}

/* ── CPU CRC32C fallback (used only when the source buffer is confirmed
 * to be plain host memory that jbof_put_full_crc_cuda() could not/would
 * not touch on the GPU -- see the call site in aws_s3_jbof_put_object()
 * and the return-code contract documented in s3_jbof_put_crc_cuda.c). ── */

static uint32_t jbof_put_crc32c_table[256];
static pthread_once_t jbof_put_crc32c_once = PTHREAD_ONCE_INIT;

static void jbof_put_crc32c_table_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c >> 1) ^ (0x82F63B78u & -(int32_t)(c & 1));
        jbof_put_crc32c_table[i] = c;
    }
}

/* CRC32C (Castagnoli) over [buf, buf+len). The table used to be built
 * behind a plain `static int built` flag with no synchronization -- two
 * PUTs racing on first use could have one thread read table[] entries
 * that the other thread hadn't finished writing yet (a real data race,
 * not just a benign redundant-init). pthread_once guarantees the table
 * is fully built, with the necessary memory barrier, before any caller
 * proceeds. */
static uint32_t jbof_put_crc32c_cpu(const void *buf, size_t len) {
    pthread_once(&jbof_put_crc32c_once, jbof_put_crc32c_table_init);
    uint32_t crc = 0xFFFFFFFFu;
    const uint8_t *p = buf;
    for (size_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ jbof_put_crc32c_table[(crc ^ p[i]) & 0xFF];
    return crc ^ 0xFFFFFFFFu;
}

struct jbof_put_crc_args {
    const void *src;
    size_t      len;
    uint32_t    crc;
    int         rc;
};

static void *jbof_put_crc_thread_fn(void *arg) {
    struct jbof_put_crc_args *a = (struct jbof_put_crc_args *)arg;
    extern int jbof_put_full_crc_cuda(const void *src, size_t len, uint32_t *out_crc);
    a->rc = jbof_put_full_crc_cuda(a->src, a->len, &a->crc);
    return NULL;
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

#ifdef WITH_SPDK_BYPASS
static int jbof_put_parse_to_write_work(struct aws_json_value *eo,
                                        rp_spdk_write_work_t *out,
                                        uint64_t *out_object_offset) {
    memset(out, 0, sizeof(*out));
    struct aws_json_value *v;
    struct aws_byte_cursor s;
    double d;

    uint64_t object_offset = 0;
    uint64_t start_lba = 0;
    uint32_t lba_size = 0;
    uint32_t data_offset_in_first_lba = 0;

    v = aws_json_value_get_from_object(eo, aws_byte_cursor_from_c_str("object_offset"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) object_offset = (uint64_t)d;

    v = aws_json_value_get_from_object(eo, aws_byte_cursor_from_c_str("length"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) out->valid_bytes = (uint64_t)d;

    v = aws_json_value_get_from_object(eo, aws_byte_cursor_from_c_str("nsid"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) out->target.nsid = (uint32_t)d;

    v = aws_json_value_get_from_object(eo, aws_byte_cursor_from_c_str("start_lba"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) start_lba = (uint64_t)d;

    v = aws_json_value_get_from_object(eo, aws_byte_cursor_from_c_str("lba_size"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) lba_size = (uint32_t)d;
    if (lba_size == 0) lba_size = 4096;
    out->lba_size = lba_size;

    v = aws_json_value_get_from_object(eo, aws_byte_cursor_from_c_str("data_offset_in_first_lba"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) data_offset_in_first_lba = (uint32_t)d;

    out->byte_offset = start_lba * lba_size + data_offset_in_first_lba;
    *out_object_offset = object_offset;

    struct aws_json_value *tg = aws_json_value_get_from_object(eo,
        aws_byte_cursor_from_c_str("target"));
    if (tg) {
        v = aws_json_value_get_from_object(tg, aws_byte_cursor_from_c_str("subnqn"));
        if (v && aws_json_value_get_string(v, &s) == AWS_OP_SUCCESS) {
            size_t n = s.len < sizeof(out->target.subnqn) - 1 ? s.len : sizeof(out->target.subnqn) - 1;
            memcpy(out->target.subnqn, s.ptr, n);
            out->target.subnqn[n] = '\0';
        }
    }
    return out->valid_bytes > 0 ? AWS_OP_SUCCESS : AWS_OP_ERR;
}
#endif /* WITH_SPDK_BYPASS */

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

    /* Pre-initialize CUDA context + persistent resources in the main
     * thread so the CRC thread doesn't trigger lazy CUDA context init
     * during phase 1 (which adds ~15-30ms of contention). */
    extern void jbof_put_crc_cuda_init(void);
    jbof_put_crc_cuda_init();

    /* Launch CRC computation before phase 1 — the CRC only needs
     * source_buffer+source_length, which are available now. This gives
     * the GPU CRC a ~7 ms head start (phase 1 placement round-trip)
     * before the SPDK write even begins. */
    struct jbof_put_crc_args crc_args = {
        .src = options->source_buffer,
        .len = options->source_length,
        .crc = 0,
        .rc  = -1,
    };
    pthread_t crc_thread;
    int crc_launched = 0;
    if (pthread_create(&crc_thread, NULL, jbof_put_crc_thread_fn, &crc_args) == 0) {
        crc_launched = 1;
    }

    double t0 = jbof_put_now_sec();

    /* ── Phase 1: placement request ────────────────────────────────── */
    int sock = jbof_put_tcp_connect(host_z, options->meta_server_port);
    if (sock < 0) { if (crc_launched) pthread_join(crc_thread, NULL); return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED); }

    /* Build the request path with the bucket/key percent-encoded (a raw
     * '?' or space in a key used to truncate/corrupt the request line --
     * see the fix note above jbof_put_uri_encode()). options->key may
     * already carry a literal query string for MPU part uploads
     * ("<key>?partNumber=N&uploadId=X" -- see the commit-phase comment
     * below); that tail is intentionally left unescaped and passed
     * through as-is, only the actual key path segment before the first
     * '?' is encoded. `path` is reused verbatim for both SigV4 signing
     * (canonical_uri) and the literal HTTP request line below and at
     * commit time, so signing and the wire request can never diverge. */
    char path[JBOF_PUT_PATH_BUF];
    {
        char bucket_enc[JBOF_PUT_BUCKET_ENC_BUF];
        size_t bucket_needed = jbof_put_uri_encode(
            options->bucket.ptr, options->bucket.len, bucket_enc, sizeof(bucket_enc));
        if (bucket_needed >= sizeof(bucket_enc)) {
            close(sock);
            if (crc_launched) pthread_join(crc_thread, NULL);
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }

        size_t key_path_len = options->key.len;
        for (size_t qi = 0; qi < options->key.len; qi++) {
            if (options->key.ptr[qi] == '?') { key_path_len = qi; break; }
        }
        char key_enc[JBOF_PUT_KEY_ENC_BUF];
        size_t key_needed = jbof_put_uri_encode(
            options->key.ptr, key_path_len, key_enc, sizeof(key_enc));
        if (key_needed >= sizeof(key_enc)) {
            close(sock);
            if (crc_launched) pthread_join(crc_thread, NULL);
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }

        int pathlen = snprintf(path, sizeof(path), "/%s/%s%.*s",
            bucket_enc, key_enc,
            (int)(options->key.len - key_path_len), options->key.ptr + key_path_len);
        if (pathlen < 0 || (size_t)pathlen >= sizeof(path)) {
            close(sock);
            if (crc_launched) pthread_join(crc_thread, NULL);
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }
    }
    char host_port[96];
    snprintf(host_port, sizeof(host_port), "%s:%u",
             host_z, (unsigned)options->meta_server_port);
    char sig_block[1536];
    jbof_put_emit_sig_block(options, "PUT", path, "", host_port,
                            sig_block, sizeof(sig_block));

    char req[JBOF_PUT_PATH_BUF + 1536 + 512];
    int reqlen = snprintf(req, sizeof(req),
        "PUT %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Connection: keep-alive\r\n"
        "Accept: application/vnd.s3rdma.placement+json\r\n"
        "X-S3RDMA-Object-Size: %zu\r\n"
        "Content-Length: 0\r\n"
        "%s"
        "\r\n",
        path,
        host_z, (unsigned)options->meta_server_port,
        options->source_length,
        sig_block);
    if (reqlen < 0 || (size_t)reqlen >= sizeof(req)) {
        /* snprintf() returns the length that WOULD have been written,
         * ignoring truncation. If bucket+key+sig_block overflow req[],
         * reqlen > sizeof(req) and the send below would read (size_t)reqlen
         * bytes starting at req -- past the end of the stack buffer. Reject
         * instead of sending garbage/OOB memory over the wire. */
        close(sock);
        if (crc_launched) pthread_join(crc_thread, NULL);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (jbof_put_send_all(sock, req, (size_t)reqlen) < 0) {
        close(sock);
        if (crc_launched) pthread_join(crc_thread, NULL);
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }

    char hdr_buf[JBOF_PUT_HDR_BUF];
    int body_preread = 0;
    int hdrlen = jbof_put_recv_headers(sock, hdr_buf, sizeof(hdr_buf), &body_preread);
    char saved_body_byte = hdr_buf[hdrlen];
    hdr_buf[hdrlen] = '\0';
    /* Accept 200 or 202 for placement. */
    if (hdrlen < 12 || (!strstr(hdr_buf, " 200 ") && !strstr(hdr_buf, " 202 "))) {
        close(sock);
        if (crc_launched) pthread_join(crc_thread, NULL);
        return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
    }
    const char *cl = strstr(hdr_buf, "Content-Length:");
    int content_len = cl ? atoi(cl + 15) : 0;
    if (content_len <= 0 || content_len >= JBOF_PUT_BODY_BUF - 1) {
        close(sock);
        if (crc_launched) pthread_join(crc_thread, NULL);
        return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
    }
    char *body;
    int body_on_heap = 0;
#ifdef WITH_SPDK_BYPASS
    if (options->spdk_session) {
        body = rp_spdk_get_body_buf((rp_spdk_session_t *)options->spdk_session);
    } else
#endif
    {
        body = aws_mem_calloc(allocator, 1, (size_t)content_len + 1);
        body_on_heap = 1;
    }
    if (!body) { close(sock); if (crc_launched) pthread_join(crc_thread, NULL); return aws_raise_error(AWS_ERROR_OOM); }
    int body_len = 0;
    if (body_preread > 0) {
        hdr_buf[hdrlen] = saved_body_byte;
        int copy = body_preread < content_len ? body_preread : content_len;
        memcpy(body, hdr_buf + hdrlen, (size_t)copy);
        body_len = copy;
    }
    while (body_len < content_len) {
        ssize_t n = recv(sock, body + body_len, content_len - body_len, 0);
        if (n <= 0) break;
        body_len += (int)n;
    }
    /* Keep sock open for phase 3 commit (HTTP/1.1 keep-alive). */
    if (body_len < content_len) {
        close(sock);
        if (body_on_heap) aws_mem_release(allocator, body);
        if (crc_launched) pthread_join(crc_thread, NULL);
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }

    char write_token[128];
    jbof_put_header_value(hdr_buf, "X-S3RDMA-Write-Token",
                          write_token, sizeof(write_token));
    if (!write_token[0]) {
        close(sock);
        if (body_on_heap) aws_mem_release(allocator, body);
        if (crc_launched) pthread_join(crc_thread, NULL);
        return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
    }

    /* Parse placement extents. */
    struct aws_byte_cursor bc = aws_byte_cursor_from_array(body, (size_t)body_len);
    struct aws_json_value *root = aws_json_value_new_from_string(allocator, bc);
    if (body_on_heap) aws_mem_release(allocator, body);
    if (!root) { close(sock); if (crc_launched) pthread_join(crc_thread, NULL); return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT); }

    struct aws_json_value *exts = aws_json_value_get_from_object(
        root, aws_byte_cursor_from_c_str("extents"));
    if (!exts || !aws_json_value_is_array(exts)) {
        close(sock);
        aws_json_value_destroy(root);
        if (crc_launched) pthread_join(crc_thread, NULL);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    size_t n_extents = aws_json_get_array_size(exts);
    if (n_extents == 0 || n_extents > JBOF_PUT_MAX_EXTENTS) {
        close(sock);
        aws_json_value_destroy(root);
        if (crc_launched) pthread_join(crc_thread, NULL);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    const uint8_t *src_base = (const uint8_t *)options->source_buffer;
    size_t total_bytes = 0;
    double t_phase2 = 0;

#ifdef WITH_SPDK_BYPASS
    rp_spdk_write_work_t *sw = NULL;
    if (options->spdk_session) {
        sw = rp_spdk_get_write_work_buf(
            (rp_spdk_session_t *)options->spdk_session);
        if (!sw) {
            close(sock);
            aws_json_value_destroy(root);
            if (crc_launched) pthread_join(crc_thread, NULL);
            return aws_raise_error(AWS_ERROR_OOM);
        }
        for (size_t i = 0; i < n_extents; i++) {
            struct aws_json_value *eo = aws_json_get_array_element(exts, i);
            uint64_t obj_off = 0;
            if (!eo || jbof_put_parse_to_write_work(eo, &sw[i], &obj_off) != AWS_OP_SUCCESS) {
                close(sock);
                aws_json_value_destroy(root);
                if (crc_launched) pthread_join(crc_thread, NULL);
                return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
            }
            if (obj_off > (uint64_t)options->source_length ||
                sw[i].valid_bytes > (uint64_t)options->source_length - obj_off) {
                close(sock);
                aws_json_value_destroy(root);
                if (crc_launched) pthread_join(crc_thread, NULL);
                return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
            }
            sw[i].src = src_base + obj_off;
            total_bytes += (size_t)sw[i].valid_bytes;
        }
        aws_json_value_destroy(root);
        if (total_bytes != options->source_length) {
            close(sock);
            if (crc_launched) pthread_join(crc_thread, NULL);
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }
        t_phase2 = jbof_put_now_sec();
        int sprc = rp_spdk_execute_write(sw, (int)n_extents,
                                         (rp_spdk_session_t *)options->spdk_session);
        if (sprc != RP_OK) {
            close(sock);
            if (crc_launched) pthread_join(crc_thread, NULL);
            return aws_raise_error(AWS_ERROR_S3_INTERNAL_ERROR);
        }
    } else
#endif
    {
    wp_extent_t *placement = aws_mem_calloc(allocator, n_extents, sizeof(wp_extent_t));
    if (!placement) {
        close(sock);
        aws_json_value_destroy(root);
        if (crc_launched) pthread_join(crc_thread, NULL);
        return aws_raise_error(AWS_ERROR_OOM);
    }
    for (size_t i = 0; i < n_extents; i++) {
        struct aws_json_value *eo = aws_json_get_array_element(exts, i);
        if (!eo || jbof_put_parse_placement_extent(eo, &placement[i]) != AWS_OP_SUCCESS) {
            close(sock);
            aws_mem_release(allocator, placement);
            aws_json_value_destroy(root);
            if (crc_launched) pthread_join(crc_thread, NULL);
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }
        if (placement[i].object_offset > (uint64_t)options->source_length ||
            placement[i].length > (uint64_t)options->source_length - placement[i].object_offset) {
            close(sock);
            aws_mem_release(allocator, placement);
            aws_json_value_destroy(root);
            if (crc_launched) pthread_join(crc_thread, NULL);
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }
        total_bytes += (size_t)placement[i].length;
    }
    aws_json_value_destroy(root);

    if (total_bytes != options->source_length) {
        close(sock);
        aws_mem_release(allocator, placement);
        if (crc_launched) pthread_join(crc_thread, NULL);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    t_phase2 = jbof_put_now_sec();

    wp_write_work_t *work = NULL;
    int n_work = 0;
    int rc = wp_plan_build(placement, (int)n_extents, options->source_buffer,
                           &work, &n_work);
    aws_mem_release(allocator, placement);
    if (rc != RP_OK) {
        close(sock);
        if (crc_launched) pthread_join(crc_thread, NULL);
        return aws_raise_error(AWS_ERROR_UNKNOWN);
    }

    struct jbof_put_target_map map = {
        .entries = options->target_devices,
        .count   = options->target_device_count,
    };
    rp_planner_config_t pcfg = {
        .worker_threads   = options->workers_per_target,
        .open_target      = jbof_put_open_target,
        .open_target_user = &map,
        .skip_crc         = 1,
    };
    wp_write_result_t wr = {0};
    int prc = wp_execute(work, n_work, &pcfg, &wr);
    free(work);
    if (prc != RP_OK) {
        close(sock);
        if (crc_launched) pthread_join(crc_thread, NULL);
        wp_write_result_clean_up(&wr);
        return aws_raise_error(AWS_ERROR_S3_INTERNAL_ERROR);
    }
    wp_write_result_clean_up(&wr);
    }

    if (crc_launched) pthread_join(crc_thread, NULL);
    uint32_t full_crc = crc_args.crc;
    if (crc_args.rc == -1) {
        full_crc = jbof_put_crc32c_cpu(options->source_buffer, options->source_length);
    } else if (crc_args.rc != 0) {
        close(sock);
        return aws_raise_error(AWS_ERROR_S3_INTERNAL_ERROR);
    }

    fprintf(stderr, "[put] phase1(placement): %.1f ms, phase2(pwrite): %.1f ms\n",
            (t_phase2 - t0) * 1000.0,
            (jbof_put_now_sec() - t_phase2) * 1000.0);

    /* S3 spec requires x-amz-checksum-crc32c to be the base64 encoding of
     * the 4-byte big-endian CRC32C, not a decimal integer -- the previous
     * "%u" here sent e.g. "3735928559" instead of "3q2+7w==", which no
     * spec-compliant S3 checksum validator would accept. */
    uint8_t crc_be[4] = {
        (uint8_t)(full_crc >> 24), (uint8_t)(full_crc >> 16),
        (uint8_t)(full_crc >> 8),  (uint8_t)(full_crc),
    };
    struct aws_byte_cursor crc_cursor = aws_byte_cursor_from_array(crc_be, sizeof(crc_be));
    uint8_t crc_b64_bytes[16];
    struct aws_byte_buf crc_b64_buf = aws_byte_buf_from_empty_array(crc_b64_bytes, sizeof(crc_b64_bytes));
    if (aws_base64_encode(&crc_cursor, &crc_b64_buf) != AWS_OP_SUCCESS) {
        close(sock);
        return aws_raise_error(AWS_ERROR_S3_INTERNAL_ERROR);
    }

    /* ── Phase 3: commit (reuses phase 1 socket via HTTP/1.1 keep-alive) ── */
    double t_phase3 = jbof_put_now_sec();

    /* options->key may already carry a query string (MPU part uploads:
     * "<key>?partNumber=N&uploadId=X"). Appending "?rdma-commit" in that
     * case would produce two '?' in the URL, which every URL parser
     * (including the mock server's) treats as: query = everything after
     * the FIRST '?', so "rdma-commit" would never be recognized as a
     * query key and the commit would silently fall through to a
     * non-RDMA fallback path. Use '&' when a query already exists. */
    int key_has_query = 0;
    for (size_t qi = 0; qi < options->key.len; qi++) {
        if (options->key.ptr[qi] == '?') { key_has_query = 1; break; }
    }
    const char *commit_sep = key_has_query ? "&rdma-commit" : "?rdma-commit";

    char csig[1536];
    jbof_put_emit_sig_block(options, "PUT", path,
                            key_has_query ? "rdma-commit" : "rdma-commit=",
                            host_port, csig, sizeof(csig));

    char creq[JBOF_PUT_PATH_BUF + 1536 + 512];
    int crlen = snprintf(creq, sizeof(creq),
        "PUT %s%s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Connection: close\r\n"
        "X-S3RDMA-Write-Token: %s\r\n"
        "x-amz-checksum-crc32c: %.*s\r\n"
        "Content-Length: 0\r\n"
        "%s"
        "\r\n",
        path,
        commit_sep,
        host_z, (unsigned)options->meta_server_port,
        write_token,
        (int)crc_b64_buf.len, (const char *)crc_b64_buf.buffer,
        csig);
    if (crlen < 0 || (size_t)crlen >= sizeof(creq)) {
        /* Same truncation-detection fix as the phase-1 request above:
         * snprintf()'s return value ignores truncation, so without this
         * check an oversized bucket/key/csig would make crlen exceed
         * sizeof(creq) and the send below would read past the buffer. */
        close(sock);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (jbof_put_send_all(sock, creq, (size_t)crlen) < 0) {
        close(sock);
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }
    char chdr[JBOF_PUT_HDR_BUF];
    int chdr_preread = 0;
    int chlen = jbof_put_recv_headers(sock, chdr, sizeof(chdr), &chdr_preread);
    close(sock);
    chdr[chlen] = '\0';
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
    fprintf(stderr, "[put] phase3(commit): %.1f ms, total: %.1f ms\n",
            (jbof_put_now_sec() - t_phase3) * 1000.0,
            out_result->elapsed_seconds * 1000.0);
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
