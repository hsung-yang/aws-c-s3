/*
 * s3_jbof_get.c — JBOF-direct GetObject helper.
 *
 * See include/aws/s3/s3_jbof_get.h for the public contract.
 *
 * Implementation notes:
 *  - HTTP metadata fetch uses a plain blocking TCP socket. The metadata
 *    server speaks HTTP/1.0 with a single JSON body; pulling in aws-c-http
 *    just for this would be substantial overkill.
 *  - JSON parsing reuses aws-c-common's aws_json_value_t for safety.
 *  - The data path is delegated to libobject_rdma (rp_plan_build / rp_execute).
 *  - Single-target only: every extent resolves to options->nvme_dev_path.
 */

#ifdef AWS_ENABLE_JBOF

#define _GNU_SOURCE
#include <aws/s3/s3_jbof_get.h>

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

/* Sized for the 32 GiB / 4 MiB-extent / 8-target saturation test
 * (8192 extents). The overlap check below is O(n^2); at 8192 that's
 * ~33M comparisons, negligible next to a multi-second RDMA transfer. */
#define JBOF_MAX_EXTENTS    8192
#define JBOF_HTTP_HDR_BUF   65536
#define JBOF_HTTP_BODY_BUF  131072

/* ── small helpers ─────────────────────────────────────────────────── */

static double jbof_now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static int jbof_tcp_connect(const char *ip, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int jbof_send_all(int fd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int jbof_recv_headers(int fd, char *buf, int bufsz) {
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

static int jbof_recv_body(int fd, char *buf, int content_len) {
    int total = 0;
    while (total < content_len) {
        ssize_t n = recv(fd, buf + total, content_len - total, 0);
        if (n <= 0) break;
        total += (int)n;
    }
    buf[total] = '\0';
    return total;
}

/* Find header value (case-insensitive). Returns 0/'\0'-padded buf. */
/* Copy an aws_byte_cursor into a NUL-terminated buffer. Returns "" if the
 * cursor is empty. Caller-provided buffer must be at least cap bytes. */
static const char *jbof_cur_to_cstr(struct aws_byte_cursor c, char *buf, size_t cap) {
    if (c.len == 0) { if (cap) buf[0] = '\0'; return buf; }
    size_t n = c.len < cap - 1 ? c.len : cap - 1;
    memcpy(buf, c.ptr, n);
    buf[n] = '\0';
    return buf;
}

/* Build SigV4 headers for a request. Writes the three header strings to
 * out (each pre-allocated). Returns AWS_OP_SUCCESS or sets aws_last_error.
 *
 * extra_block / extra_names follow the contract in s3_jbof_sigv4.h. */
struct jbof_sigv4_creds {
    struct aws_byte_cursor access_key, secret_key, session_token, region, service;
};

static int jbof_build_sigv4(const struct jbof_sigv4_creds *c,
                            const char *method,
                            const char *path,
                            const char *query,
                            const char *host_header,
                            const char *extra_block,
                            const char *extra_names,
                            struct aws_s3_jbof_sigv4_output *out) {
    char ak[256], sk[256], st[1024], rg[64], sv[32];
    struct aws_s3_jbof_sigv4_input in = {
        .method                       = method,
        .canonical_uri                = path,
        .canonical_query              = query,
        .host_header                  = host_header,
        .region                       = c->region.len ? jbof_cur_to_cstr(c->region, rg, sizeof(rg))
                                                      : "us-east-1",
        .service                      = c->service.len ? jbof_cur_to_cstr(c->service, sv, sizeof(sv))
                                                       : "s3",
        .access_key                   = jbof_cur_to_cstr(c->access_key, ak, sizeof(ak)),
        .secret_key                   = jbof_cur_to_cstr(c->secret_key, sk, sizeof(sk)),
        .session_token                = c->session_token.len
                                          ? jbof_cur_to_cstr(c->session_token, st, sizeof(st))
                                          : NULL,
        .extra_signed_headers_block   = extra_block,
        .extra_signed_headers_names   = extra_names,
        .timestamp                    = 0,
    };
    return aws_s3_jbof_sigv4_sign(&in, out);
}

static void jbof_header_value(const char *hdr, const char *name,
                              char *out, size_t outsz) {
    out[0] = '\0';
    size_t name_len = strlen(name);
    const char *p = hdr;
    while (*p) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;
        if ((size_t)(eol - p) > name_len + 1 &&
            strncasecmp(p, name, name_len) == 0 &&
            p[name_len] == ':') {
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

/* True if the HTTP status line indicates a usable response: 200 always;
 * 206 (Partial Content) or 204 (No Content) additionally accepted when the
 * request carried a Range header (ranged != 0). Fix: the code used to
 * reject 206 unconditionally, which breaks ranged GETs against a
 * conforming metadata server. */
static int jbof_status_ok(const char *hdr, int ranged) {
    if (strstr(hdr, " 200 ")) return 1;
    if (ranged && (strstr(hdr, " 206 ") || strstr(hdr, " 204 "))) return 1;
    return 0;
}

/* True if the response's Content-Type (case-insensitive header name, per
 * jbof_header_value) contains `token`, OR no Content-Type header is present
 * at all (tolerated for compatibility with permissive mock servers that
 * omit it — real conforming servers always send it). Returns 0 only when a
 * Content-Type IS present and does NOT contain `token`. `token` itself is
 * matched case-sensitively: the media-type string is lowercase by spec. */
static int jbof_content_type_ok(const char *hdr, const char *token) {
    char ctype[256];
    jbof_header_value(hdr, "Content-Type", ctype, sizeof(ctype));
    if (!ctype[0]) return 1;
    return strstr(ctype, token) != NULL;
}

/* Percent-encode everything except unreserved chars [A-Za-z0-9-._~] and
 * '/' (S3 keeps '/' unescaped inside object keys). Behaves like snprintf:
 * always returns the full encoded length needed (even if it doesn't fit),
 * and NUL-terminates whatever was written when `out_cap` is nonzero. The
 * caller MUST check the return value against out_cap and treat `>= out_cap`
 * as an error — this function never writes past out_cap and never emits a
 * partial %XX escape, but a too-small buffer means the string was
 * truncated. */
static size_t jbof_get_uri_encode(const char *in, size_t in_len,
                                  char *out, size_t out_cap) {
    static const char hex[] = "0123456789ABCDEF";
    size_t needed = 0;
    size_t oi = 0;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];
        int unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                         (c >= '0' && c <= '9') ||
                         c == '-' || c == '.' || c == '_' || c == '~' || c == '/';
        size_t unit = unreserved ? 1 : 3;
        needed += unit;
        if (out && out_cap && oi + unit < out_cap) {
            if (unreserved) {
                out[oi++] = (char)c;
            } else {
                out[oi++] = '%';
                out[oi++] = hex[(c >> 4) & 0xF];
                out[oi++] = hex[c & 0xF];
            }
        }
    }
    if (out && out_cap) out[(oi < out_cap) ? oi : out_cap - 1] = '\0';
    return needed;
}

static char *jbof_dup_cstr_from_json(struct aws_allocator *alloc,
                                     struct aws_json_value *parent,
                                     const char *key) {
    struct aws_json_value *v = aws_json_value_get_from_object(
        parent, aws_byte_cursor_from_c_str(key));
    if (!v) return NULL;
    struct aws_byte_cursor s;
    if (aws_json_value_get_string(v, &s) != AWS_OP_SUCCESS) return NULL;
    char *out = aws_mem_calloc(alloc, 1, s.len + 1);
    if (!out) return NULL;
    memcpy(out, s.ptr, s.len);
    out[s.len] = '\0';
    return out;
}

static uint64_t jbof_get_u64(struct aws_json_value *parent, const char *key) {
    struct aws_json_value *v = aws_json_value_get_from_object(
        parent, aws_byte_cursor_from_c_str(key));
    double d = 0;
    if (!v || aws_json_value_get_number(v, &d) != AWS_OP_SUCCESS) return 0;
    return (uint64_t)d;
}

struct jbof_lease_ctx {
    struct aws_allocator   *alloc;
    rp_gpu_object_buffer_t *pbuf;
    char     host[64];
    uint16_t port;
    char     token[128];
};

/* Layout validation (RDMA_PROTOCOL_SPEC.md §7.1 + HLD §8.1):
 *   - per-extent: block_count * lba_size >= length + data_offset_in_first_lba
 *   - per-extent: data_offset_in_first_lba < lba_size
 *   - per-extent: (subnqn, nsid) resolves to a target_devices entry
 *   - no overlapping object_offset ranges
 *   - sum(length) == expected_total (object_size or range.length)
 * Returns AWS_OP_SUCCESS or sets aws_last_error and returns AWS_OP_ERR.
 */
static int jbof_validate_layout(const rp_extent_t *ex, size_t n,
                                size_t expected_total,
                                const struct aws_s3_jbof_target_device *td,
                                size_t td_count) {
    if (n == 0) return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);

    /* Per-extent invariants. */
    size_t sum_len = 0;
    for (size_t i = 0; i < n; i++) {
        const rp_extent_t *e = &ex[i];
        uint32_t lbs = e->lba_size ? e->lba_size : 4096;
        if (e->data_offset_in_first_lba >= lbs) {
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }
        uint64_t reserve = (uint64_t)e->block_count * lbs;
        if (reserve < (uint64_t)e->length + e->data_offset_in_first_lba) {
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }
        /* (subnqn, nsid) must be in target_devices. */
        int found = 0;
        for (size_t k = 0; k < td_count; k++) {
            if (td[k].nsid != e->nsid) continue;
            if (td[k].subnqn.len != strlen(e->subnqn)) continue;
            if (memcmp(td[k].subnqn.ptr, e->subnqn, td[k].subnqn.len) != 0) continue;
            found = 1; break;
        }
        if (!found) return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        sum_len += (size_t)e->length;
    }

    if (expected_total != 0 && sum_len != expected_total) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* O(n^2) overlap check. n is bounded by JBOF_MAX_EXTENTS (8192); fine. */
    for (size_t i = 0; i < n; i++) {
        uint64_t a_lo = ex[i].object_offset;
        uint64_t a_hi = a_lo + ex[i].length;
        for (size_t j = i + 1; j < n; j++) {
            uint64_t b_lo = ex[j].object_offset;
            uint64_t b_hi = b_lo + ex[j].length;
            if (a_lo < b_hi && b_lo < a_hi) {
                return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
            }
        }
    }
    return AWS_OP_SUCCESS;
}

/* Translate planner return code to an aws-c-s3 error and raise it. Returns
 * AWS_OP_SUCCESS for RP_OK, AWS_OP_ERR otherwise. */
static int jbof_raise_for_planner_rc(int prc) {
    switch (prc) {
        case RP_OK:
            return AWS_OP_SUCCESS;
        case RP_E_CRC_MISMATCH:
            return aws_raise_error(AWS_ERROR_S3_RESPONSE_CHECKSUM_MISMATCH);
        case RP_E_IO:
            return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
        case RP_E_NOMEM:
            return aws_raise_error(AWS_ERROR_OOM);
        case RP_E_INVAL:
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        case RP_E_CUDA:
            return aws_raise_error(AWS_ERROR_S3_INTERNAL_ERROR);
        default:
            return aws_raise_error(AWS_ERROR_UNKNOWN);
    }
}

void aws_s3_jbof_get_result_clean_up(struct aws_allocator *allocator,
                                     struct aws_s3_jbof_get_result *result) {
    if (!allocator || !result) return;
    if (result->etag)        aws_mem_release(allocator, result->etag);
    if (result->version_id)  aws_mem_release(allocator, result->version_id);
    result->etag = NULL;
    result->version_id = NULL;
}

/* ── layout JSON → rp_extent_t[] ───────────────────────────────────── */

static int jbof_parse_extent(struct aws_allocator *alloc,
                             struct aws_json_value *ext_obj,
                             rp_extent_t *out) {
    (void)alloc;
    memset(out, 0, sizeof(*out));

    struct aws_json_value *v;
    struct aws_byte_cursor s;
    double d;

    v = aws_json_value_get_from_object(ext_obj, aws_byte_cursor_from_c_str("object_offset"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) out->object_offset = (uint64_t)d;

    v = aws_json_value_get_from_object(ext_obj, aws_byte_cursor_from_c_str("length"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) out->length = (uint64_t)d;

    v = aws_json_value_get_from_object(ext_obj, aws_byte_cursor_from_c_str("nsid"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) out->nsid = (uint32_t)d;

    v = aws_json_value_get_from_object(ext_obj, aws_byte_cursor_from_c_str("start_lba"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) out->start_lba = (uint64_t)d;

    v = aws_json_value_get_from_object(ext_obj, aws_byte_cursor_from_c_str("lba_size"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) out->lba_size = (uint32_t)d;
    if (out->lba_size == 0) out->lba_size = 4096;

    v = aws_json_value_get_from_object(ext_obj, aws_byte_cursor_from_c_str("block_count"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) out->block_count = (uint32_t)d;

    v = aws_json_value_get_from_object(ext_obj, aws_byte_cursor_from_c_str("data_offset_in_first_lba"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) out->data_offset_in_first_lba = (uint32_t)d;

    v = aws_json_value_get_from_object(ext_obj, aws_byte_cursor_from_c_str("generation"));
    if (v && aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) out->generation = (uint32_t)d;

    struct aws_json_value *target = aws_json_value_get_from_object(
        ext_obj, aws_byte_cursor_from_c_str("target"));
    if (target) {
        v = aws_json_value_get_from_object(target, aws_byte_cursor_from_c_str("subnqn"));
        if (v && aws_json_value_get_string(v, &s) == AWS_OP_SUCCESS) {
            size_t n = s.len < sizeof(out->subnqn) - 1 ? s.len : sizeof(out->subnqn) - 1;
            memcpy(out->subnqn, s.ptr, n);
            out->subnqn[n] = '\0';
        }
        v = aws_json_value_get_from_object(target, aws_byte_cursor_from_c_str("traddr"));
        if (v && aws_json_value_get_string(v, &s) == AWS_OP_SUCCESS) {
            size_t n = s.len < sizeof(out->traddr) - 1 ? s.len : sizeof(out->traddr) - 1;
            memcpy(out->traddr, s.ptr, n);
            out->traddr[n] = '\0';
        }
    }

    struct aws_json_value *ck = aws_json_value_get_from_object(
        ext_obj, aws_byte_cursor_from_c_str("checksum"));
    if (ck) {
        v = aws_json_value_get_from_object(ck, aws_byte_cursor_from_c_str("value"));
        if (v) {
            /* RDMA_PROTOCOL_SPEC.md: checksum.value is a base64-encoded
             * 4-byte CRC32C (S3 convention: big-endian byte order), not a
             * JSON number. A conforming server sends a string; parsing it
             * as a number silently failed and left expected_crc32c at 0,
             * causing false CRC mismatches (or worse, unverified data if
             * the actual CRC also happened to be 0). */
            struct aws_byte_cursor b64;
            if (aws_json_value_get_string(v, &b64) == AWS_OP_SUCCESS) {
                size_t decoded_len = 0;
                if (aws_base64_compute_decoded_len(&b64, &decoded_len) == AWS_OP_SUCCESS &&
                    decoded_len == 4) {
                    uint8_t decoded[4];
                    struct aws_byte_buf decoded_buf =
                        aws_byte_buf_from_empty_array(decoded, sizeof(decoded));
                    if (aws_base64_decode(&b64, &decoded_buf) == AWS_OP_SUCCESS &&
                        decoded_buf.len == 4) {
                        out->expected_crc32c =
                            ((uint32_t)decoded[0] << 24) | ((uint32_t)decoded[1] << 16) |
                            ((uint32_t)decoded[2] << 8)  |  (uint32_t)decoded[3];
                    }
                }
                /* decode failure or decoded_len != 4: leave expected_crc32c
                 * at its memset(0) default. rp_extent_t (see
                 * include/object_rdma/read_planner.h, a different vendored
                 * library out of scope here) has no has_crc/crc_valid flag
                 * for "this extent carried no expected checksum" — only
                 * rp_read_work_t does, and that's set by the planner from
                 * ranged-clipping, not from checksum presence. So this is
                 * no worse than the pre-fix behavior (which also silently
                 * left expected_crc32c at 0 whenever parsing failed); it's
                 * a known gap, not something this file can close alone. */
            } else if (aws_json_value_get_number(v, &d) == AWS_OP_SUCCESS) {
                /* Fallback for non-conforming senders (e.g. some mock/test
                 * servers) that still emit checksum.value as a JSON number.
                 * The base64-string path above is preferred per spec. */
                out->expected_crc32c = (uint32_t)d;
            }
        }
    }

    return out->length > 0 ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

/* ── connection-pool stub: lookup device by (subnqn, nsid) ─────────── */

struct jbof_target_map {
    const struct aws_s3_jbof_target_device *entries;
    size_t                                  count;
    int                                     use_o_direct;
};

static int jbof_open_target(const rp_target_t *target, void *user) {
    const struct jbof_target_map *map = user;
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
        int flags = O_RDONLY;
        if (map->use_o_direct) flags |= O_DIRECT;
        return open(path, flags);
    }
    return -1;
}

/* ── public entry point ────────────────────────────────────────────── */

int aws_s3_jbof_get_object(struct aws_allocator *allocator,
                           const struct aws_s3_jbof_get_options *options,
                           struct aws_s3_jbof_get_result *out_result) {
    if (!allocator || !options || !out_result) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (!options->gpu_buffer || options->gpu_buffer_capacity == 0) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (!options->target_devices || options->target_device_count == 0) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    memset(out_result, 0, sizeof(*out_result));

    /* ── 1. HTTP/1.0 GET to metadata server ────────────────────────── */
    char host_z[256];
    size_t hlen = options->meta_server_host.len < sizeof(host_z) - 1
                ? options->meta_server_host.len : sizeof(host_z) - 1;
    memcpy(host_z, options->meta_server_host.ptr, hlen);
    host_z[hlen] = '\0';

    int sock = jbof_tcp_connect(host_z, options->meta_server_port);
    if (sock < 0) return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);

    char req[8192];
    char range_hdr[64] = "";
    if (options->req_range_length) {
        snprintf(range_hdr, sizeof(range_hdr),
                 "Range: bytes=%llu-%llu\r\n",
                 (unsigned long long)options->req_range_offset,
                 (unsigned long long)(options->req_range_offset
                                      + options->req_range_length - 1));
    }

    /* Percent-encode bucket/key once; reused for both the SigV4 canonical
     * URI and the literal request line below so the two can never diverge
     * (a mismatch there breaks SigV4 signature verification server-side). */
    char enc_bucket[256], enc_key[3200];
    size_t enc_bucket_len = jbof_get_uri_encode(
        (const char *)options->bucket.ptr, options->bucket.len,
        enc_bucket, sizeof(enc_bucket));
    size_t enc_key_len = jbof_get_uri_encode(
        (const char *)options->key.ptr, options->key.len,
        enc_key, sizeof(enc_key));
    if (enc_bucket_len >= sizeof(enc_bucket) || enc_key_len >= sizeof(enc_key)) {
        close(sock);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    char path[sizeof(enc_bucket) + sizeof(enc_key) + 4];
    int path_len = snprintf(path, sizeof(path), "/%s/%s", enc_bucket, enc_key);
    if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
        close(sock);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* Optional SigV4 signing. */
    char sig_block[1536] = "";
    if (options->access_key.len && options->secret_key.len) {
        char host_port[96];
        snprintf(host_port, sizeof(host_port), "%s:%u",
                 host_z, (unsigned)options->meta_server_port);
        struct aws_s3_jbof_sigv4_output sv = {0};
        struct jbof_sigv4_creds c = {
            .access_key = options->access_key, .secret_key = options->secret_key,
            .session_token = options->session_token,
            .region = options->region, .service = options->service,
        };
        if (jbof_build_sigv4(&c, "GET", path, "", host_port, NULL, NULL, &sv)
            == AWS_OP_SUCCESS) {
            int sn = snprintf(sig_block, sizeof(sig_block),
                "X-Amz-Date: %s\r\n"
                "X-Amz-Content-SHA256: %s\r\n"
                "Authorization: %s\r\n",
                sv.amz_date, sv.content_sha256, sv.authorization);
            if (sn < 0) sn = 0;
            if ((size_t)sn >= sizeof(sig_block)) sn = (int)sizeof(sig_block) - 1;
            if (options->session_token.len && (size_t)sn < sizeof(sig_block)) {
                char st[1024];
                jbof_cur_to_cstr(options->session_token, st, sizeof(st));
                snprintf(sig_block + sn, sizeof(sig_block) - sn,
                         "X-Amz-Security-Token: %s\r\n", st);
            }
        }
    }

    int  reqlen = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\n"
        "Host: %s:%u\r\n"
        "Accept: application/vnd.s3rdma.layout+json\r\n"
        "%s%s"
        "\r\n",
        path,
        host_z, (unsigned)options->meta_server_port,
        range_hdr, sig_block);
    if (reqlen < 0 || (size_t)reqlen >= sizeof(req)) {
        close(sock);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (jbof_send_all(sock, req, (size_t)reqlen) < 0) {
        close(sock);
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }

    char hdr_buf[JBOF_HTTP_HDR_BUF];
    int  hdrlen = jbof_recv_headers(sock, hdr_buf, sizeof(hdr_buf));
    if (hdrlen < 12 || !jbof_status_ok(hdr_buf, options->req_range_length != 0)) {
        close(sock);
        return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
    }
    const char *cl = strstr(hdr_buf, "Content-Length:");
    int content_len = cl ? atoi(cl + 15) : 0;
    if (content_len <= 0) {
        close(sock);
        return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
    }
    char *body = aws_mem_calloc(allocator, 1, (size_t)content_len + 1);
    if (!body) { close(sock); return aws_raise_error(AWS_ERROR_OOM); }
    int body_len = jbof_recv_body(sock, body, content_len);
    close(sock);
    if (body_len < content_len) {
        aws_mem_release(allocator, body);
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }

    /* ── 1a. RDMA-decline (spec §4.3) → HTTP body IS the object data ─── */
    {
        char reply[16];
        jbof_header_value(hdr_buf, "x-amz-rdma-reply", reply, sizeof(reply));
        if (reply[0] == '5' && reply[1] == '0' && reply[2] == '1') {
            if ((size_t)content_len > options->gpu_buffer_capacity) {
                aws_mem_release(allocator, body);
                return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
            }
            memcpy(options->gpu_buffer, body, (size_t)content_len);
            aws_mem_release(allocator, body);
            char etag_hdr[256];
            jbof_header_value(hdr_buf, "ETag", etag_hdr, sizeof(etag_hdr));
            if (etag_hdr[0]) {
                size_t l = strlen(etag_hdr);
                out_result->etag = aws_mem_calloc(allocator, 1, l + 1);
                if (out_result->etag) memcpy(out_result->etag, etag_hdr, l);
            }
            out_result->object_bytes  = (size_t)content_len;
            out_result->crc_ok        = 1;   /* HTTP body is authoritative */
            out_result->planner_rc    = RP_OK;
            out_result->elapsed_seconds = 0.0;
            return AWS_OP_SUCCESS;
        }
    }

    /* Body is not a decline payload past this point — it must be layout
     * JSON. Reject anything whose Content-Type says otherwise; tolerate an
     * absent Content-Type header for mock-server compat (see
     * jbof_content_type_ok). */
    if (!jbof_content_type_ok(hdr_buf, "application/vnd.s3rdma.layout+json")) {
        aws_mem_release(allocator, body);
        return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
    }

    /* ── 1b. Pull headers we care about for the layout/lease cycle ───── */
    char lease_token[128];
    jbof_header_value(hdr_buf, "X-S3RDMA-Lease-Token", lease_token, sizeof(lease_token));
    char layout_epoch_hdr[32];
    jbof_header_value(hdr_buf, "X-S3RDMA-Layout-Epoch", layout_epoch_hdr, sizeof(layout_epoch_hdr));

    /* ── 2. Parse layout JSON via aws_json ─────────────────────────── */
    struct aws_byte_cursor body_cur = aws_byte_cursor_from_array(body, (size_t)body_len);
    struct aws_json_value *root = aws_json_value_new_from_string(allocator, body_cur);
    if (!root) {
        aws_mem_release(allocator, body);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* Top-level fields per RDMA_PROTOCOL_SPEC.md §4.2 */
    out_result->etag         = jbof_dup_cstr_from_json(allocator, root, "etag");
    out_result->version_id   = jbof_dup_cstr_from_json(allocator, root, "version_id");
    out_result->layout_epoch              = jbof_get_u64(root, "layout_epoch");
    out_result->lease_expires_at_unix_ms  = jbof_get_u64(root, "lease_expires_at_unix_ms");
    uint64_t object_size_field            = jbof_get_u64(root, "object_size");
    struct aws_json_value *range_obj = aws_json_value_get_from_object(
        root, aws_byte_cursor_from_c_str("range"));
    if (range_obj) {
        out_result->range_offset = jbof_get_u64(range_obj, "offset");
        out_result->range_length = jbof_get_u64(range_obj, "length");
    }
    struct aws_json_value *ck = aws_json_value_get_from_object(
        root, aws_byte_cursor_from_c_str("checksum"));
    if (ck) {
        struct aws_json_value *cv = aws_json_value_get_from_object(
            ck, aws_byte_cursor_from_c_str("value"));
        double d = 0;
        if (cv && aws_json_value_get_number(cv, &d) == AWS_OP_SUCCESS) {
            out_result->full_object_crc32c = (uint32_t)d;
            out_result->full_object_crc_present = 1;
        }
    }

    struct aws_json_value *exts = aws_json_value_get_from_object(
        root, aws_byte_cursor_from_c_str("extents"));
    if (!exts || !aws_json_value_is_array(exts)) {
        aws_json_value_destroy(root);
        aws_mem_release(allocator, body);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    size_t n_extents = aws_json_get_array_size(exts);
    if (n_extents == 0 || n_extents > JBOF_MAX_EXTENTS) {
        aws_json_value_destroy(root);
        aws_mem_release(allocator, body);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    rp_extent_t *rex = aws_mem_calloc(allocator, n_extents, sizeof(rp_extent_t));
    if (!rex) {
        aws_json_value_destroy(root);
        aws_mem_release(allocator, body);
        return aws_raise_error(AWS_ERROR_OOM);
    }

    size_t total_bytes = 0;
    for (size_t i = 0; i < n_extents; i++) {
        struct aws_json_value *eo = aws_json_get_array_element(exts, i);
        if (!eo || jbof_parse_extent(allocator, eo, &rex[i]) != AWS_OP_SUCCESS) {
            aws_mem_release(allocator, rex);
            aws_json_value_destroy(root);
            aws_mem_release(allocator, body);
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }
        /* object_offset/length are server-controlled; object_offset near
         * SIZE_MAX would wrap the addition and under-count total_bytes,
         * defeating the gpu_buffer_capacity check below. Reject instead. */
        size_t off = (size_t)rex[i].object_offset;
        size_t len = (size_t)rex[i].length;
        size_t end = off + len;
        if (end < off) {
            aws_mem_release(allocator, rex);
            aws_json_value_destroy(root);
            aws_mem_release(allocator, body);
            return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
        }
        if (end > total_bytes) total_bytes = end;
    }

    aws_json_value_destroy(root);
    aws_mem_release(allocator, body);

    if (total_bytes > options->gpu_buffer_capacity) {
        aws_mem_release(allocator, rex);
        return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
    }

    /* ── 2b. Validate layout invariants (HLD §8.1, spec §7.1) ─────── */
    {
        size_t expected = out_result->range_length
                            ? (size_t)out_result->range_length
                            : (object_size_field ? (size_t)object_size_field : 0);
        if (jbof_validate_layout(rex, n_extents, expected,
                                 options->target_devices,
                                 options->target_device_count) != AWS_OP_SUCCESS) {
            aws_mem_release(allocator, rex);
            return AWS_OP_ERR;  /* aws_last_error already set */
        }
    }

    /* ── 3. plan → execute ─────────────────────────────────────────── */

    /* A6: Bounce buffer for soft-RoCE hosts where ibv_reg_mr cannot
     * register CUDA memory. If use_bounce_buffer is set, or the
     * SHFT_BOUNCE env var is present, pread into a CPU-side scratch
     * buffer and then copy to gpu_buffer after rp_execute completes.
     * A6: pass --use-bounce-buffer to demo to test this path */

    /* If ranged, the planner writes req_range_length bytes; otherwise the
     * full total_bytes. Compute now so bounce is sized correctly. */
    size_t plan_bytes = options->req_range_length
                      ? (size_t)options->req_range_length
                      : total_bytes;

    int need_bounce = options->use_bounce_buffer || (getenv("SHFT_BOUNCE") != NULL);
    void *bounce = NULL;
    void *plan_dst = options->gpu_buffer;
    if (need_bounce) {
        bounce = malloc(plan_bytes);
        if (!bounce) {
            aws_mem_release(allocator, rex);
            return aws_raise_error(AWS_ERROR_OOM);
        }
        plan_dst = bounce;
    }

    rp_read_work_t *work = NULL;
    int             n_work = 0;
    int rc = rp_plan_build_ranged(rex, (int)n_extents, plan_dst,
                                  options->req_range_offset,
                                  options->req_range_length,
                                  &work, &n_work);
    aws_mem_release(allocator, rex);
    if (rc != RP_OK) {
        if (bounce) free(bounce);
        return aws_raise_error(AWS_ERROR_UNKNOWN);
    }
    /* If ranged, the destination buffer holds req_range_length bytes
     * starting at offset 0 (planner rebased gpu_dst). */
    if (options->req_range_length) {
        total_bytes = (size_t)options->req_range_length;
    }

    struct jbof_target_map map = {
        .entries      = options->target_devices,
        .count        = options->target_device_count,
        .use_o_direct = options->use_o_direct,
    };
    rp_planner_config_t pcfg = {
        .worker_threads   = options->workers_per_target,
        .crc_stream       = 0,
        .open_target      = jbof_open_target,
        .open_target_user = &map,
        .skip_crc         = options->verify_crc ? 0 : 1,
        /* A6/UAF: when async_crc is on, rp_execute submits the CRC kernel
         * and returns before it finishes; the caller (below) then frees
         * `bounce` right after rp_execute returns. With a bounce buffer in
         * play, that free can race a still-running CRC step that reads
         * `bounce`. rp_finish_crc has no hook to defer that free (the
         * bounce lifetime is owned entirely by this file, not by
         * libobject_rdma), so the safe fix is to force synchronous CRC
         * whenever a bounce buffer is used — async_crc is only ever an
         * optimization, never a correctness requirement. */
        .async_crc        = need_bounce ? 0 : (options->verify_crc && options->async_crc ? 1 : 0),
        .use_o_direct     = options->use_o_direct,
    };
    /* Heap-allocate the planner buffer so it can outlive this stack frame
     * when the caller asked for async mode. */
    rp_gpu_object_buffer_t *pbuf = aws_mem_calloc(allocator, 1, sizeof(*pbuf));
    if (!pbuf) {
        free(work);
        if (bounce) free(bounce);
        return aws_raise_error(AWS_ERROR_OOM);
    }
    pbuf->data   = plan_dst;
    pbuf->length = total_bytes;

    double t0 = jbof_now_sec();
    int prc;
#ifdef WITH_SPDK_BYPASS
    if (options->spdk_targets && options->spdk_target_count > 0) {
        rp_spdk_target_t *spdk_tgts = calloc(options->spdk_target_count,
                                              sizeof(*spdk_tgts));
        if (!spdk_tgts) {
            free(work);
            if (bounce) free(bounce);
            aws_mem_release(allocator, pbuf);
            return aws_raise_error(AWS_ERROR_OOM);
        }
        for (size_t i = 0; i < options->spdk_target_count; i++) {
            const struct aws_s3_jbof_spdk_target *st = &options->spdk_targets[i];
            snprintf(spdk_tgts[i].traddr, sizeof(spdk_tgts[i].traddr), "%.*s",
                     (int)st->traddr.len, st->traddr.ptr);
            spdk_tgts[i].trsvcid = st->trsvcid;
            snprintf(spdk_tgts[i].subnqn, sizeof(spdk_tgts[i].subnqn), "%.*s",
                     (int)st->subnqn.len, st->subnqn.ptr);
            if (st->hostaddr.len > 0) {
                snprintf(spdk_tgts[i].hostaddr, sizeof(spdk_tgts[i].hostaddr),
                         "%.*s", (int)st->hostaddr.len, st->hostaddr.ptr);
            }
        }
        static rp_spdk_session_t *s_cached_sess = NULL;
        static int s_cached_n_targets = 0;

        if (!s_cached_sess || s_cached_n_targets != (int)options->spdk_target_count) {
            if (s_cached_sess) {
                rp_spdk_session_destroy(s_cached_sess);
                s_cached_sess = NULL;
            }
            s_cached_sess = rp_spdk_session_create(spdk_tgts,
                (int)options->spdk_target_count, 1);
            s_cached_n_targets = (int)options->spdk_target_count;
        }
        free(spdk_tgts);
        if (!s_cached_sess) {
            free(work);
            if (bounce) free(bounce);
            aws_mem_release(allocator, pbuf);
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }
        prc = rp_spdk_execute(work, n_work, pbuf, s_cached_sess,
                              options->verify_crc ? 0 : 1);
    } else {
        prc = rp_execute(work, n_work, pbuf, &pcfg);
    }
#else
    prc = rp_execute(work, n_work, pbuf, &pcfg);
#endif
    double elapsed = jbof_now_sec() - t0;
    free(work);

    /* A6: copy bounce buffer → gpu_buffer after planner completes. */
    if (bounce) {
#ifndef RP_WITHOUT_CUDA
        cudaMemcpy(options->gpu_buffer, bounce, total_bytes, cudaMemcpyHostToDevice);
#else
        memcpy(options->gpu_buffer, bounce, total_bytes);
#endif
        free(bounce);
        bounce = NULL;
        pbuf->data = options->gpu_buffer;
    }

    out_result->object_bytes     = total_bytes;
    out_result->crc_ok           = pbuf->crc_ok;
    out_result->planner_rc       = prc;
    out_result->elapsed_seconds  = elapsed;

    /* Async-path bookkeeping: lease release happens in finish_crc after
     * CRC has been verified. Sync path releases here. */
    struct jbof_lease_ctx *lc = NULL;
    if (lease_token[0] && prc == RP_OK) {
        if (pcfg.async_crc) {
            lc = aws_mem_calloc(allocator, 1, sizeof(*lc));
            if (lc) {
                lc->alloc = allocator;
                lc->pbuf  = pbuf;
                strncpy(lc->host, host_z, sizeof(lc->host) - 1);
                lc->port = options->meta_server_port;
                strncpy(lc->token, lease_token, sizeof(lc->token) - 1);
            }
        } else {
            int rsock = jbof_tcp_connect(host_z, options->meta_server_port);
            if (rsock >= 0) {
                char rreq[512];
                int rl = snprintf(rreq, sizeof(rreq),
                    "DELETE /v1/lease/%s HTTP/1.0\r\n"
                    "Host: %s:%u\r\n"
                    "\r\n",
                    lease_token, host_z, (unsigned)options->meta_server_port);
                if (rl > 0 && (size_t)rl < sizeof(rreq))
                    (void)jbof_send_all(rsock, rreq, (size_t)rl);
                char tmp[256];
                (void)jbof_recv_headers(rsock, tmp, sizeof(tmp));
                close(rsock);
            }
        }
    }

    if (pcfg.async_crc && prc == RP_OK) {
        out_result->_planner_buffer = lc;   /* opaque to caller */
    } else {
        out_result->_planner_buffer = NULL;
        if (lc) aws_mem_release(allocator, lc);
        aws_mem_release(allocator, pbuf);
    }

    return jbof_raise_for_planner_rc(prc);
}

/* ── Async finish: wait for CRC, release lease, free planner state ── */

int aws_s3_jbof_get_finish_crc(struct aws_s3_jbof_get_result *result) {
    if (!result) return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    if (!result->_planner_buffer) return AWS_OP_SUCCESS;   /* sync path */

    struct jbof_lease_ctx *lc = result->_planner_buffer;
    int prc = rp_finish_crc(lc->pbuf);
    result->crc_ok = lc->pbuf->crc_ok;

    if (prc == RP_OK && lc->token[0]) {
        int rsock = jbof_tcp_connect(lc->host, lc->port);
        if (rsock >= 0) {
            char rreq[512];
            int rl = snprintf(rreq, sizeof(rreq),
                "DELETE /v1/lease/%s HTTP/1.0\r\n"
                "Host: %s:%u\r\n\r\n",
                lc->token, lc->host, (unsigned)lc->port);
            if (rl > 0 && (size_t)rl < sizeof(rreq))
                (void)jbof_send_all(rsock, rreq, (size_t)rl);
            char tmp[256];
            (void)jbof_recv_headers(rsock, tmp, sizeof(tmp));
            close(rsock);
        }
    }

    struct aws_allocator *alloc = lc->alloc;
    aws_mem_release(alloc, lc->pbuf);
    aws_mem_release(alloc, lc);
    result->_planner_buffer = NULL;

    return jbof_raise_for_planner_rc(prc);
}

/* ════════════════════════════════════════════════════════════════════ *
 *  Client object: layout cache + fd pool
 * ════════════════════════════════════════════════════════════════════ */

static uint64_t jbof_now_unix_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* ── Layout cache entry (singly-linked, LRU via cached_at) ─────────── */

struct jbof_cache_entry {
    struct jbof_cache_entry *next;
    char     *bucket;
    char     *key;
    uint64_t  layout_epoch;
    uint64_t  lease_expires_at_unix_ms;
    uint64_t  cached_at_unix_ms;
    uint64_t  object_size;
    char     *etag;
    char     *version_id;
    rp_extent_t *extents;
    size_t       n_extents;
};

static void jbof_cache_entry_free(struct aws_allocator *a,
                                  struct jbof_cache_entry *e) {
    if (!e) return;
    aws_mem_release(a, e->bucket);
    aws_mem_release(a, e->key);
    aws_mem_release(a, e->etag);
    aws_mem_release(a, e->version_id);
    aws_mem_release(a, e->extents);
    aws_mem_release(a, e);
}

/* ── fd pool entry (per subnqn, nsid, worker_index) ────────────────── */

struct jbof_fd_entry {
    struct jbof_fd_entry *next;
    char     subnqn[256];
    uint32_t nsid;
    int      worker_index;
    int      fd;
};

/* ── Client struct ────────────────────────────────────────────────── */

struct aws_s3_jbof_client {
    struct aws_allocator    *alloc;
    char                     meta_host[64];
    uint16_t                 meta_port;
    size_t                   max_cache_entries;
    pthread_mutex_t          cache_mu;
    struct jbof_cache_entry *cache_head;
    size_t                   cache_count;
    pthread_mutex_t          fd_mu;
    struct jbof_fd_entry    *fd_head;
    char access_key[256], secret_key[256], session_token[1024];
    char region[64], service[32];
    int  signing_enabled;
    int  use_o_direct;
#ifdef WITH_SPDK_BYPASS
    rp_spdk_session_t       *spdk_session;
#endif
};

struct aws_s3_jbof_client *aws_s3_jbof_client_new(
    struct aws_allocator *allocator,
    const struct aws_s3_jbof_client_options *options) {
    if (!allocator || !options) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }
    struct aws_s3_jbof_client *c = aws_mem_calloc(allocator, 1, sizeof(*c));
    if (!c) { aws_raise_error(AWS_ERROR_OOM); return NULL; }
    c->alloc = allocator;
    size_t hlen = options->meta_server_host.len < sizeof(c->meta_host) - 1
                ? options->meta_server_host.len : sizeof(c->meta_host) - 1;
    memcpy(c->meta_host, options->meta_server_host.ptr, hlen);
    c->meta_host[hlen] = '\0';
    c->meta_port = options->meta_server_port;
    c->max_cache_entries = options->max_cache_entries ? options->max_cache_entries : 1024;
    c->use_o_direct = options->use_o_direct;
    pthread_mutex_init(&c->cache_mu, NULL);
    pthread_mutex_init(&c->fd_mu, NULL);

    if (options->access_key.len && options->secret_key.len) {
        jbof_cur_to_cstr(options->access_key,    c->access_key,    sizeof(c->access_key));
        jbof_cur_to_cstr(options->secret_key,    c->secret_key,    sizeof(c->secret_key));
        jbof_cur_to_cstr(options->session_token, c->session_token, sizeof(c->session_token));
        jbof_cur_to_cstr(options->region,        c->region,        sizeof(c->region));
        jbof_cur_to_cstr(options->service,       c->service,       sizeof(c->service));
        if (!c->region[0])  snprintf(c->region,  sizeof(c->region),  "us-east-1");
        if (!c->service[0]) snprintf(c->service, sizeof(c->service), "s3");
        c->signing_enabled = 1;
    }

#ifdef WITH_SPDK_BYPASS
    if (options->spdk_targets && options->spdk_target_count > 0) {
        rp_spdk_target_t *spdk_tgts = calloc(options->spdk_target_count,
                                              sizeof(*spdk_tgts));
        if (!spdk_tgts) {
            aws_mem_release(allocator, c);
            aws_raise_error(AWS_ERROR_OOM);
            return NULL;
        }
        for (size_t i = 0; i < options->spdk_target_count; i++) {
            const struct aws_s3_jbof_spdk_target *st = &options->spdk_targets[i];
            snprintf(spdk_tgts[i].traddr, sizeof(spdk_tgts[i].traddr), "%.*s",
                     (int)st->traddr.len, st->traddr.ptr);
            spdk_tgts[i].trsvcid = st->trsvcid;
            snprintf(spdk_tgts[i].subnqn, sizeof(spdk_tgts[i].subnqn), "%.*s",
                     (int)st->subnqn.len, st->subnqn.ptr);
            if (st->hostaddr.len > 0) {
                snprintf(spdk_tgts[i].hostaddr, sizeof(spdk_tgts[i].hostaddr),
                         "%.*s", (int)st->hostaddr.len, st->hostaddr.ptr);
            }
        }
        c->spdk_session = rp_spdk_session_create(spdk_tgts,
            (int)options->spdk_target_count, 1);
        free(spdk_tgts);
        if (!c->spdk_session) {
            aws_mem_release(allocator, c);
            aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
            return NULL;
        }
    }
#endif
    return c;
}

void aws_s3_jbof_client_destroy(struct aws_s3_jbof_client *c) {
    if (!c) return;
    pthread_mutex_lock(&c->cache_mu);
    struct jbof_cache_entry *e = c->cache_head;
    while (e) {
        struct jbof_cache_entry *next = e->next;
        jbof_cache_entry_free(c->alloc, e);
        e = next;
    }
    pthread_mutex_unlock(&c->cache_mu);
    pthread_mutex_destroy(&c->cache_mu);

    pthread_mutex_lock(&c->fd_mu);
    struct jbof_fd_entry *fe = c->fd_head;
    while (fe) {
        struct jbof_fd_entry *next = fe->next;
        if (fe->fd >= 0) close(fe->fd);
        aws_mem_release(c->alloc, fe);
        fe = next;
    }
    pthread_mutex_unlock(&c->fd_mu);
    pthread_mutex_destroy(&c->fd_mu);

#ifdef WITH_SPDK_BYPASS
    if (c->spdk_session) {
        rp_spdk_session_destroy(c->spdk_session);
        c->spdk_session = NULL;
    }
#endif

    aws_mem_release(c->alloc, c);
}

void *aws_s3_jbof_client_get_spdk_session(struct aws_s3_jbof_client *client) {
#ifdef WITH_SPDK_BYPASS
    return client ? client->spdk_session : NULL;
#else
    return NULL;
#endif
}

/* Linear cache lookup. n is bounded by max_cache_entries (default 1024). */
static struct jbof_cache_entry *jbof_cache_find_locked(
    struct aws_s3_jbof_client *c,
    struct aws_byte_cursor bucket,
    struct aws_byte_cursor key) {
    for (struct jbof_cache_entry *e = c->cache_head; e; e = e->next) {
        if (strlen(e->bucket) == bucket.len &&
            strlen(e->key)    == key.len    &&
            memcmp(e->bucket, bucket.ptr, bucket.len) == 0 &&
            memcmp(e->key,    key.ptr,    key.len)    == 0) {
            return e;
        }
    }
    return NULL;
}

static void jbof_cache_evict_oldest_locked(struct aws_s3_jbof_client *c) {
    struct jbof_cache_entry *oldest = NULL, *oldest_prev = NULL, *prev = NULL;
    for (struct jbof_cache_entry *e = c->cache_head; e; prev = e, e = e->next) {
        if (!oldest || e->cached_at_unix_ms < oldest->cached_at_unix_ms) {
            oldest = e;
            oldest_prev = prev;
        }
    }
    if (!oldest) return;
    if (oldest_prev) oldest_prev->next = oldest->next;
    else             c->cache_head     = oldest->next;
    jbof_cache_entry_free(c->alloc, oldest);
    c->cache_count--;
}

static void jbof_cache_remove_locked(struct aws_s3_jbof_client *c,
                                     struct aws_byte_cursor bucket,
                                     struct aws_byte_cursor key) {
    struct jbof_cache_entry *prev = NULL;
    for (struct jbof_cache_entry *e = c->cache_head; e; prev = e, e = e->next) {
        if (strlen(e->bucket) == bucket.len && strlen(e->key) == key.len &&
            memcmp(e->bucket, bucket.ptr, bucket.len) == 0 &&
            memcmp(e->key,    key.ptr,    key.len)    == 0) {
            if (prev) prev->next = e->next; else c->cache_head = e->next;
            jbof_cache_entry_free(c->alloc, e);
            c->cache_count--;
            return;
        }
    }
}

/* Per-(target, worker_index) fd. Lazy open. */
static int jbof_fd_pool_acquire(struct aws_s3_jbof_client *c,
                                const rp_target_t *t,
                                const char *device_path,
                                int worker_index) {
    pthread_mutex_lock(&c->fd_mu);
    for (struct jbof_fd_entry *fe = c->fd_head; fe; fe = fe->next) {
        if (fe->nsid == t->nsid &&
            fe->worker_index == worker_index &&
            strcmp(fe->subnqn, t->subnqn) == 0) {
            int fd = fe->fd;
            pthread_mutex_unlock(&c->fd_mu);
            return fd;
        }
    }
    int flags = O_RDONLY;
    if (c->use_o_direct) flags |= O_DIRECT;
    int fd = open(device_path, flags);
    if (fd < 0) {
        pthread_mutex_unlock(&c->fd_mu);
        return -1;
    }
    struct jbof_fd_entry *fe = aws_mem_calloc(c->alloc, 1, sizeof(*fe));
    if (!fe) {
        close(fd);
        pthread_mutex_unlock(&c->fd_mu);
        return -1;
    }
    strncpy(fe->subnqn, t->subnqn, sizeof(fe->subnqn) - 1);
    fe->subnqn[sizeof(fe->subnqn) - 1] = '\0';
    fe->nsid = t->nsid;
    fe->worker_index = worker_index;
    fe->fd = fd;
    fe->next = c->fd_head;
    c->fd_head = fe;
    pthread_mutex_unlock(&c->fd_mu);
    return fd;
}

/* ── Pooled open_target callback (per-worker fd indexing) ──────────── */
/* The planner today doesn't pass a worker_index through the callback.
 * Work around by maintaining a per-target atomic counter in user data. */

struct jbof_pool_ctx {
    struct aws_s3_jbof_client *client;
    const struct aws_s3_jbof_target_device *targets;
    size_t                                  n_targets;
    pthread_mutex_t                         counter_mu;
    /* counters[i] tracks how many times target i has been opened in the
     * current rp_execute. Reset by caller before each call. */
    int                                    *counters;
};

static int jbof_pooled_open_target(const rp_target_t *t, void *user) {
    struct jbof_pool_ctx *ctx = user;
    /* Find the target entry. */
    size_t ti = (size_t)-1;
    for (size_t i = 0; i < ctx->n_targets; i++) {
        if (t->nsid != ctx->targets[i].nsid) continue;
        if (ctx->targets[i].subnqn.len != strlen(t->subnqn)) continue;
        if (memcmp(t->subnqn, ctx->targets[i].subnqn.ptr,
                   ctx->targets[i].subnqn.len) != 0) continue;
        ti = i; break;
    }
    if (ti == (size_t)-1) return -1;

    /* Atomically grab the next worker index for this target. */
    pthread_mutex_lock(&ctx->counter_mu);
    int widx = ctx->counters[ti]++;
    pthread_mutex_unlock(&ctx->counter_mu);

    char path[256];
    size_t l = ctx->targets[ti].device_path.len < sizeof(path) - 1
             ? ctx->targets[ti].device_path.len : sizeof(path) - 1;
    memcpy(path, ctx->targets[ti].device_path.ptr, l);
    path[l] = '\0';

    /* dup() because the planner close()s the fd it received; the pool
     * keeps the canonical fd open. */
    int pooled = jbof_fd_pool_acquire(ctx->client, t, path, widx);
    if (pooled < 0) return -1;
    int dup_fd = dup(pooled);
    return dup_fd;
}

/* ── HTTP layout fetch shared by client + standalone helper ─────────── *
 * Extracted here so the client can call it without re-running the body
 * parser inline. Populates a freshly-allocated cache entry. */

static int jbof_fetch_layout(struct aws_allocator *allocator,
                             const char *host_z, uint16_t port,
                             struct aws_byte_cursor bucket,
                             struct aws_byte_cursor key,
                             uint64_t range_offset, uint64_t range_length,
                             const struct aws_s3_jbof_client *signing_client,
                             char *lease_token_out, size_t lease_token_cap,
                             struct jbof_cache_entry **out_entry) {
    *out_entry = NULL;
    if (lease_token_out && lease_token_cap) lease_token_out[0] = '\0';

    /* Percent-encode bucket/key once; reused for both the SigV4 canonical
     * URI and the literal request line below (must never diverge — see the
     * matching comment in aws_s3_jbof_get_object). */
    char enc_bucket[256], enc_key[3200];
    size_t enc_bucket_len = jbof_get_uri_encode(
        (const char *)bucket.ptr, bucket.len, enc_bucket, sizeof(enc_bucket));
    size_t enc_key_len = jbof_get_uri_encode(
        (const char *)key.ptr, key.len, enc_key, sizeof(enc_key));
    if (enc_bucket_len >= sizeof(enc_bucket) || enc_key_len >= sizeof(enc_key)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    char path[sizeof(enc_bucket) + sizeof(enc_key) + 4];
    int path_len = snprintf(path, sizeof(path), "/%s/%s", enc_bucket, enc_key);
    if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    int sock = jbof_tcp_connect(host_z, port);
    if (sock < 0) return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);

    /* Fix (ranged cached GET): this request previously never carried a
     * Range header, yet the caller validates the returned layout's summed
     * length against range_length — which only works if the metadata
     * server independently guesses the range. Send it explicitly. */
    char range_hdr[64] = "";
    if (range_length) {
        snprintf(range_hdr, sizeof(range_hdr),
                 "Range: bytes=%llu-%llu\r\n",
                 (unsigned long long)range_offset,
                 (unsigned long long)(range_offset + range_length - 1));
    }

    char sig_block[1536] = "";
    if (signing_client && signing_client->signing_enabled) {
        char host_port[96];
        snprintf(host_port, sizeof(host_port), "%s:%u", host_z, (unsigned)port);
        struct aws_s3_jbof_sigv4_input in = {
            .method = "GET", .canonical_uri = path, .canonical_query = "",
            .host_header = host_port,
            .region = signing_client->region, .service = signing_client->service,
            .access_key = signing_client->access_key,
            .secret_key = signing_client->secret_key,
            .session_token = signing_client->session_token[0]
                               ? signing_client->session_token : NULL,
        };
        struct aws_s3_jbof_sigv4_output sv = {0};
        if (aws_s3_jbof_sigv4_sign(&in, &sv) == AWS_OP_SUCCESS) {
            int sn = snprintf(sig_block, sizeof(sig_block),
                "X-Amz-Date: %s\r\n"
                "X-Amz-Content-SHA256: %s\r\n"
                "Authorization: %s\r\n",
                sv.amz_date, sv.content_sha256, sv.authorization);
            if (sn < 0) sn = 0;
            if ((size_t)sn >= sizeof(sig_block)) sn = (int)sizeof(sig_block) - 1;
            if (signing_client->session_token[0] && (size_t)sn < sizeof(sig_block)) {
                snprintf(sig_block + sn, sizeof(sig_block) - sn,
                         "X-Amz-Security-Token: %s\r\n",
                         signing_client->session_token);
            }
        }
    }

    char req[8192];
    int reqlen = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\n"
        "Host: %s:%u\r\n"
        "Accept: application/vnd.s3rdma.layout+json\r\n"
        "%s%s"
        "\r\n",
        path,
        host_z, (unsigned)port, range_hdr, sig_block);
    if (reqlen < 0 || (size_t)reqlen >= sizeof(req)) {
        close(sock);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (jbof_send_all(sock, req, (size_t)reqlen) < 0) {
        close(sock);
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }
    char hdr_buf[JBOF_HTTP_HDR_BUF];
    int hdrlen = jbof_recv_headers(sock, hdr_buf, sizeof(hdr_buf));
    if (hdrlen < 12 || !jbof_status_ok(hdr_buf, range_length != 0)) {
        close(sock);
        return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
    }

    /* A6/fallback: detect RDMA decline (spec §4.3). Unlike the standalone
     * aws_s3_jbof_get_object (§1a there), this cached-client path has no
     * HTTP-body downloader: a decline's body is raw object bytes, not
     * layout JSON, and jbof_cache_entry only knows how to store a parsed
     * layout. Fail clearly rather than feeding object bytes to the JSON
     * parser below (which would misparse or silently produce garbage).
     * TODO(A6/fallback): to support this path, have jbof_fetch_layout
     * return the raw body plus a "this is data, not layout" flag, and
     * teach aws_s3_jbof_client_get_object to copy it into gpu_buffer the
     * same way aws_s3_jbof_get_object's §1a branch does. */
    {
        char reply[16];
        jbof_header_value(hdr_buf, "x-amz-rdma-reply", reply, sizeof(reply));
        if (reply[0] == '5' && reply[1] == '0' && reply[2] == '1') {
            close(sock);
            return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
        }
    }

    if (!jbof_content_type_ok(hdr_buf, "application/vnd.s3rdma.layout+json")) {
        close(sock);
        return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
    }

    const char *cl = strstr(hdr_buf, "Content-Length:");
    int content_len = cl ? atoi(cl + 15) : 0;
    if (content_len <= 0) {
        close(sock);
        return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
    }
    char *body = aws_mem_calloc(allocator, 1, (size_t)content_len + 1);
    if (!body) { close(sock); return aws_raise_error(AWS_ERROR_OOM); }
    int body_len = jbof_recv_body(sock, body, content_len);
    close(sock);
    if (body_len < content_len) {
        aws_mem_release(allocator, body);
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }
    if (lease_token_out)
        jbof_header_value(hdr_buf, "X-S3RDMA-Lease-Token", lease_token_out, lease_token_cap);

    struct aws_byte_cursor bc = aws_byte_cursor_from_array(body, (size_t)body_len);
    struct aws_json_value *root = aws_json_value_new_from_string(allocator, bc);
    if (!root) {
        aws_mem_release(allocator, body);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    struct jbof_cache_entry *ce = aws_mem_calloc(allocator, 1, sizeof(*ce));
    if (!ce) {
        aws_json_value_destroy(root);
        aws_mem_release(allocator, body);
        return aws_raise_error(AWS_ERROR_OOM);
    }
    ce->bucket = aws_mem_calloc(allocator, 1, bucket.len + 1);
    ce->key    = aws_mem_calloc(allocator, 1, key.len + 1);
    if (!ce->bucket || !ce->key) {
        jbof_cache_entry_free(allocator, ce);
        aws_json_value_destroy(root);
        aws_mem_release(allocator, body);
        return aws_raise_error(AWS_ERROR_OOM);
    }
    memcpy(ce->bucket, bucket.ptr, bucket.len);
    memcpy(ce->key,    key.ptr,    key.len);

    ce->etag                     = jbof_dup_cstr_from_json(allocator, root, "etag");
    ce->version_id               = jbof_dup_cstr_from_json(allocator, root, "version_id");
    ce->layout_epoch             = jbof_get_u64(root, "layout_epoch");
    ce->lease_expires_at_unix_ms = jbof_get_u64(root, "lease_expires_at_unix_ms");
    ce->object_size              = jbof_get_u64(root, "object_size");
    ce->cached_at_unix_ms        = jbof_now_unix_ms();

    struct aws_json_value *exts = aws_json_value_get_from_object(
        root, aws_byte_cursor_from_c_str("extents"));
    if (!exts || !aws_json_value_is_array(exts)) {
        jbof_cache_entry_free(allocator, ce);
        aws_json_value_destroy(root);
        aws_mem_release(allocator, body);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    size_t n_extents = aws_json_get_array_size(exts);
    if (n_extents == 0 || n_extents > JBOF_MAX_EXTENTS) {
        jbof_cache_entry_free(allocator, ce);
        aws_json_value_destroy(root);
        aws_mem_release(allocator, body);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    ce->extents = aws_mem_calloc(allocator, n_extents, sizeof(rp_extent_t));
    if (!ce->extents) {
        jbof_cache_entry_free(allocator, ce);
        aws_json_value_destroy(root);
        aws_mem_release(allocator, body);
        return aws_raise_error(AWS_ERROR_OOM);
    }
    for (size_t i = 0; i < n_extents; i++) {
        struct aws_json_value *eo = aws_json_get_array_element(exts, i);
        if (!eo || jbof_parse_extent(allocator, eo, &ce->extents[i]) != AWS_OP_SUCCESS) {
            jbof_cache_entry_free(allocator, ce);
            aws_json_value_destroy(root);
            aws_mem_release(allocator, body);
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }
    }
    ce->n_extents = n_extents;
    aws_json_value_destroy(root);
    aws_mem_release(allocator, body);
    *out_entry = ce;
    return AWS_OP_SUCCESS;
}

int aws_s3_jbof_client_get_object(struct aws_s3_jbof_client *client,
                                  const struct aws_s3_jbof_get_options *options,
                                  struct aws_s3_jbof_get_result *out_result) {
    if (!client || !options || !out_result) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    memset(out_result, 0, sizeof(*out_result));
    struct aws_allocator *alloc = client->alloc;

    /* 1. Layout cache lookup. Ranged GETs bypass the cache (we cache the
     * full-object layout, not arbitrary slices). */
    int bypass_cache = options->req_range_length != 0;
    char lease_token[128] = {0};
    struct jbof_cache_entry *hit = NULL;
    uint64_t now_ms = jbof_now_unix_ms();
    if (!bypass_cache) {
        pthread_mutex_lock(&client->cache_mu);
        hit = jbof_cache_find_locked(client, options->bucket, options->key);
        if (hit && hit->lease_expires_at_unix_ms <= now_ms) {
            jbof_cache_remove_locked(client, options->bucket, options->key);
            hit = NULL;
        }
    } else {
        pthread_mutex_lock(&client->cache_mu);   /* still take it; we unlock below */
    }
    /* Snapshot the cache entry under the lock so the cache stays consistent
     * during plan_build (which copies them again into ReadWork). Strings
     * are dup'd to insulate against concurrent eviction. */
    rp_extent_t *local_extents = NULL;
    size_t   local_n = 0;
    char    *local_etag = NULL, *local_version_id = NULL;
    uint64_t local_layout_epoch = 0, local_lease_expires = 0;
    if (hit) {
        local_extents = aws_mem_calloc(alloc, hit->n_extents, sizeof(rp_extent_t));
        if (local_extents) {
            memcpy(local_extents, hit->extents, hit->n_extents * sizeof(rp_extent_t));
            local_n = hit->n_extents;
            if (hit->etag) {
                size_t l = strlen(hit->etag);
                local_etag = aws_mem_calloc(alloc, 1, l + 1);
                if (local_etag) memcpy(local_etag, hit->etag, l);
            }
            if (hit->version_id) {
                size_t l = strlen(hit->version_id);
                local_version_id = aws_mem_calloc(alloc, 1, l + 1);
                if (local_version_id) memcpy(local_version_id, hit->version_id, l);
            }
            local_layout_epoch  = hit->layout_epoch;
            local_lease_expires = hit->lease_expires_at_unix_ms;
        } else {
            hit = NULL;   /* treat as miss; cache still valid for next call */
        }
    }
    pthread_mutex_unlock(&client->cache_mu);

    if (!hit) {
        /* 2. HTTP fetch on miss. */
        struct jbof_cache_entry *fresh = NULL;
        if (jbof_fetch_layout(alloc, client->meta_host, client->meta_port,
                              options->bucket, options->key,
                              options->req_range_offset, options->req_range_length,
                              client,
                              lease_token, sizeof(lease_token),
                              &fresh) != AWS_OP_SUCCESS) {
            return AWS_OP_ERR;
        }
        /* 3. Validate before caching. For ranged GETs the per-extent sum
         * should equal range_length, not object_size. */
        size_t expected_total = options->req_range_length
                                  ? (size_t)options->req_range_length
                                  : (size_t)fresh->object_size;
        if (jbof_validate_layout(fresh->extents, fresh->n_extents,
                                 expected_total,
                                 options->target_devices,
                                 options->target_device_count) != AWS_OP_SUCCESS) {
            jbof_cache_entry_free(alloc, fresh);
            return AWS_OP_ERR;
        }
        /* 4. Insert into cache (evict-then-insert if full). */
        pthread_mutex_lock(&client->cache_mu);
        while (client->cache_count >= client->max_cache_entries) {
            jbof_cache_evict_oldest_locked(client);
        }
        fresh->next = client->cache_head;
        client->cache_head = fresh;
        client->cache_count++;
        /* Take a private copy of extents + strings for this run. */
        local_extents = aws_mem_calloc(alloc, fresh->n_extents, sizeof(rp_extent_t));
        if (local_extents) {
            memcpy(local_extents, fresh->extents,
                   fresh->n_extents * sizeof(rp_extent_t));
            local_n = fresh->n_extents;
            if (fresh->etag) {
                size_t l = strlen(fresh->etag);
                local_etag = aws_mem_calloc(alloc, 1, l + 1);
                if (local_etag) memcpy(local_etag, fresh->etag, l);
            }
            if (fresh->version_id) {
                size_t l = strlen(fresh->version_id);
                local_version_id = aws_mem_calloc(alloc, 1, l + 1);
                if (local_version_id) memcpy(local_version_id, fresh->version_id, l);
            }
            local_layout_epoch  = fresh->layout_epoch;
            local_lease_expires = fresh->lease_expires_at_unix_ms;
        }
        pthread_mutex_unlock(&client->cache_mu);
        if (!local_extents) return aws_raise_error(AWS_ERROR_OOM);
    }

    /* Populate result top-level fields. Ownership transfers to result. */
    out_result->etag                     = local_etag;
    out_result->version_id               = local_version_id;
    out_result->layout_epoch             = local_layout_epoch;
    out_result->lease_expires_at_unix_ms = local_lease_expires;

    /* 5. Drive planner using pooled fds. */

    /* A6: Bounce buffer for soft-RoCE — pread into CPU scratch then copy
     * to gpu_buffer. Activated by use_bounce_buffer flag or SHFT_BOUNCE
     * env var. A6: pass --use-bounce-buffer to demo to test this path */
    size_t total_bytes;
    if (options->req_range_length) {
        total_bytes = (size_t)options->req_range_length;
    } else {
        /* MAX(object_offset + length) across extents, NOT sum of lengths.
         * The planner writes each extent at plan_dst + object_offset
         * (rp_plan_build_ranged), so a layout with gaps or reordered
         * extents makes sum(length) undercount the highest byte actually
         * written — that undercount let rp_execute write past
         * gpu_buffer/bounce. Mirrors the overflow-checked computation in
         * the standalone path (aws_s3_jbof_get_object). */
        total_bytes = 0;
        for (size_t i = 0; i < local_n; i++) {
            size_t off = (size_t)local_extents[i].object_offset;
            size_t len = (size_t)local_extents[i].length;
            size_t end = off + len;
            if (end < off) {   /* overflow: server-controlled object_offset */
                aws_mem_release(alloc, local_extents);
                return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
            }
            if (end > total_bytes) total_bytes = end;
        }
    }

    /* Capacity check BEFORE any pread/execute — and before sizing the
     * bounce buffer below, which is later memcpy'd straight into
     * gpu_buffer at this same size. */
    if (total_bytes > options->gpu_buffer_capacity) {
        aws_mem_release(alloc, local_extents);
        return aws_raise_error(AWS_ERROR_S3_INVALID_RESPONSE_STATUS);
    }

    int need_bounce = options->use_bounce_buffer || (getenv("SHFT_BOUNCE") != NULL);
    void *bounce = NULL;
    void *plan_dst = options->gpu_buffer;
    if (need_bounce) {
        bounce = malloc(total_bytes);
        if (!bounce) {
            aws_mem_release(alloc, local_extents);
            return aws_raise_error(AWS_ERROR_OOM);
        }
        plan_dst = bounce;
    }

    rp_read_work_t *work = NULL;
    int n_work = 0;
    int rc = rp_plan_build_ranged(local_extents, (int)local_n,
                                  plan_dst,
                                  options->req_range_offset,
                                  options->req_range_length,
                                  &work, &n_work);
    aws_mem_release(alloc, local_extents);
    if (rc != RP_OK) {
        if (bounce) free(bounce);
        return jbof_raise_for_planner_rc(rc);
    }

    int workers = options->workers_per_target > 0 ? options->workers_per_target : 1;
    int *counters = aws_mem_calloc(alloc, options->target_device_count, sizeof(int));
    (void)workers;
    if (!counters) { free(work); if (bounce) free(bounce); return aws_raise_error(AWS_ERROR_OOM); }
    struct jbof_pool_ctx pool_ctx = {
        .client    = client,
        .targets   = options->target_devices,
        .n_targets = options->target_device_count,
        .counters  = counters,
    };
    pthread_mutex_init(&pool_ctx.counter_mu, NULL);

    rp_gpu_object_buffer_t pbuf = {
        .data   = plan_dst,
        .length = total_bytes,
    };
    rp_planner_config_t pcfg = {
        .worker_threads   = options->workers_per_target,
        .crc_stream       = 0,
        .open_target      = jbof_pooled_open_target,
        .open_target_user = &pool_ctx,
        .skip_crc         = options->verify_crc ? 0 : 1,
        .async_crc        = 0,    /* client path: sync for now; async_crc adds complexity */
    };

    double t0 = jbof_now_sec();
    int prc;
#ifdef WITH_SPDK_BYPASS
    if (client->spdk_session) {
        prc = rp_spdk_execute(work, n_work, &pbuf, client->spdk_session,
                              options->verify_crc ? 0 : 1);
    } else {
        prc = rp_execute(work, n_work, &pbuf, &pcfg);
    }
#else
    prc = rp_execute(work, n_work, &pbuf, &pcfg);
#endif
    double elapsed = jbof_now_sec() - t0;
    free(work);
    pthread_mutex_destroy(&pool_ctx.counter_mu);
    aws_mem_release(alloc, counters);

    /* A6: copy bounce buffer → gpu_buffer after planner completes. */
    if (bounce) {
#ifndef RP_WITHOUT_CUDA
        cudaMemcpy(options->gpu_buffer, bounce, total_bytes, cudaMemcpyHostToDevice);
#else
        memcpy(options->gpu_buffer, bounce, total_bytes);
#endif
        free(bounce);
        bounce = NULL;
    }

    out_result->object_bytes    = total_bytes;
    out_result->crc_ok          = pbuf.crc_ok;
    out_result->planner_rc      = prc;
    out_result->elapsed_seconds = elapsed;
    out_result->_planner_buffer = NULL;

    /* On RP_E_IO: layout might be stale — evict so the next call re-fetches. */
    if (prc == RP_E_IO) {
        pthread_mutex_lock(&client->cache_mu);
        jbof_cache_remove_locked(client, options->bucket, options->key);
        pthread_mutex_unlock(&client->cache_mu);
    }

    /* Release lease on success (HLD §8.1). Only when we just fetched it
     * (cache miss); cached entries don't carry a token. */
    if (prc == RP_OK && lease_token[0]) {
        int rsock = jbof_tcp_connect(client->meta_host, client->meta_port);
        if (rsock >= 0) {
            char rreq[512];
            int rl = snprintf(rreq, sizeof(rreq),
                "DELETE /v1/lease/%s HTTP/1.0\r\n"
                "Host: %s:%u\r\n\r\n",
                lease_token, client->meta_host, (unsigned)client->meta_port);
            if (rl > 0 && (size_t)rl < sizeof(rreq))
                (void)jbof_send_all(rsock, rreq, (size_t)rl);
            char tmp[256];
            (void)jbof_recv_headers(rsock, tmp, sizeof(tmp));
            close(rsock);
        }
    }

    return jbof_raise_for_planner_rc(prc);
}

/* ── A4: callback-based async GET ────────────────────────────────────── */

struct jbof_async_ctx {
    struct aws_s3_jbof_client       *client;
    struct aws_s3_jbof_get_options   opts;   /* shallow copy; caller owns deep ptrs */
    struct aws_s3_jbof_get_result   *out_result;
    aws_s3_jbof_get_completion_fn    on_complete;
    void                            *user_data;
};

static void *jbof_async_thread(void *arg) {
    struct jbof_async_ctx *ctx = arg;
    int rc = aws_s3_jbof_client_get_object(ctx->client, &ctx->opts,
                                            ctx->out_result);
    ctx->on_complete(rc, ctx->out_result, ctx->user_data);
    free(ctx);
    return NULL;
}

int aws_s3_jbof_client_get_object_async(
    struct aws_s3_jbof_client *client,
    const struct aws_s3_jbof_get_options *options,
    struct aws_s3_jbof_get_result *out_result,
    aws_s3_jbof_get_completion_fn on_complete,
    void *user_data)
{
    if (!client || !options || !out_result || !on_complete) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    struct jbof_async_ctx *ctx = malloc(sizeof(*ctx));
    if (!ctx) return aws_raise_error(AWS_ERROR_OOM);

    ctx->client     = client;
    ctx->opts       = *options;   /* shallow copy; caller owns deep ptrs per API contract */
    ctx->out_result = out_result;
    ctx->on_complete = on_complete;
    ctx->user_data  = user_data;

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int err = pthread_create(&tid, &attr, jbof_async_thread, ctx);
    pthread_attr_destroy(&attr);
    if (err != 0) {
        free(ctx);
        return aws_raise_error(AWS_ERROR_THREAD_INVALID_SETTINGS);
    }
    return AWS_OP_SUCCESS;
}

#endif /* AWS_ENABLE_JBOF */
