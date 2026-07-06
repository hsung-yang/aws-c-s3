#ifndef AWS_S3_JBOF_SIGV4_H
#define AWS_S3_JBOF_SIGV4_H

/*
 * Minimal SigV4 signer for JBOF metadata requests.
 *
 * Computes:
 *   - X-Amz-Date                    (out_amz_date, ISO8601 basic)
 *   - X-Amz-Content-SHA256           (out_content_sha)
 *   - Authorization: AWS4-HMAC-SHA256 ... (out_authz)
 *
 * Payload hash is always SHA256("") per RDMA_PROTOCOL_SPEC.md §6.1 — the
 * body is empty on the wire even when there is RDMA payload behind the
 * request. The helper signs (method, path, query, host, region, service,
 * access_key, secret_key, [session_token]) and produces the three header
 * values the caller stitches into the outgoing raw HTTP request.
 *
 * No aws-c-auth dependency — pure SHA-256/HMAC-SHA256 + sprintf. Caller
 * owns all buffers.
 *
 * IMPORTANT — canonical_uri encoding contract: this signer does NOT
 * percent-encode the path. `canonical_uri` (and `canonical_query`) MUST
 * already be percent-encoded exactly as they will appear on the wire
 * (unreserved chars [A-Za-z0-9-._~] literal, everything else — including
 * a literal '/' *within* a path segment — percent-encoded; the '/'
 * segment separators themselves stay literal; encode the path segment
 * exactly ONCE for S3, per SigV4). Callers (s3_jbof_get.c / s3_jbof_put.c /
 * s3_jbof_mpu.c) build canonical_uri from bucket/key and are responsible
 * for this encoding before calling in; passing an already-percent-encoded
 * string here and re-encoding it, or passing a raw/unencoded string, both
 * produce a signature that does not match the wire request.
 *
 * Returns AWS_OP_SUCCESS / AWS_OP_ERR (sets aws_last_error on failure).
 */

#include <aws/s3/exports.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct aws_s3_jbof_sigv4_input {
    const char *method;            /* "GET", "PUT", "DELETE" */
    /* Path, MUST already be percent-encoded by the caller exactly as it
     * will be sent on the wire (e.g. "/bucket/key"); this signer does not
     * encode it. See the encoding-contract note above. */
    const char *canonical_uri;
    const char *canonical_query;   /* "" or "rdma-commit=" etc. — also caller pre-encoded */
    const char *host_header;       /* "127.0.0.1:8080" — used verbatim */
    const char *region;            /* "us-east-1" */
    const char *service;           /* "s3" */
    const char *access_key;
    const char *secret_key;
    const char *session_token;     /* may be NULL */
    /* Caller may supply additional headers that MUST be signed
     * (e.g. X-S3RDMA-Object-Size). Format: "name:value\n" repeated.
     * Names lower-case. Trailing newline required. NULL/"" if none.
     * The signer parses this block into individual headers and sorts the
     * full header set (host, x-amz-*, extras) by lowercase name itself —
     * callers do not need to pre-sort extras relative to the fixed
     * headers. */
    const char *extra_signed_headers_block;
    /* Historically: names of those extra headers, semicolon-separated,
     * lower-case, lexicographic order, e.g. "x-s3rdma-object-size". No
     * longer read by the signer (names/order are now derived directly
     * from extra_signed_headers_block and sorted automatically) — kept
     * only for source compatibility with existing callers/initializers. */
    const char *extra_signed_headers_names;
    /* Unix epoch seconds (or 0 → now). Tests inject a fixed value. */
    uint64_t    timestamp;
};

struct aws_s3_jbof_sigv4_output {
    char amz_date[32];          /* "20260630T120000Z" */
    char content_sha256[80];    /* hex(sha256("")) */
    char authorization[1024];   /* "AWS4-HMAC-SHA256 Credential=..." */
};

AWS_S3_API
int aws_s3_jbof_sigv4_sign(const struct aws_s3_jbof_sigv4_input *in,
                           struct aws_s3_jbof_sigv4_output *out);

#ifdef __cplusplus
}
#endif

#endif /* AWS_S3_JBOF_SIGV4_H */
