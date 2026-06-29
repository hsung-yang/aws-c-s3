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
    const char *canonical_uri;     /* path, percent-encoded; e.g. "/bucket/key" */
    const char *canonical_query;   /* "" or "rdma-commit=" etc. */
    const char *host_header;       /* "127.0.0.1:8080" — used verbatim */
    const char *region;            /* "us-east-1" */
    const char *service;           /* "s3" */
    const char *access_key;
    const char *secret_key;
    const char *session_token;     /* may be NULL */
    /* Caller may supply additional headers that MUST be signed
     * (e.g. X-S3RDMA-Object-Size). Format: "name:value\n" repeated.
     * Names lower-case. Trailing newline required. NULL/"" if none. */
    const char *extra_signed_headers_block;
    /* Names of those extra headers, semicolon-separated, lower-case,
     * lexicographic order. e.g. "x-s3rdma-object-size". */
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
