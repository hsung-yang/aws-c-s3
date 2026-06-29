/*
 * s3_jbof_sigv4.c — self-contained SigV4 signer (no aws-c-auth).
 *
 * Implements:
 *   - SHA-256 (FIPS 180-4)
 *   - HMAC-SHA256 (RFC 2104)
 *   - AWS SigV4 canonical request → string to sign → signing key → signature
 *
 * Public-domain SHA-256 / HMAC from common reference implementations,
 * cleaned up for this file. Payload hash is always SHA256("") per
 * RDMA_PROTOCOL_SPEC.md §6.1 (data goes via RDMA, HTTP body empty).
 */

#ifdef AWS_ENABLE_JBOF

#include <aws/s3/s3_jbof_sigv4.h>
#include <aws/common/error.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ── SHA-256 ────────────────────────────────────────────────────────── */

#define SHA256_BLOCK_BYTES 64
#define SHA256_DIGEST_BYTES 32

typedef struct sha256_ctx {
    uint32_t h[8];
    uint8_t  buf[SHA256_BLOCK_BYTES];
    size_t   buf_len;
    uint64_t total_bits;
} sha256_ctx_t;

static const uint32_t K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

#define ROR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_init(sha256_ctx_t *c) {
    static const uint32_t H0[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    memcpy(c->h, H0, sizeof(H0));
    c->buf_len = 0; c->total_bits = 0;
}

static void sha256_compress(sha256_ctx_t *c, const uint8_t *blk) {
    uint32_t W[64];
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint32_t)blk[i*4] << 24) | ((uint32_t)blk[i*4+1] << 16) |
               ((uint32_t)blk[i*4+2] << 8) | (uint32_t)blk[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(W[i-15], 7) ^ ROR32(W[i-15], 18) ^ (W[i-15] >> 3);
        uint32_t s1 = ROR32(W[i-2], 17) ^ ROR32(W[i-2], 19) ^ (W[i-2] >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }
    uint32_t a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3];
    uint32_t e=c->h[4],f=c->h[5],g=c->h[6],h=c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROR32(e,6) ^ ROR32(e,11) ^ ROR32(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t T1 = h + S1 + ch + K256[i] + W[i];
        uint32_t S0 = ROR32(a,2) ^ ROR32(a,13) ^ ROR32(a,22);
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t T2 = S0 + mj;
        h = g; g = f; f = e; e = d + T1;
        d = cc; cc = b; b = a; a = T1 + T2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g;  c->h[7]+=h;
}

static void sha256_update(sha256_ctx_t *c, const void *data, size_t len) {
    const uint8_t *p = data;
    c->total_bits += (uint64_t)len * 8;
    while (len) {
        size_t take = SHA256_BLOCK_BYTES - c->buf_len;
        if (take > len) take = len;
        memcpy(c->buf + c->buf_len, p, take);
        c->buf_len += take; p += take; len -= take;
        if (c->buf_len == SHA256_BLOCK_BYTES) {
            sha256_compress(c, c->buf);
            c->buf_len = 0;
        }
    }
}

static void sha256_final(sha256_ctx_t *c, uint8_t out[SHA256_DIGEST_BYTES]) {
    c->buf[c->buf_len++] = 0x80;
    if (c->buf_len > SHA256_BLOCK_BYTES - 8) {
        while (c->buf_len < SHA256_BLOCK_BYTES) c->buf[c->buf_len++] = 0;
        sha256_compress(c, c->buf); c->buf_len = 0;
    }
    while (c->buf_len < SHA256_BLOCK_BYTES - 8) c->buf[c->buf_len++] = 0;
    uint64_t bits = c->total_bits;
    for (int i = 7; i >= 0; i--) c->buf[c->buf_len++] = (uint8_t)(bits >> (i*8));
    sha256_compress(c, c->buf);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
}

static void sha256_oneshot(const void *data, size_t len,
                           uint8_t out[SHA256_DIGEST_BYTES]) {
    sha256_ctx_t c; sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

/* ── HMAC-SHA256 ────────────────────────────────────────────────────── */

static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t out[SHA256_DIGEST_BYTES]) {
    uint8_t kpad[SHA256_BLOCK_BYTES];
    uint8_t khash[SHA256_DIGEST_BYTES];
    if (key_len > SHA256_BLOCK_BYTES) {
        sha256_oneshot(key, key_len, khash);
        key = khash; key_len = SHA256_DIGEST_BYTES;
    }
    memset(kpad, 0, sizeof(kpad));
    memcpy(kpad, key, key_len);

    uint8_t ipad[SHA256_BLOCK_BYTES], opad[SHA256_BLOCK_BYTES];
    for (int i = 0; i < SHA256_BLOCK_BYTES; i++) {
        ipad[i] = kpad[i] ^ 0x36;
        opad[i] = kpad[i] ^ 0x5c;
    }

    uint8_t inner[SHA256_DIGEST_BYTES];
    sha256_ctx_t c;
    sha256_init(&c);
    sha256_update(&c, ipad, SHA256_BLOCK_BYTES);
    sha256_update(&c, msg, msg_len);
    sha256_final(&c, inner);

    sha256_init(&c);
    sha256_update(&c, opad, SHA256_BLOCK_BYTES);
    sha256_update(&c, inner, SHA256_DIGEST_BYTES);
    sha256_final(&c, out);
}

static void hex_lower(const uint8_t *bytes, size_t n, char *out) {
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i*2]   = hex[(bytes[i] >> 4) & 0xF];
        out[i*2+1] = hex[ bytes[i]       & 0xF];
    }
    out[n*2] = '\0';
}

/* ── SigV4 ──────────────────────────────────────────────────────────── */

/* SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
static const char EMPTY_BODY_SHA256[] =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

int aws_s3_jbof_sigv4_sign(const struct aws_s3_jbof_sigv4_input *in,
                           struct aws_s3_jbof_sigv4_output *out) {
    if (!in || !out || !in->method || !in->canonical_uri || !in->host_header ||
        !in->region || !in->service || !in->access_key || !in->secret_key) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* Timestamp → "YYYYMMDDTHHMMSSZ" and "YYYYMMDD". */
    time_t now = (time_t)(in->timestamp ? in->timestamp : (uint64_t)time(NULL));
    struct tm tm_utc;
#if defined(_WIN32)
    gmtime_s(&tm_utc, &now);
#else
    gmtime_r(&now, &tm_utc);
#endif
    char date_short[16];
    snprintf(out->amz_date, sizeof(out->amz_date),
             "%04d%02d%02dT%02d%02d%02dZ",
             tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday,
             tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec);
    snprintf(date_short, sizeof(date_short),
             "%04d%02d%02d",
             tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday);

    /* Content-SHA256 header value (always SHA256 of empty body). */
    snprintf(out->content_sha256, sizeof(out->content_sha256),
             "%s", EMPTY_BODY_SHA256);

    /* Canonical headers (lower-case names, sorted lexicographically).
     * We always sign: host, x-amz-content-sha256, x-amz-date. Optionally
     * x-amz-security-token + any extras the caller supplied. */
    char canonical_headers[2048];
    char signed_headers[512];
    int needs_token = in->session_token && in->session_token[0];

    /* Insert in sorted order. Names known to be sorted:
     *   host < x-amz-content-sha256 < x-amz-date < x-amz-security-token
     * Extras (caller-supplied) come in the right place by being added
     * AFTER host but BEFORE x-amz-* (we don't validate the caller's
     * order). For now, require extras to be sorted by the caller and
     * start with names < "x-amz-*". */
    int chn = snprintf(canonical_headers, sizeof(canonical_headers),
                       "host:%s\n", in->host_header);
    int shn = snprintf(signed_headers, sizeof(signed_headers), "host");

    if (in->extra_signed_headers_block && in->extra_signed_headers_block[0]) {
        chn += snprintf(canonical_headers + chn, sizeof(canonical_headers) - chn,
                        "%s", in->extra_signed_headers_block);
        shn += snprintf(signed_headers + shn, sizeof(signed_headers) - shn,
                        ";%s", in->extra_signed_headers_names);
    }
    chn += snprintf(canonical_headers + chn, sizeof(canonical_headers) - chn,
                    "x-amz-content-sha256:%s\nx-amz-date:%s\n",
                    out->content_sha256, out->amz_date);
    shn += snprintf(signed_headers + shn, sizeof(signed_headers) - shn,
                    ";x-amz-content-sha256;x-amz-date");
    if (needs_token) {
        chn += snprintf(canonical_headers + chn, sizeof(canonical_headers) - chn,
                        "x-amz-security-token:%s\n", in->session_token);
        shn += snprintf(signed_headers + shn, sizeof(signed_headers) - shn,
                        ";x-amz-security-token");
    }

    /* Canonical request = method + uri + query + canonical_headers + "" +
     *                     signed_headers + payload_hash */
    char canonical_request[4096];
    int crn = snprintf(canonical_request, sizeof(canonical_request),
                       "%s\n%s\n%s\n%s\n%s\n%s",
                       in->method,
                       in->canonical_uri,
                       in->canonical_query ? in->canonical_query : "",
                       canonical_headers,
                       signed_headers,
                       EMPTY_BODY_SHA256);
    if (crn <= 0 || crn >= (int)sizeof(canonical_request)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* String to sign. */
    uint8_t cr_hash[SHA256_DIGEST_BYTES];
    sha256_oneshot(canonical_request, (size_t)crn, cr_hash);
    char cr_hash_hex[SHA256_DIGEST_BYTES * 2 + 1];
    hex_lower(cr_hash, SHA256_DIGEST_BYTES, cr_hash_hex);

    char credential_scope[128];
    snprintf(credential_scope, sizeof(credential_scope),
             "%s/%s/%s/aws4_request",
             date_short, in->region, in->service);

    char string_to_sign[1024];
    snprintf(string_to_sign, sizeof(string_to_sign),
             "AWS4-HMAC-SHA256\n%s\n%s\n%s",
             out->amz_date, credential_scope, cr_hash_hex);

    /* Signing key. */
    char kSecret[256];
    snprintf(kSecret, sizeof(kSecret), "AWS4%s", in->secret_key);

    uint8_t kDate[SHA256_DIGEST_BYTES];
    uint8_t kRegion[SHA256_DIGEST_BYTES];
    uint8_t kService[SHA256_DIGEST_BYTES];
    uint8_t kSigning[SHA256_DIGEST_BYTES];
    hmac_sha256((const uint8_t *)kSecret, strlen(kSecret),
                (const uint8_t *)date_short, strlen(date_short), kDate);
    hmac_sha256(kDate, SHA256_DIGEST_BYTES,
                (const uint8_t *)in->region, strlen(in->region), kRegion);
    hmac_sha256(kRegion, SHA256_DIGEST_BYTES,
                (const uint8_t *)in->service, strlen(in->service), kService);
    hmac_sha256(kService, SHA256_DIGEST_BYTES,
                (const uint8_t *)"aws4_request", 12, kSigning);

    /* Signature. */
    uint8_t sig[SHA256_DIGEST_BYTES];
    hmac_sha256(kSigning, SHA256_DIGEST_BYTES,
                (const uint8_t *)string_to_sign, strlen(string_to_sign), sig);
    char sig_hex[SHA256_DIGEST_BYTES * 2 + 1];
    hex_lower(sig, SHA256_DIGEST_BYTES, sig_hex);

    snprintf(out->authorization, sizeof(out->authorization),
             "AWS4-HMAC-SHA256 "
             "Credential=%s/%s, "
             "SignedHeaders=%s, "
             "Signature=%s",
             in->access_key, credential_scope, signed_headers, sig_hex);

    return AWS_OP_SUCCESS;
}

#endif /* AWS_ENABLE_JBOF */
