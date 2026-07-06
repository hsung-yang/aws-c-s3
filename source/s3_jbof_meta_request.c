/*
 * s3_jbof_meta_request.c — JBOF meta-request subclass (Task A5).
 *
 * Routes aws_s3_client_make_meta_request(TYPE_JBOF_GET|TYPE_JBOF_PUT) into
 * the existing blocking JBOF helpers (aws_s3_jbof_client_get_object /
 * aws_s3_jbof_put_object) while conforming to the aws-c-s3 vtable contract.
 *
 * Threading model:
 *   - update() and finished_request() run on the client's process-work
 *     event loop thread.
 *   - prepare_request() is called from the event loop's "prepare" task.
 *     It immediately spawns a pthread to run the blocking JBOF helper
 *     and returns a future.  The pthread sets the future on completion,
 *     which unblocks the framework to proceed with the HTTP send.
 *   - The HTTP round-trip to the mock metadata server is initiated by the
 *     JBOF client helper internally; the framework's HTTP pipeline treats
 *     the request as a single-shot default request (no body streaming).
 *   - finished_request() signals meta-request success/failure based on the
 *     helper return value stored in jbof->completion_error_code.
 */

#ifdef AWS_ENABLE_JBOF

#include "aws/s3/private/s3_jbof_meta_request.h"
#include "aws/s3/private/s3_client_impl.h"
#include "aws/s3/private/s3_meta_request_impl.h"
#include "aws/s3/private/s3_request.h"
#include "aws/s3/private/s3_request_messages.h"
#include "aws/s3/private/s3_util.h"
#include <aws/common/error.h>
#include <aws/http/http.h>
#include <aws/http/request_response.h>
#include <aws/io/io.h>
#include <aws/s3/s3.h>
#include <aws/s3/s3_jbof_get.h>
#include <aws/s3/s3_jbof_put.h>

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── subclass struct ─────────────────────────────────────────────────── */

struct aws_s3_meta_request_jbof {
    struct aws_s3_meta_request             base;
    struct aws_s3_jbof_meta_request_extra *extra;
    int                                    is_put;

    /* D2: copied from extra->disable_rdma_on_retry at construction time. */
    int                                    disable_rdma_on_retry;

    /* Written by background pthread; read by finished_request.
     *
     * op_has_run distinguishes "the blocking JBOF op (GET read+CRC, or PUT
     * write+commit) actually executed at least once, and completion_error_code
     * holds its result" from "prepare_request's worker thread never got to run
     * it" (e.g. pthread_create failed) -- completion_error_code's zero-initialized
     * default is numerically equal to AWS_ERROR_SUCCESS, so it cannot serve as
     * its own "did it run" sentinel.
     *
     * It doubles as the single-shot guard: the framework may re-invoke
     * prepare_request (and thus spawn a new worker thread) on the same
     * meta-request if the synthetic probe HTTP request that follows the JBOF
     * op is retried (see aws_s3_client_notify_connection_finished's
     * AWS_S3_CONNECTION_FINISH_CODE_RETRY path -> s_s3_client_retry_ready ->
     * aws_s3_meta_request_prepare_request, all in s3_client.c, called on the
     * SAME struct aws_s3_request*). Once op_has_run is true, a subsequent
     * worker-thread invocation must NOT re-run the destructive GET/PUT --
     * doing so would double-commit a PUT or double-execute a GET. */
    bool op_has_run;
    int  completion_error_code;

    struct {
        uint32_t request_sent      : 1;
        uint32_t request_completed : 1;
        int      cached_response_status;
    } synced_data;
};

/* ── per-prepare job (heap) ──────────────────────────────────────────── */

struct s3_jbof_prepare_job {
    struct aws_allocator            *allocator;
    struct aws_s3_request           *request;
    struct aws_future_void          *on_complete;
    struct aws_s3_meta_request_jbof *jbof;
};

/* ── vtable forward declarations ─────────────────────────────────────── */

static void s_jbof_destroy(struct aws_s3_meta_request *meta_request);

static bool s_jbof_update(
    struct aws_s3_meta_request *meta_request,
    uint32_t flags,
    struct aws_s3_request **out_request);

static struct aws_future_void *s_jbof_prepare_request(struct aws_s3_request *request);

static void s_jbof_finished_request(
    struct aws_s3_meta_request *meta_request,
    struct aws_s3_request *request,
    int error_code);

static struct aws_s3_meta_request_vtable s_s3_jbof_vtable = {
    .update              = s_jbof_update,
    .send_request_finish = aws_s3_meta_request_send_request_finish_default,
    .prepare_request     = s_jbof_prepare_request,
    .init_signing_date_time = aws_s3_meta_request_init_signing_date_time_default,
    .sign_request        = aws_s3_meta_request_sign_request_default,
    .finished_request    = s_jbof_finished_request,
    .destroy             = s_jbof_destroy,
    .finish              = aws_s3_meta_request_finish_default,
};

/* ── helper: parse "host" header value into host_buf and port ─────────── */

static void s_parse_host_port(
    struct aws_byte_cursor hdr,
    char *host_buf, size_t host_buf_len,
    uint16_t *out_port,
    uint16_t default_port) {

    const char *ptr = (const char *)hdr.ptr;
    size_t len = hdr.len;

    /* Bracketed form: "[host]" or "[host]:port" -- required by RFC 3986 for
     * IPv6 literals precisely so the port-separating ':' is unambiguous.
     * Splitting on the LAST ':' (the old logic) mangles "[::1]:8080" by
     * cutting the host in the middle of the address. */
    if (len > 0 && ptr[0] == '[') {
        const char *close = memchr(ptr, ']', len);
        if (close != NULL) {
            size_t hlen = (size_t)(close - ptr) - 1; /* exclude '[' */
            size_t copy = hlen < host_buf_len - 1 ? hlen : host_buf_len - 1;
            memcpy(host_buf, ptr + 1, copy);
            host_buf[copy] = '\0';

            const char *after = close + 1;
            size_t after_len = len - (size_t)(after - ptr);
            if (after_len > 0 && after[0] == ':') {
                char pbuf[8];
                size_t plen = after_len - 1;
                if (plen >= sizeof(pbuf)) plen = sizeof(pbuf) - 1;
                memcpy(pbuf, after + 1, plen);
                pbuf[plen] = '\0';
                *out_port = (uint16_t)atoi(pbuf);
                if (*out_port == 0) *out_port = default_port;
            } else {
                *out_port = default_port;
            }
            return;
        }
        /* Malformed "[..." with no closing ']': fall through and treat the
         * whole thing as an opaque host below (better than misparsing it). */
    }

    /* Not bracketed. Count colons: a bare (bracketless) IPv6 literal, e.g.
     * "::1" or "fe80::1", has 2+ colons and no way to safely tell host from
     * port apart -- treat the whole string as the host with the default
     * port rather than guessing. Only split on ':' when there is exactly
     * one, which unambiguously means "host:port" (IPv4 or hostname). */
    size_t colon_count = 0;
    const char *colon = NULL;
    for (size_t i = 0; i < len; i++) {
        if (ptr[i] == ':') { colon_count++; colon = ptr + i; }
    }

    if (colon_count == 1) {
        size_t hlen = (size_t)(colon - ptr);
        size_t copy = hlen < host_buf_len - 1 ? hlen : host_buf_len - 1;
        memcpy(host_buf, ptr, copy);
        host_buf[copy] = '\0';
        char pbuf[8];
        size_t plen = len - hlen - 1;
        if (plen >= sizeof(pbuf)) plen = sizeof(pbuf) - 1;
        memcpy(pbuf, colon + 1, plen);
        pbuf[plen] = '\0';
        *out_port = (uint16_t)atoi(pbuf);
        if (*out_port == 0) *out_port = default_port;
    } else {
        /* Zero colons (plain hostname/IPv4 with no port), or 2+ colons
         * (bracketless IPv6 literal, no reliable port separator): keep the
         * whole string as host. */
        size_t copy = len < host_buf_len - 1 ? len : host_buf_len - 1;
        memcpy(host_buf, ptr, copy);
        host_buf[copy] = '\0';
        *out_port = default_port;
    }
}

/* ── helper: bounded percent-decode ─────────────────────────────────── */

/* Decodes %XX escapes in `in` (in_len bytes) into `out` (out_len capacity,
 * NUL-terminated). '+' is left literal -- S3 keys are path segments, not
 * form-encoded query values. Returns AWS_OP_SUCCESS, or AWS_OP_ERR (with
 * AWS_ERROR_INVALID_ARGUMENT raised) if the decoded key would not fit --
 * callers must not silently truncate, since that addresses the wrong
 * object. */
static int s_url_decode(const char *in, size_t in_len, char *out, size_t out_len) {
    size_t o = 0;
    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == '%' && i + 2 < in_len &&
            isxdigit((unsigned char)in[i + 1]) && isxdigit((unsigned char)in[i + 2])) {
            char hex[3] = { in[i + 1], in[i + 2], '\0' };
            c = (char)strtol(hex, NULL, 16);
            i += 2;
        }
        if (o >= out_len - 1) {
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }
        out[o++] = c;
    }
    out[o] = '\0';
    return AWS_OP_SUCCESS;
}

/* ── helper: parse "/bucket/key" path ───────────────────────────────── */

/* Returns AWS_OP_SUCCESS, or raises AWS_ERROR_INVALID_ARGUMENT and returns
 * AWS_OP_ERR if the bucket name or the (decoded) object key does not fit in
 * the supplied buffers. A truncated key would silently address the WRONG
 * object, so this must fail the meta-request rather than truncate. */
static int s_parse_path(
    struct aws_byte_cursor path,
    char *bucket_buf, size_t bucket_len,
    char *key_buf,    size_t key_len) {

    const char *p = (const char *)path.ptr;
    size_t n = path.len;

    /* skip leading '/' */
    if (n > 0 && p[0] == '/') { p++; n--; }

    /* Strip the query string, if any -- it is not part of the object key. */
    const char *qmark = memchr(p, '?', n);
    if (qmark != NULL) {
        n = (size_t)(qmark - p);
    }

    /* find next '/' to split bucket from key */
    const char *slash = memchr(p, '/', n);
    if (!slash) {
        /* no key */
        if (n >= bucket_len) {
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }
        memcpy(bucket_buf, p, n);
        bucket_buf[n] = '\0';
        key_buf[0] = '\0';
        return AWS_OP_SUCCESS;
    }

    size_t blen = (size_t)(slash - p);
    if (blen >= bucket_len) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    memcpy(bucket_buf, p, blen);
    bucket_buf[blen] = '\0';

    const char *kp = slash + 1;
    size_t klen = n - (size_t)(kp - p);
    if (s_url_decode(kp, klen, key_buf, key_len) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/* ── constructor ─────────────────────────────────────────────────────── */

struct aws_s3_meta_request *aws_s3_meta_request_jbof_new(
    struct aws_allocator *allocator,
    struct aws_s3_client *client,
    int is_put,
    const struct aws_s3_meta_request_options *options) {

    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(client);
    AWS_PRECONDITION(options);
    AWS_PRECONDITION(options->message);

    if (options->user_data == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_S3_META_REQUEST,
            "Could not create JBOF meta request: options->user_data must point "
            "to struct aws_s3_jbof_meta_request_extra");
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_s3_meta_request_jbof *jbof =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_s3_meta_request_jbof));

    if (aws_s3_meta_request_init_base(
            allocator,
            client,
            0,
            false,
            false,
            options,
            jbof,
            &s_s3_jbof_vtable,
            &jbof->base)) {

        AWS_LOGF_ERROR(
            AWS_LS_S3_META_REQUEST,
            "id=%p Could not initialize base for JBOF meta request",
            (void *)jbof);
        aws_mem_release(allocator, jbof);
        return NULL;
    }

    jbof->extra                 = (struct aws_s3_jbof_meta_request_extra *)options->user_data;
    jbof->is_put                = is_put;
    jbof->disable_rdma_on_retry = jbof->extra->disable_rdma_on_retry;

    AWS_LOGF_DEBUG(
        AWS_LS_S3_META_REQUEST,
        "id=%p Created JBOF meta request (%s)",
        (void *)jbof,
        is_put ? "PUT" : "GET");

    return &jbof->base;
}

/* ── destroy ─────────────────────────────────────────────────────────── */

static void s_jbof_destroy(struct aws_s3_meta_request *meta_request) {
    AWS_PRECONDITION(meta_request);
    struct aws_s3_meta_request_jbof *jbof = meta_request->impl;
    aws_mem_release(meta_request->allocator, jbof);
}

/* ── update ──────────────────────────────────────────────────────────── */

static bool s_jbof_update(
    struct aws_s3_meta_request *meta_request,
    uint32_t flags,
    struct aws_s3_request **out_request) {
    (void)flags;

    AWS_PRECONDITION(meta_request);
    AWS_PRECONDITION(out_request);

    struct aws_s3_meta_request_jbof *jbof = meta_request->impl;
    struct aws_s3_request *request = NULL;
    bool work_remaining = false;

    aws_s3_meta_request_lock_synced_data(meta_request);

    if (!aws_s3_meta_request_has_finish_result_synced(meta_request)) {

        if (!jbof->synced_data.request_sent) {
            request = aws_s3_request_new(
                meta_request,
                0,
                AWS_S3_REQUEST_TYPE_GET_OBJECT,
                1,
                AWS_S3_REQUEST_FLAG_RECORD_RESPONSE_HEADERS);

            jbof->synced_data.request_sent = true;
            work_remaining = true;

        } else if (!jbof->synced_data.request_completed) {
            work_remaining = true;
        }

    } else {
        /* cancelling: wait for in-flight request if sent */
        work_remaining = jbof->synced_data.request_sent &&
                         !jbof->synced_data.request_completed;
    }

    if (!work_remaining &&
        aws_s3_meta_request_are_events_out_for_delivery_synced(meta_request)) {
        work_remaining = true;
    }

    /* finish_result already set by finished_request; set success again only
     * if we reached no_work after a successful completion (idempotent). */
    if (!work_remaining && jbof->synced_data.request_completed &&
        !aws_s3_meta_request_has_finish_result_synced(meta_request)) {
        aws_s3_meta_request_set_success_synced(
            meta_request, jbof->synced_data.cached_response_status);
    }

    aws_s3_meta_request_unlock_synced_data(meta_request);

    if (work_remaining && request != NULL) {
        *out_request = request;
    } else if (!work_remaining) {
        AWS_ASSERT(request == NULL);
        aws_s3_meta_request_finish(meta_request);
    }

    return work_remaining;
}

/* ── background thread running the blocking JBOF helper ─────────────── */

static void *s_jbof_worker_thread(void *arg) {
    struct s3_jbof_prepare_job *job = arg;
    struct aws_s3_meta_request_jbof *jbof = job->jbof;
    struct aws_s3_meta_request *meta_request = &jbof->base;
    struct aws_s3_jbof_meta_request_extra *extra = jbof->extra;

    /* Single-shot guard (see op_has_run's doc comment on the struct):
     * capture whether the blocking op already ran in a PRIOR invocation of
     * this worker before unconditionally marking that an attempt is now
     * underway. `already_ran` gates the destructive GET/PUT call below;
     * op_has_run itself tells finished_request that completion_error_code
     * is meaningful (as opposed to its zero-initialized default). */
    bool already_ran = jbof->op_has_run;
    jbof->op_has_run = true;

    char host_buf[128]   = "127.0.0.1";
    char bucket_buf[256] = "";
    char key_buf[512]    = "";
    uint16_t port = 8080;

    /* Extract path from HTTP message. */
    struct aws_byte_cursor path;
    AWS_ZERO_STRUCT(path);
    if (aws_http_message_get_request_path(meta_request->initial_request_message, &path)
        != AWS_OP_SUCCESS) {
        jbof->completion_error_code = aws_last_error_or_unknown();
        goto done;
    }
    if (s_parse_path(path, bucket_buf, sizeof(bucket_buf), key_buf, sizeof(key_buf))
        != AWS_OP_SUCCESS) {
        /* Bucket or object key does not fit in the fixed-size buffers.
         * Fail outright rather than silently truncate -- a truncated key
         * would address the wrong object. */
        jbof->completion_error_code = AWS_ERROR_INVALID_ARGUMENT;
        goto done;
    }

    /* Extract host header. */
    {
        const struct aws_http_headers *hdrs =
            aws_http_message_get_headers(meta_request->initial_request_message);
        struct aws_byte_cursor host_hdr;
        AWS_ZERO_STRUCT(host_hdr);
        struct aws_byte_cursor host_name = aws_byte_cursor_from_c_str("host");
        if (aws_http_headers_get(hdrs, host_name, &host_hdr) != AWS_OP_SUCCESS) {
            jbof->completion_error_code = AWS_ERROR_INVALID_ARGUMENT;
            goto done;
        }
        s_parse_host_port(host_hdr, host_buf, sizeof(host_buf), &port, 8080);
    }

    if (already_ran) {
        /* The destructive GET/PUT already executed in a prior invocation of
         * this worker (the framework retried the synthetic probe HTTP
         * request built at `done:` below, which re-invoked prepare_request
         * on the same aws_s3_request). completion_error_code already holds
         * that prior result -- do not re-run the op (would double-commit a
         * PUT or double-execute a GET) and do not re-touch
         * extra->result_out / extra->put_result_ptr. */
        AWS_LOGF_DEBUG(
            AWS_LS_S3_META_REQUEST,
            "id=%p JBOF op already executed once (result %d); skipping re-run on probe retry",
            (void *)meta_request,
            jbof->completion_error_code);
        goto done;
    }

    if (!jbof->is_put) {
        /* ── GET ── */
        struct aws_s3_jbof_client_options copts;
        AWS_ZERO_STRUCT(copts);
        copts.meta_server_host = aws_byte_cursor_from_c_str(host_buf);
        copts.meta_server_port = port;
        copts.use_o_direct     = extra->use_o_direct;
        copts.access_key       = extra->access_key;
        copts.secret_key       = extra->secret_key;
        copts.session_token    = extra->session_token;
        copts.region           = extra->region;
        copts.service          = extra->service;

        struct aws_s3_jbof_client *jclient =
            aws_s3_jbof_client_new(meta_request->allocator, &copts);
        if (!jclient) {
            jbof->completion_error_code = aws_last_error_or_unknown();
            goto done;
        }

        struct aws_s3_jbof_get_options gopts;
        AWS_ZERO_STRUCT(gopts);
        gopts.meta_server_host    = copts.meta_server_host;
        gopts.meta_server_port    = port;
        gopts.bucket              = aws_byte_cursor_from_c_str(bucket_buf);
        gopts.key                 = aws_byte_cursor_from_c_str(key_buf);
        gopts.gpu_buffer          = extra->gpu_buffer;
        gopts.gpu_buffer_capacity = extra->gpu_buffer_capacity;
        gopts.target_devices      = extra->target_devices;
        gopts.target_device_count = extra->target_device_count;
        gopts.workers_per_target  = extra->workers_per_target;
        gopts.verify_crc          = extra->verify_crc ? extra->verify_crc : 1;
        gopts.use_o_direct        = extra->use_o_direct;
        gopts.access_key          = extra->access_key;
        gopts.secret_key          = extra->secret_key;
        gopts.session_token       = extra->session_token;
        gopts.region              = extra->region;
        gopts.service             = extra->service;

        int rc = aws_s3_jbof_client_get_object(jclient, &gopts, &extra->result_out);
        aws_s3_jbof_client_destroy(jclient);

        jbof->completion_error_code =
            (rc == AWS_OP_SUCCESS) ? AWS_ERROR_SUCCESS : aws_last_error_or_unknown();

    } else {
        /* ── PUT ── */
        struct aws_s3_jbof_put_options popts;
        AWS_ZERO_STRUCT(popts);
        popts.meta_server_host    = aws_byte_cursor_from_c_str(host_buf);
        popts.meta_server_port    = port;
        popts.bucket              = aws_byte_cursor_from_c_str(bucket_buf);
        popts.key                 = aws_byte_cursor_from_c_str(key_buf);
        popts.source_buffer       = extra->gpu_buffer;
        popts.source_length       = extra->gpu_buffer_capacity;
        popts.target_devices      = extra->target_devices;
        popts.target_device_count = extra->target_device_count;
        popts.workers_per_target  = extra->workers_per_target;
        popts.access_key          = extra->access_key;
        popts.secret_key          = extra->secret_key;
        popts.session_token       = extra->session_token;
        popts.region              = extra->region;
        popts.service             = extra->service;

        struct aws_s3_jbof_put_result put_res;
        AWS_ZERO_STRUCT(put_res);

        int rc = aws_s3_jbof_put_object(meta_request->allocator, &popts, &put_res);
        if (rc == AWS_OP_SUCCESS) {
            jbof->completion_error_code = AWS_ERROR_SUCCESS;
            if (extra->put_result_ptr) {
                *extra->put_result_ptr = put_res;
            } else {
                aws_s3_jbof_put_result_clean_up(meta_request->allocator, &put_res);
            }
        } else {
            jbof->completion_error_code = aws_last_error_or_unknown();
        }
    }

done:;
    /* Set up a minimal HTTP message so the framework proceeds to
     * finished_request().  Always use GET regardless of the actual operation
     * so the mock metadata server does not trigger a new Phase-1 placement
     * for PUT requests (the JBOF helper already committed the object). */
    struct aws_http_message *msg = aws_http_message_new_request(job->request->allocator);
    if (msg) {
        char path_for_probe[800];
        snprintf(path_for_probe, sizeof(path_for_probe), "/%s/%s",
                 bucket_buf, key_buf);
        aws_http_message_set_request_method(msg, aws_byte_cursor_from_c_str("GET"));
        aws_http_message_set_request_path(msg,
            aws_byte_cursor_from_c_str(path_for_probe));
        struct aws_http_header h = {
            .name  = aws_byte_cursor_from_c_str("host"),
            .value = aws_byte_cursor_from_c_str(host_buf),
        };
        aws_http_message_add_header(msg, h);

        aws_s3_request_setup_send_data(job->request, msg);
        aws_http_message_release(msg);
        aws_future_void_set_result(job->on_complete);
    } else {
        aws_future_void_set_error(
            job->on_complete,
            jbof->completion_error_code != AWS_ERROR_SUCCESS
                ? jbof->completion_error_code
                : AWS_ERROR_UNKNOWN);
    }

    aws_future_void_release(job->on_complete);
    aws_mem_release(job->allocator, job);
    return NULL;
}

/* ── prepare_request ─────────────────────────────────────────────────── */

static struct aws_future_void *s_jbof_prepare_request(struct aws_s3_request *request) {
    AWS_PRECONDITION(request);

    struct aws_s3_meta_request *meta_request = request->meta_request;
    AWS_PRECONDITION(meta_request);

    struct aws_s3_meta_request_jbof *jbof = meta_request->impl;
    AWS_PRECONDITION(jbof);

    struct aws_future_void *future = aws_future_void_new(request->allocator);

    struct s3_jbof_prepare_job *job =
        aws_mem_calloc(request->allocator, 1, sizeof(struct s3_jbof_prepare_job));
    job->allocator   = request->allocator;
    job->request     = request;
    job->on_complete = aws_future_void_acquire(future);
    job->jbof        = jbof;

    pthread_t tid;
    if (pthread_create(&tid, NULL, s_jbof_worker_thread, job) != 0) {
        AWS_LOGF_ERROR(
            AWS_LS_S3_META_REQUEST,
            "id=%p JBOF meta request: pthread_create failed",
            (void *)meta_request);
        aws_future_void_set_error(future, AWS_ERROR_SYS_CALL_FAILURE);
        aws_future_void_release(job->on_complete);
        aws_mem_release(job->allocator, job);
    } else {
        pthread_detach(tid);
    }

    return future;
}

/* ── finished_request ────────────────────────────────────────────────── */

/* D2 whitelist: only these error codes indicate that the RDMA/JBOF data
 * path itself is unavailable (transport/connection/thread-setup failure),
 * meaning a caller-visible "fall back to plain HTTP" signal is appropriate.
 * Deliberately excludes data-integrity errors (CRC mismatch), argument
 * errors, and OOM -- those indicate a real defect or a real failed
 * operation and must be reported as themselves, never masked as
 * "unimplemented" (which could trigger a fallback that hides the bug). */
static bool s_is_rdma_fallback_worthy_error(int error_code) {
    switch (error_code) {
        case AWS_IO_SOCKET_NOT_CONNECTED:
        case AWS_ERROR_HTTP_CONNECTION_CLOSED:
        case AWS_ERROR_THREAD_INVALID_SETTINGS:
            return true;
        default:
            return false;
    }
}

static void s_jbof_finished_request(
    struct aws_s3_meta_request *meta_request,
    struct aws_s3_request *request,
    int error_code) {

    AWS_PRECONDITION(meta_request);
    struct aws_s3_meta_request_jbof *jbof = meta_request->impl;
    (void)request;

    /* JBOF helper result is authoritative -- but only if it actually ran.
     * completion_error_code's zero-initialized default is numerically equal
     * to AWS_ERROR_SUCCESS, indistinguishable from a real success, so guard
     * on op_has_run: if the worker thread never got to run (e.g.
     * prepare_request's pthread_create failed), use the framework's
     * error_code directly instead of misreporting success.
     *
     * When the op did run: the probe HTTP request may fail (e.g. socket
     * closed by mock server) even when the JBOF operation succeeded --
     * treat that as success. Only if the JBOF helper itself succeeded but
     * the framework signaled an infrastructure failure do we keep the HTTP
     * error. */
    int final_code;
    if (!jbof->op_has_run) {
        AWS_LOGF_DEBUG(
            AWS_LS_S3_META_REQUEST,
            "id=%p JBOF op never ran (prepare_request infra failure); using framework error %d",
            (void *)meta_request, error_code);
        final_code = (error_code != AWS_ERROR_SUCCESS) ? error_code : AWS_ERROR_UNKNOWN;
    } else {
        final_code = jbof->completion_error_code;
    }

    /* D2: if disable_rdma_on_retry is set and the JBOF op hit a genuinely
     * fallback-worthy error, remap it to AWS_ERROR_UNIMPLEMENTED so the
     * caller falls back to the plain HTTP path instead of retrying RDMA.
     * Gated on op_has_run: this signal is about the RDMA data path itself,
     * not generic framework infra failures. */
    if (jbof->op_has_run && final_code != AWS_ERROR_SUCCESS &&
        jbof->disable_rdma_on_retry && s_is_rdma_fallback_worthy_error(final_code)) {
        fprintf(stderr, "[s3_jbof] RDMA failed, falling back to HTTP\n");
        jbof->completion_error_code = AWS_ERROR_UNIMPLEMENTED;
        final_code                  = AWS_ERROR_UNIMPLEMENTED;
    }

    if (final_code == AWS_ERROR_SUCCESS && error_code != AWS_ERROR_SUCCESS) {
        AWS_LOGF_DEBUG(
            AWS_LS_S3_META_REQUEST,
            "id=%p JBOF probe HTTP error %d (ignored; JBOF op succeeded)",
            (void *)meta_request, error_code);
    } else if (final_code != AWS_ERROR_SUCCESS && error_code == AWS_ERROR_SUCCESS) {
        /* JBOF failed: keep jbof error. */
    } else if (final_code != AWS_ERROR_SUCCESS && error_code != AWS_ERROR_SUCCESS) {
        /* Both failed: JBOF error is more specific. */
    }

    aws_s3_meta_request_lock_synced_data(meta_request);
    jbof->synced_data.request_completed      = true;
    jbof->synced_data.cached_response_status = (final_code == AWS_ERROR_SUCCESS) ? 200 : 500;

    if (final_code != AWS_ERROR_SUCCESS) {
        aws_s3_meta_request_set_fail_synced(meta_request, request, final_code);
    } else {
        aws_s3_meta_request_set_success_synced(meta_request, 200);
    }
    aws_s3_request_finish_up_metrics_synced(request, meta_request);
    aws_s3_meta_request_unlock_synced_data(meta_request);
}

#endif /* AWS_ENABLE_JBOF */
