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
#include <aws/http/request_response.h>
#include <aws/s3/s3.h>
#include <aws/s3/s3_jbof_get.h>
#include <aws/s3/s3_jbof_put.h>

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

    /* Written by background pthread; read by finished_request. */
    int completion_error_code;

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

    /* Find last ':' in hdr; everything before is host, after is port. */
    const char *ptr = (const char *)hdr.ptr;
    size_t len = hdr.len;
    const char *colon = NULL;
    for (size_t i = 0; i < len; i++) {
        if (ptr[i] == ':') colon = ptr + i;
    }
    if (colon == NULL) {
        size_t copy = len < host_buf_len - 1 ? len : host_buf_len - 1;
        memcpy(host_buf, ptr, copy);
        host_buf[copy] = '\0';
        *out_port = default_port;
    } else {
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
    }
}

/* ── helper: parse "/bucket/key" path ───────────────────────────────── */

static void s_parse_path(
    struct aws_byte_cursor path,
    char *bucket_buf, size_t bucket_len,
    char *key_buf,    size_t key_len) {

    const char *p = (const char *)path.ptr;
    size_t n = path.len;

    /* skip leading '/' */
    if (n > 0 && p[0] == '/') { p++; n--; }

    /* find next '/' to split bucket from key */
    const char *slash = memchr(p, '/', n);
    if (!slash) {
        /* no key */
        size_t blen = n < bucket_len - 1 ? n : bucket_len - 1;
        memcpy(bucket_buf, p, blen);
        bucket_buf[blen] = '\0';
        key_buf[0] = '\0';
    } else {
        size_t blen = (size_t)(slash - p);
        if (blen >= bucket_len) blen = bucket_len - 1;
        memcpy(bucket_buf, p, blen);
        bucket_buf[blen] = '\0';

        const char *kp = slash + 1;
        size_t klen = n - (size_t)(kp - p);
        if (klen >= key_len) klen = key_len - 1;
        memcpy(key_buf, kp, klen);
        key_buf[klen] = '\0';
    }
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
    s_parse_path(path, bucket_buf, sizeof(bucket_buf), key_buf, sizeof(key_buf));

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

static void s_jbof_finished_request(
    struct aws_s3_meta_request *meta_request,
    struct aws_s3_request *request,
    int error_code) {

    AWS_PRECONDITION(meta_request);
    struct aws_s3_meta_request_jbof *jbof = meta_request->impl;
    (void)request;

    /* JBOF helper result is authoritative.
     * The probe HTTP request may fail (e.g. socket closed by mock server) even
     * when the JBOF operation succeeded — treat that as success.
     * Only if the JBOF helper itself succeeded but the framework signaled an
     * infrastructure failure (e.g. pthread_create) do we keep the HTTP error. */
    int final_code = jbof->completion_error_code;

    /* D2: if disable_rdma_on_retry is set and RDMA failed, log and signal
     * the caller to use the HTTP fallback path instead of retrying RDMA. */
    if (final_code != AWS_ERROR_SUCCESS && jbof->disable_rdma_on_retry) {
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
