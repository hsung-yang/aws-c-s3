#ifndef AWS_S3_JBOF_GET_H
#define AWS_S3_JBOF_GET_H

/*
 * JBOF-direct GetObject helper.
 *
 * Bypasses S3 for objects whose layout is served by a metadata server. The
 * helper:
 *   1. HTTP/1.0 GETs /<bucket>/<key> from the metadata server
 *   2. parses the s3rdma.layout.v1 JSON response into an extent array
 *   3. drives libobject_rdma (rp_plan_build + rp_execute) to fill the
 *      caller-supplied GPU buffer and verify CRC32C
 *
 * Only available when aws-c-s3 was configured with -DAWS_ENABLE_JBOF=ON.
 */

#include <aws/common/byte_buf.h>
#include <aws/s3/exports.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct aws_allocator;
struct aws_s3_jbof_client;

/* Target → device mapping. The helper opens the device once per unique
 * (subnqn, nsid) pair encountered in the layout. */
struct aws_s3_jbof_target_device {
    struct aws_byte_cursor subnqn;
    uint32_t               nsid;
    struct aws_byte_cursor device_path;   /* e.g. "/dev/nvme1n1" */
};

/* SPDK bypass target — one per RDMA leg. When spdk_targets is non-NULL in
 * aws_s3_jbof_get_options, the helper uses SPDK userspace NVMe-oF instead
 * of kernel pread. Requires -DWITH_SPDK_BYPASS=ON at build time. */
struct aws_s3_jbof_spdk_target {
    struct aws_byte_cursor traddr;    /* e.g. "172.52.8.30" */
    uint16_t               trsvcid;   /* e.g. 4420 */
    struct aws_byte_cursor subnqn;    /* e.g. "nqn.2024-01.io.example:jbof-ns0" */
    struct aws_byte_cursor hostaddr;  /* source IP for 2nd leg, empty for 1st */
};

struct aws_s3_jbof_client_options {
    /* Metadata server endpoint (used by every GET on this client). */
    struct aws_byte_cursor meta_server_host;
    uint16_t               meta_server_port;
    /* Layout cache size (default 1024 if 0). Entries are evicted LRU once
     * the table is full or when their lease expires. */
    size_t                 max_cache_entries;

    /* SigV4 credentials. When access_key / secret_key are non-empty, the
     * client signs every outbound HTTP request (Authorization +
     * X-Amz-Date + X-Amz-Content-SHA256). All-empty → unsigned (works
     * against the permissive mock server). session_token is optional. */
    struct aws_byte_cursor access_key;
    struct aws_byte_cursor secret_key;
    struct aws_byte_cursor session_token;
    struct aws_byte_cursor region;      /* default "us-east-1" if empty */
    struct aws_byte_cursor service;     /* default "s3" if empty */

    /* When non-zero, pool fds opened with O_DIRECT (page cache bypass). */
    int                    use_o_direct;

    /* SPDK bypass targets. When non-NULL, the client initializes the SPDK
     * environment and creates a session at client_new time, so the first
     * GET does not pay env_init + connect + qpair + bounce costs.
     * Requires -DWITH_SPDK_BYPASS=ON at build time; ignored otherwise. */
    const struct aws_s3_jbof_spdk_target *spdk_targets;
    size_t                                  spdk_target_count;
};

struct aws_s3_jbof_get_options {
    /* metadata server: e.g. {"127.0.0.1", 8080} */
    struct aws_byte_cursor meta_server_host;
    uint16_t               meta_server_port;

    /* object identity */
    struct aws_byte_cursor bucket;
    struct aws_byte_cursor key;

    /* destination: caller-allocated, large enough for object_size */
    void                  *gpu_buffer;
    size_t                 gpu_buffer_capacity;

    /* Target → device map. The helper resolves each extent's
     * (subnqn, nsid) against this array; missing entries cause an
     * AWS_ERROR_INVALID_ARGUMENT. */
    const struct aws_s3_jbof_target_device *target_devices;
    size_t                                  target_device_count;

    /* Worker threads per (subnqn, nsid) group. 0 → 1 worker per target
     * (current default). N → N parallel preads against the same target,
     * matching the saturation harness "N procs per ns" pattern. */
    int                                     workers_per_target;

    /* Maximum bytes per pread. 0 = no splitting (one pread per extent).
     * Non-zero splits extents larger than this into multiple sub-I/Os,
     * increasing NVMe-oF pipeline depth. Per-I/O CRC is skipped for
     * sub-I/Os; end-to-end integrity is verified by the full-object CRC.
     * Typical value: 131072 (128 KiB) — matches the 2026-07-10 saturation
     * baseline. */
    size_t                                  io_size;

    /* When 0, the planner skips CRC verification entirely (returns
     * crc_ok = 1 unconditionally). Used by saturation measurements
     * where the on-disk data is pre-existing and the bytes-per-second
     * is the only metric of interest. */
    int                                     verify_crc;

    /* When non-zero AND verify_crc is set, return as soon as the CRC
     * kernel is submitted and ready_event is recorded. The caller is
     * responsible for waiting on result.ready_event (or via
     * cudaStreamWaitEvent on an app stream) and then calling
     * aws_s3_jbof_get_finish_crc() to populate crc_ok. Matches the
     * HLD §8.0 contract. */
    int                                     async_crc;

    /* Byte range request. range_length == 0 means "full object". The
     * helper sends a Range: bytes=N-M header so the metadata server can
     * emit a partial layout if it supports it; client-side the planner
     * also clips extents to the requested range. */
    uint64_t                                req_range_offset;
    uint64_t                                req_range_length;

    /* When non-zero, open backing devices with O_DIRECT so the kernel
     * page cache is bypassed. Required for honest saturation measurement
     * (otherwise iter-2+ becomes a memcpy from RAM, not RDMA). The
     * caller's gpu_buffer must be sector-aligned (cudaMallocManaged
     * gives 4 KiB which satisfies typical 512/4096-byte sector
     * requirements). */
    int                                     use_o_direct;

    /* A6: When non-zero, pread targets a CPU-side scratch buffer that is
     * then copied to gpu_buffer via memcpy (or cudaMemcpy on a CUDA build).
     * Required on soft-RoCE hosts where ibv_reg_mr cannot register CUDA
     * memory. Set automatically if SHFT_BOUNCE=1 env var is detected. */
    int                                     use_bounce_buffer;

    const struct aws_s3_jbof_spdk_target   *spdk_targets;
    size_t                                  spdk_target_count;

    /* SigV4 credentials for this single call (only consulted by the
     * standalone aws_s3_jbof_get_object; the cached client carries its
     * own credentials in aws_s3_jbof_client_options). */
    struct aws_byte_cursor                  access_key;
    struct aws_byte_cursor                  secret_key;
    struct aws_byte_cursor                  session_token;
    struct aws_byte_cursor                  region;
    struct aws_byte_cursor                  service;
};

struct aws_s3_jbof_get_result {
    size_t   object_bytes;     /* bytes the planner placed into gpu_buffer */
    int      crc_ok;           /* 1 if every extent's CRC matched */
    int      planner_rc;       /* rp_execute return code (RP_OK or RP_E_*) */
    double   elapsed_seconds;  /* wall clock from execute call */

    /* Layout fields lifted from the v1.2 layout JSON. Pointers owned by
     * the caller's allocator (passed to aws_s3_jbof_get_object) — release
     * with aws_s3_jbof_get_result_clean_up. */
    char    *etag;
    char    *version_id;
    uint64_t layout_epoch;
    uint64_t lease_expires_at_unix_ms;
    uint64_t range_offset;
    uint64_t range_length;
    uint32_t full_object_crc32c;       /* 0 if not present */
    int      full_object_crc_present;

    /* Opaque handle holding the gpu_buffer used by rp_finish_crc in async
     * mode. NULL when async_crc was off (crc_ok already valid). Caller MUST
     * call aws_s3_jbof_get_finish_crc() in async mode to populate crc_ok
     * and release planner-side state. */
    void    *_planner_buffer;
};

/* Finalize an async-mode GET: wait for the CRC kernel, copy back results,
 * fill in crc_ok. Returns AWS_OP_SUCCESS / AWS_OP_ERR (AWS_ERROR_S3_-
 * RESPONSE_CHECKSUM_MISMATCH on mismatch). Safe to call when async_crc
 * was off — becomes a no-op. */
AWS_S3_API
int aws_s3_jbof_get_finish_crc(struct aws_s3_jbof_get_result *result);

AWS_S3_API
void aws_s3_jbof_get_result_clean_up(struct aws_allocator *allocator,
                                     struct aws_s3_jbof_get_result *result);

/* Run the entire flow synchronously. Returns AWS_OP_SUCCESS / AWS_OP_ERR. */
AWS_S3_API
int aws_s3_jbof_get_object(struct aws_allocator *allocator,
                           const struct aws_s3_jbof_get_options *options,
                           struct aws_s3_jbof_get_result *out_result);

/* ── Client object (layout cache + fd pool) ─────────────────────────── */

AWS_S3_API
struct aws_s3_jbof_client *aws_s3_jbof_client_new(
    struct aws_allocator *allocator,
    const struct aws_s3_jbof_client_options *options);

AWS_S3_API
void aws_s3_jbof_client_destroy(struct aws_s3_jbof_client *client);

/* Returns the client's SPDK bypass session, or NULL if SPDK is not
 * configured.  The returned pointer is valid until client_destroy.
 * Pass it to aws_s3_jbof_put_options.spdk_session to enable SPDK
 * write bypass for PUT. */
AWS_S3_API
void *aws_s3_jbof_client_get_spdk_session(struct aws_s3_jbof_client *client);

/* Same as aws_s3_jbof_get_object but routes through the client's layout
 * cache and fd pool: a cache hit skips the HTTP round-trip; fds are
 * opened once per (subnqn, nsid, worker_index) and reused across calls.
 * Options' meta_server_host/port are ignored (client provides them). */
AWS_S3_API
int aws_s3_jbof_client_get_object(
    struct aws_s3_jbof_client *client,
    const struct aws_s3_jbof_get_options *options,
    struct aws_s3_jbof_get_result *out_result);

/* ── A4: callback-based async GET ──────────────────────────────────── */

/* A4: async completion callback. error_code = AWS_OP_SUCCESS or an AWS
 * error code. Called on a background thread after pread + CRC complete. */
typedef void (*aws_s3_jbof_get_completion_fn)(
    int error_code,
    struct aws_s3_jbof_get_result *result,
    void *user_data);

/* A4: Submit a GET asynchronously. Returns immediately. The completion
 * callback fires on a background thread after pread + CRC complete.
 * The caller must not free options or result until the callback fires.
 * Returns AWS_OP_SUCCESS if the background thread was launched, or
 * AWS_OP_ERR if thread creation failed (callback will NOT fire in that
 * case). */
AWS_S3_API
int aws_s3_jbof_client_get_object_async(
    struct aws_s3_jbof_client *client,
    const struct aws_s3_jbof_get_options *options,
    struct aws_s3_jbof_get_result *out_result,
    aws_s3_jbof_get_completion_fn on_complete,
    void *user_data);

/* ── Meta-request extra (A5: aws_s3_client_make_meta_request dispatch) ── */

/* Forward declaration; full definition is in s3_jbof_put.h. */
struct aws_s3_jbof_put_result;

/* Pass a pointer to this struct as aws_s3_meta_request_options.user_data
 * when using AWS_S3_META_REQUEST_TYPE_JBOF_GET or _JBOF_PUT.
 * The caller owns all referenced buffers for the lifetime of the meta-request.
 * On completion, result_out/put_result_out is populated before finish_callback
 * fires. Include s3_jbof_put.h to access put_result_out fields. */
struct aws_s3_jbof_meta_request_extra {
    /* GET destination / PUT source (CUDA-managed or host memory). */
    void                                   *gpu_buffer;
    size_t                                  gpu_buffer_capacity;

    const struct aws_s3_jbof_target_device *target_devices;
    size_t                                  target_device_count;
    int                                     workers_per_target;
    int                                     verify_crc;    /* default: 1 */
    int                                     use_o_direct;

    /* SigV4 credentials (all-empty → unsigned). */
    struct aws_byte_cursor                  access_key;
    struct aws_byte_cursor                  secret_key;
    struct aws_byte_cursor                  session_token;
    struct aws_byte_cursor                  region;
    struct aws_byte_cursor                  service;

    /* GET result populated before finish_callback fires. */
    struct aws_s3_jbof_get_result           result_out;
    /* PUT result; only populated when type == JBOF_PUT. */
    struct aws_s3_jbof_put_result          *put_result_ptr; /* caller-alloc */

    /* D2: When set, the meta-request falls back to HTTP on RDMA failure
     * rather than retrying RDMA. Default 0 = RDMA errors are surfaced
     * to the caller. */
    int disable_rdma_on_retry;
};

#ifdef __cplusplus
}
#endif

#endif /* AWS_S3_JBOF_GET_H */
