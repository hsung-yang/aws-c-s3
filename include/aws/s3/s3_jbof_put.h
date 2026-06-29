#ifndef AWS_S3_JBOF_PUT_H
#define AWS_S3_JBOF_PUT_H

/*
 * JBOF-direct PutObject helper.
 *
 * Three-phase disaggregated PUT per RDMA_PROTOCOL_SPEC.md §3:
 *   1. POST-like request → placement JSON (target/lba allocation)
 *   2. NVMe-oF pwrite() directly to each placement extent
 *   3. Commit request → server records object → JBOF mapping, returns ETag
 *
 * Only available when aws-c-s3 was configured with -DAWS_ENABLE_JBOF=ON.
 */

#include <aws/common/byte_buf.h>
#include <aws/s3/exports.h>
#include <aws/s3/s3_jbof_get.h>   /* shares aws_s3_jbof_target_device */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct aws_allocator;

struct aws_s3_jbof_put_options {
    struct aws_byte_cursor meta_server_host;
    uint16_t               meta_server_port;
    struct aws_byte_cursor bucket;
    struct aws_byte_cursor key;

    /* Source bytes. Must be CUDA-reachable in the GPU build (currently
     * the helper does not call any CUDA APIs on it — CRC is host-side). */
    const void            *source_buffer;
    size_t                 source_length;

    /* Target → device map (same as GET options). */
    const struct aws_s3_jbof_target_device *target_devices;
    size_t                                  target_device_count;

    int                                     workers_per_target;

    /* SigV4. All-empty → unsigned. */
    struct aws_byte_cursor access_key;
    struct aws_byte_cursor secret_key;
    struct aws_byte_cursor session_token;
    struct aws_byte_cursor region;
    struct aws_byte_cursor service;
};

struct aws_s3_jbof_put_result {
    char    *etag;
    size_t   bytes_written;
    double   elapsed_seconds;
    uint32_t full_object_crc32c;
};

AWS_S3_API
int aws_s3_jbof_put_object(struct aws_allocator *allocator,
                           const struct aws_s3_jbof_put_options *options,
                           struct aws_s3_jbof_put_result *out_result);

AWS_S3_API
void aws_s3_jbof_put_result_clean_up(struct aws_allocator *allocator,
                                     struct aws_s3_jbof_put_result *result);

#ifdef __cplusplus
}
#endif

#endif /* AWS_S3_JBOF_PUT_H */
