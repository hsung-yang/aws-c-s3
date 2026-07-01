#ifndef AWS_S3_JBOF_MPU_H
#define AWS_S3_JBOF_MPU_H
/*
 * s3_jbof_mpu.h — JBOF multipart upload (MPU) API (Task B4).
 *
 * Objects above a threshold are split into N parts, each uploaded
 * via the 3-phase RDMA flow (placement → pwrite → commit).  The
 * CreateMultipartUpload and CompleteMultipartUpload calls use plain
 * S3 HTTP (no RDMA).
 *
 * Usage:
 *   1. aws_s3_jbof_mpu_create()
 *   2. aws_s3_jbof_mpu_upload_part() × N  (can be called serially)
 *   3. aws_s3_jbof_mpu_complete()
 *   or aws_s3_jbof_mpu_abort() on failure
 */

#include <aws/s3/s3_jbof_get.h>   /* aws_s3_jbof_target_device */
#include <aws/s3/s3_jbof_put.h>   /* aws_s3_jbof_put_options, aws_s3_jbof_put_result */
#include <aws/s3/exports.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define JBOF_MPU_DEFAULT_PART_SIZE (8 * 1024 * 1024)   /* 8 MiB */
#define JBOF_MPU_MAX_PARTS 10000

struct aws_s3_jbof_mpu;

struct aws_s3_jbof_mpu_options {
    struct aws_byte_cursor meta_server_host;
    uint16_t               meta_server_port;
    struct aws_byte_cursor bucket;
    struct aws_byte_cursor key;
    size_t                 part_size;          /* 0 → JBOF_MPU_DEFAULT_PART_SIZE */
    const struct aws_s3_jbof_target_device *target_devices;
    size_t                                  target_device_count;
    int                                     workers_per_target;
    int                                     verify_crc;   /* default 1 */
    struct aws_byte_cursor access_key;
    struct aws_byte_cursor secret_key;
    struct aws_byte_cursor session_token;
    struct aws_byte_cursor region;
    struct aws_byte_cursor service;
};

struct aws_s3_jbof_mpu_part_result {
    int    part_number;
    char   etag[128];
};

struct aws_s3_jbof_mpu_result {
    char   *etag;           /* final ETag from CompleteMultipartUpload */
    size_t  bytes_written;
    double  elapsed_seconds;
};

/* Create a multipart upload session. Sends CreateMultipartUpload to the
 * metadata server and returns an opaque handle.
 * Returns NULL and sets aws_last_error on failure. */
AWS_S3_API
struct aws_s3_jbof_mpu *aws_s3_jbof_mpu_create(
    struct aws_allocator *allocator,
    const struct aws_s3_jbof_mpu_options *options);

/* Upload one part. part_number is 1-based. source_buffer + source_length
 * describe the part's data in CPU or GPU memory.
 * Fills part_result on success.
 * Returns AWS_OP_SUCCESS / AWS_OP_ERR. */
AWS_S3_API
int aws_s3_jbof_mpu_upload_part(
    struct aws_s3_jbof_mpu *mpu,
    int                    part_number,
    const void            *source_buffer,
    size_t                 source_length,
    struct aws_s3_jbof_mpu_part_result *part_result);

/* Finalize the upload. Sends CompleteMultipartUpload.
 * part_results is an array of part_count entries in part_number order.
 * Returns AWS_OP_SUCCESS / AWS_OP_ERR. */
AWS_S3_API
int aws_s3_jbof_mpu_complete(
    struct aws_s3_jbof_mpu *mpu,
    const struct aws_s3_jbof_mpu_part_result *part_results,
    size_t part_count,
    struct aws_s3_jbof_mpu_result *out_result);

/* Abort a multipart upload. Sends DeleteMultipartUpload / rdma-commit-abort.
 * Always destroys the mpu handle (do not call aws_s3_jbof_mpu_destroy after abort). */
AWS_S3_API
void aws_s3_jbof_mpu_abort(struct aws_s3_jbof_mpu *mpu);

/* Destroy the handle without aborting (call only after complete or on early
 * failure before any parts are uploaded). */
AWS_S3_API
void aws_s3_jbof_mpu_destroy(struct aws_s3_jbof_mpu *mpu);

#ifdef __cplusplus
}
#endif

#endif /* AWS_S3_JBOF_MPU_H */
