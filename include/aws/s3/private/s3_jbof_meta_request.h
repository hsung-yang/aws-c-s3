#ifndef AWS_S3_JBOF_META_REQUEST_H
#define AWS_S3_JBOF_META_REQUEST_H

/**
 * Private header for the JBOF meta-request subclass.
 * Only s3_jbof_meta_request.c and s3_client.c (dispatch) should include this.
 */

#include "aws/s3/private/s3_meta_request_impl.h"
#include <aws/s3/s3_client.h>

struct aws_s3_meta_request;
struct aws_s3_client;
struct aws_s3_meta_request_options;

/**
 * Create a new JBOF meta-request subclass.
 * is_put == 0 → GET path (aws_s3_jbof_client_get_object)
 * is_put == 1 → PUT path (aws_s3_jbof_put_object)
 * options->user_data must point to a struct aws_s3_jbof_meta_request_extra.
 */
AWS_S3_API
struct aws_s3_meta_request *aws_s3_meta_request_jbof_new(
    struct aws_allocator *allocator,
    struct aws_s3_client *client,
    int is_put,
    const struct aws_s3_meta_request_options *options);

#endif /* AWS_S3_JBOF_META_REQUEST_H */
