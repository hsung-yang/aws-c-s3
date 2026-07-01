/*
 * s3_jbof_put_crc_cuda.c — single-shot GPU CRC32C for the PUT commit phase.
 *
 * Replaces the helper's single-threaded CPU CRC32C loop (0.22 GB/s on
 * Spark) with one nvcomp batched call over the whole source buffer.
 *
 * Compiled only when AWS_ENABLE_JBOF is on (production build).
 */

#ifdef AWS_ENABLE_JBOF

#include <cuda_runtime.h>
#include <nvcomp/crc32.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Compute full-object CRC32C of [src, src+len). src must be CUDA-reachable
 * (cudaMallocManaged or device alloc — verified by cudaPointerGetAttributes).
 * Returns 0 on failure (caller falls back to CPU). */
uint32_t jbof_put_full_crc_cuda(const void *src, size_t len) {
    if (!src || len == 0) return 0;

    /* Verify the pointer is reachable from the GPU. cudaMemoryTypeUnregistered
     * means plain host malloc — bail out and let the caller fall back. */
    struct cudaPointerAttributes attrs;
    if (cudaPointerGetAttributes(&attrs, src) != cudaSuccess) return 0;
    if (attrs.type == cudaMemoryTypeUnregistered) return 0;

    cudaStream_t stream;
    if (cudaStreamCreate(&stream) != cudaSuccess) return 0;

    /* Single "extent" — one device pointer, one size. */
    const void **d_ptrs = NULL;
    size_t      *d_sizes = NULL;
    uint32_t    *d_crcs = NULL;
    if (cudaMalloc((void **)&d_ptrs,  sizeof(void *))    != cudaSuccess ||
        cudaMalloc((void **)&d_sizes, sizeof(size_t))    != cudaSuccess ||
        cudaMalloc((void **)&d_crcs,  sizeof(uint32_t))  != cudaSuccess) {
        if (d_ptrs)  cudaFree(d_ptrs);
        if (d_sizes) cudaFree(d_sizes);
        if (d_crcs)  cudaFree(d_crcs);
        cudaStreamDestroy(stream);
        return 0;
    }

    const void *h_ptrs[1]  = { src };
    size_t      h_sizes[1] = { len };
    if (cudaMemcpy(d_ptrs,  h_ptrs,  sizeof(void *), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(d_sizes, h_sizes, sizeof(size_t), cudaMemcpyHostToDevice) != cudaSuccess) {
        cudaFree(d_ptrs); cudaFree(d_sizes); cudaFree(d_crcs);
        cudaStreamDestroy(stream);
        return 0;
    }

    nvcompBatchedCRC32Opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.spec = nvcompCRC32_C;
    if (nvcompBatchedCRC32GetHeuristicConf(
            nvcompCRC32IgnoredInputChunkBytes, 1,
            &opts.kernel_conf, len, stream) != nvcompSuccess) {
        cudaFree(d_ptrs); cudaFree(d_sizes); cudaFree(d_crcs);
        cudaStreamDestroy(stream);
        return 0;
    }
    if (nvcompBatchedCRC32Async(
            (const void *const *)d_ptrs, d_sizes, 1, d_crcs,
            opts, nvcompCRC32OnlySegment, NULL, stream) != nvcompSuccess) {
        cudaFree(d_ptrs); cudaFree(d_sizes); cudaFree(d_crcs);
        cudaStreamDestroy(stream);
        return 0;
    }
    if (cudaStreamSynchronize(stream) != cudaSuccess) {
        cudaFree(d_ptrs); cudaFree(d_sizes); cudaFree(d_crcs);
        cudaStreamDestroy(stream);
        return 0;
    }

    uint32_t result = 0;
    if (cudaMemcpy(&result, d_crcs, sizeof(uint32_t),
                   cudaMemcpyDeviceToHost) != cudaSuccess) {
        result = 0;
    }
    cudaFree(d_ptrs); cudaFree(d_sizes); cudaFree(d_crcs);
    cudaStreamDestroy(stream);
    return result;
}

#endif /* AWS_ENABLE_JBOF */
