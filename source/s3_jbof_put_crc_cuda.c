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

/* Compute full-object CRC32C of [src, src+len).
 *
 * Return value is deliberately NOT the CRC itself -- a genuine CRC32C
 * result can be 0, so overloading 0 as "failure" (the previous contract)
 * silently corrupted the commit checksum whenever the real CRC happened
 * to be 0. Success/failure and the CRC value are now fully separate:
 *
 *   0  = success; *out_crc holds the CRC32C.
 *  -1  = src is NOT GPU-reachable (cudaPointerGetAttributes reports
 *        cudaMemoryTypeUnregistered, i.e. plain host malloc()'d memory).
 *        This is an expected, non-fatal outcome: such a pointer IS safely
 *        host-dereferenceable, so the caller may fall back to a CPU
 *        CRC32C loop over the same bytes.
 *  -2  = a real CUDA/nvcomp call failed (cudaStreamCreate, cudaMalloc,
 *        cudaMemcpy, nvcomp calls, or cudaStreamSynchronize) while operating on
 *        memory we had already confirmed IS GPU-reachable (device,
 *        managed, or pinned host memory reported by
 *        cudaPointerGetAttributes). In this case src may be device-only
 *        memory (e.g. plain cudaMalloc, not cudaMallocManaged/pinned)
 *        that the CPU cannot dereference at all -- the caller MUST NOT
 *        attempt a CPU fallback on a -2 return; it must surface an error
 *        instead of risking a host dereference of device memory.
 */
int jbof_put_full_crc_cuda(const void *src, size_t len, uint32_t *out_crc) {
    if (!src || !out_crc || len == 0) return -2;

    /* Verify the pointer is reachable from the GPU. cudaMemoryTypeUnregistered
     * means plain host malloc — bail out and let the caller fall back to a
     * CPU CRC (safe: the memory IS host-dereferenceable in this case). */
    struct cudaPointerAttributes attrs;
    if (cudaPointerGetAttributes(&attrs, src) != cudaSuccess) return -2;
    if (attrs.type == cudaMemoryTypeUnregistered) return -1;

    cudaStream_t stream;
    if (cudaStreamCreate(&stream) != cudaSuccess) return -2;

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
        return -2;
    }

    const void *h_ptrs[1]  = { src };
    size_t      h_sizes[1] = { len };
    if (cudaMemcpy(d_ptrs,  h_ptrs,  sizeof(void *), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(d_sizes, h_sizes, sizeof(size_t), cudaMemcpyHostToDevice) != cudaSuccess) {
        cudaFree(d_ptrs); cudaFree(d_sizes); cudaFree(d_crcs);
        cudaStreamDestroy(stream);
        return -2;
    }

    nvcompBatchedCRC32Opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.spec = nvcompCRC32_C;
    if (nvcompBatchedCRC32GetHeuristicConf(
            nvcompCRC32IgnoredInputChunkBytes, 1,
            &opts.kernel_conf, len, stream) != nvcompSuccess) {
        cudaFree(d_ptrs); cudaFree(d_sizes); cudaFree(d_crcs);
        cudaStreamDestroy(stream);
        return -2;
    }
    if (nvcompBatchedCRC32Async(
            (const void *const *)d_ptrs, d_sizes, 1, d_crcs,
            opts, nvcompCRC32OnlySegment, NULL, stream) != nvcompSuccess) {
        cudaFree(d_ptrs); cudaFree(d_sizes); cudaFree(d_crcs);
        cudaStreamDestroy(stream);
        return -2;
    }
    if (cudaStreamSynchronize(stream) != cudaSuccess) {
        cudaFree(d_ptrs); cudaFree(d_sizes); cudaFree(d_crcs);
        cudaStreamDestroy(stream);
        return -2;
    }

    uint32_t result = 0;
    if (cudaMemcpy(&result, d_crcs, sizeof(uint32_t),
                   cudaMemcpyDeviceToHost) != cudaSuccess) {
        cudaFree(d_ptrs); cudaFree(d_sizes); cudaFree(d_crcs);
        cudaStreamDestroy(stream);
        return -2;
    }
    cudaFree(d_ptrs); cudaFree(d_sizes); cudaFree(d_crcs);
    cudaStreamDestroy(stream);
    *out_crc = result;
    return 0;
}

#endif /* AWS_ENABLE_JBOF */
