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

/* Persistent CUDA resources — allocated once on first call, reused on
 * every subsequent call. Eliminates ~2-3 ms of per-call overhead from
 * cudaStreamCreate/Destroy + 3× cudaMalloc/cudaFree for tiny 8-byte
 * buffers.
 *
 * Thread-safety: jbof_put_full_crc_cuda() is called from a single pthread
 * per PUT (jbof_put_crc_thread_fn in s3_jbof_put.c), and PUTs are
 * serialized in the test harness. No concurrent access. */
static cudaStream_t  s_stream        = NULL;
static const void  **s_d_ptrs        = NULL;
static size_t       *s_d_sizes       = NULL;
static uint32_t     *s_d_crcs        = NULL;
static int           s_pageable_init = 0;  /* 0 = unchecked, 1 = checked */
static int           s_pageable_access = 0;

static int ensure_crc_resources(void) {
    if (!s_stream) {
        if (cudaStreamCreate(&s_stream) != cudaSuccess) return -1;
    }
    if (!s_d_ptrs) {
        if (cudaMalloc((void **)&s_d_ptrs, sizeof(void *)) != cudaSuccess) return -1;
    }
    if (!s_d_sizes) {
        if (cudaMalloc((void **)&s_d_sizes, sizeof(size_t)) != cudaSuccess) return -1;
    }
    if (!s_d_crcs) {
        if (cudaMalloc((void **)&s_d_crcs, sizeof(uint32_t)) != cudaSuccess) return -1;
    }
    return 0;
}

void jbof_put_crc_cuda_init(void) {
    cudaSetDevice(0);
    ensure_crc_resources();
    int dev = 0;
    cudaDeviceGetAttribute(&s_pageable_access,
        cudaDevAttrPageableMemoryAccess, dev);
    s_pageable_init = 1;
}

/* Compute full-object CRC32C of [src, src+len).
 *
 * Return value is deliberately NOT the CRC itself -- a genuine CRC32C
 * result can be 0, so overloading 0 as "failure" (the previous contract)
 * silently corrupted the commit checksum whenever the real CRC happened
 * to be 0. Success/failure and the CRC value are now fully separate:
 *
 *   0  = success; *out_crc holds the CRC32C.
 *  -1  = src is plain host memory AND the GPU path failed. The caller
 *        may safely fall back to a CPU CRC32C loop because the memory
 *        IS host-dereferenceable.
 *  -2  = a real CUDA/nvcomp call failed while operating on memory we had
 *        already confirmed IS GPU-reachable (device, managed, or pinned
 *        host memory). In this case src may be device-only memory that
 *        the CPU cannot dereference at all -- the caller MUST NOT attempt
 *        a CPU fallback on a -2 return; it must surface an error instead.
 *
 * Host-memory handling (cudaMemoryTypeUnregistered) — three paths,
 * tried fastest-first:
 *
 *   1. Direct access (Grace+Blackwell): The GPU reads host memory via
 *      the NVLink C2C coherent interconnect without any registration.
 *      Detected via cudaDevAttrPageableMemoryAccess (cached after first
 *      call). Zero per-call overhead — no pin, no copy, no unpin. The
 *      nvcomp kernel fetches data directly from host RAM at ~24 GB/s.
 *
 *   2. cudaHostRegister (other unified-memory archs): Pin the pages so
 *      the GPU gets a stable physical mapping, then
 *      cudaHostGetDevicePointer. Adds ~20 ms pin/unpin overhead for
 *      512 MB but avoids a full H2D copy.
 *
 *   3. H2D copy (discrete GPUs): cudaMalloc + cudaMemcpyAsync. The GPU
 *      DMA engine copies src to a device buffer, then nvcomp runs on
 *      the copy. When overlapped with the SPDK write (caller-side
 *      pthread), the H2D copy runs in parallel with CPU memcpy + NIC.
 */
int jbof_put_full_crc_cuda(const void *src, size_t len, uint32_t *out_crc) {
    if (!src || !out_crc || len == 0) return -2;

    if (ensure_crc_resources() != 0) return -2;

    struct cudaPointerAttributes attrs;
    if (cudaPointerGetAttributes(&attrs, src) != cudaSuccess) return -2;

    void *d_buf = NULL;
    const void *crc_src = src;
    int host_registered = 0;

    if (attrs.type == cudaMemoryTypeUnregistered) {
        /* Path 1: direct access (Grace+Blackwell NVLink C2C).
         * Device capability cached after first check. */
        if (!s_pageable_init) {
            cudaDeviceGetAttribute(&s_pageable_access,
                cudaDevAttrPageableMemoryAccess, attrs.device);
            s_pageable_init = 1;
        }

        if (s_pageable_access) {
            /* crc_src stays as src — GPU reads it directly. */
        } else {
            /* Path 2: cudaHostRegister + cudaHostGetDevicePointer. */
            if (cudaHostRegister((void *)src, len,
                                 cudaHostRegisterDefault) == cudaSuccess) {
                void *d_ptr = NULL;
                if (cudaHostGetDevicePointer(&d_ptr, (void *)src, 0) == cudaSuccess) {
                    crc_src = d_ptr;
                    host_registered = 1;
                } else {
                    cudaHostUnregister((void *)src);
                }
            }

            if (!host_registered) {
                /* Path 3: H2D copy fallback. */
                if (cudaMalloc(&d_buf, len) != cudaSuccess) return -1;
                crc_src = d_buf;
            }
        }
    }

    if (d_buf) {
        if (cudaMemcpyAsync(d_buf, src, len,
                            cudaMemcpyHostToDevice, s_stream) != cudaSuccess) {
            cudaFree(d_buf);
            if (host_registered) cudaHostUnregister((void *)src);
            return -1;
        }
    }

    const void *h_ptrs[1]  = { crc_src };
    size_t      h_sizes[1] = { len };
    if (cudaMemcpyAsync(s_d_ptrs,  h_ptrs,  sizeof(void *),
                        cudaMemcpyHostToDevice, s_stream) != cudaSuccess ||
        cudaMemcpyAsync(s_d_sizes, h_sizes, sizeof(size_t),
                        cudaMemcpyHostToDevice, s_stream) != cudaSuccess) {
        if (d_buf) cudaFree(d_buf);
        if (host_registered) cudaHostUnregister((void *)src);
        return (d_buf || host_registered) ? -1 : -2;
    }

    nvcompBatchedCRC32Opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.spec = nvcompCRC32_C;
    if (nvcompBatchedCRC32GetHeuristicConf(
            nvcompCRC32IgnoredInputChunkBytes, 1,
            &opts.kernel_conf, len, s_stream) != nvcompSuccess) {
        if (d_buf) cudaFree(d_buf);
        if (host_registered) cudaHostUnregister((void *)src);
        return (d_buf || host_registered) ? -1 : -2;
    }
    if (nvcompBatchedCRC32Async(
            (const void *const *)s_d_ptrs, s_d_sizes, 1, s_d_crcs,
            opts, nvcompCRC32OnlySegment, NULL, s_stream) != nvcompSuccess) {
        if (d_buf) cudaFree(d_buf);
        if (host_registered) cudaHostUnregister((void *)src);
        return (d_buf || host_registered) ? -1 : -2;
    }
    if (cudaStreamSynchronize(s_stream) != cudaSuccess) {
        if (d_buf) cudaFree(d_buf);
        if (host_registered) cudaHostUnregister((void *)src);
        return (d_buf || host_registered) ? -1 : -2;
    }

    uint32_t result = 0;
    if (cudaMemcpy(&result, s_d_crcs, sizeof(uint32_t),
                   cudaMemcpyDeviceToHost) != cudaSuccess) {
        if (d_buf) cudaFree(d_buf);
        if (host_registered) cudaHostUnregister((void *)src);
        return (d_buf || host_registered) ? -1 : -2;
    }
    if (d_buf) cudaFree(d_buf);
    if (host_registered) cudaHostUnregister((void *)src);
    *out_crc = result;
    return 0;
}

#endif /* AWS_ENABLE_JBOF */
