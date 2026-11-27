#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

typedef int CUresult;
typedef int CUdevice;
typedef struct CUctx_st *CUcontext;
typedef unsigned long long CUdeviceptr;
typedef CUresult (*init_fn)(unsigned int);
typedef CUresult (*device_get_fn)(CUdevice *, int);
typedef CUresult (*ctx_create_fn)(CUcontext *, unsigned int, CUdevice);
typedef CUresult (*ctx_destroy_fn)(CUcontext);
typedef CUresult (*mem_alloc_fn)(CUdeviceptr *, size_t);
typedef CUresult (*memset_d8_fn)(CUdeviceptr, unsigned char, size_t);
typedef CUresult (*ctx_sync_fn)(void);
typedef CUresult (*mem_free_fn)(CUdeviceptr);

#define LOAD(api, symbol) do { *(void **)(&(api)) = dlsym(lib, (symbol)); \
  if (!(api)) { fprintf(stderr, "cuda_symbol_missing=%s\n", (symbol)); goto done; } \
} while (0)

int main(void) {
  const size_t bytes = 128u * 1024u * 1024u;
  void *lib = dlopen("libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
  CUcontext ctx = NULL;
  CUdeviceptr device_mem = 0;
  CUdevice device = 0;
  int rc = 1;
  CUresult result = 0;
  init_fn cuInit = NULL;
  device_get_fn cuDeviceGet = NULL;
  ctx_create_fn cuCtxCreate = NULL;
  ctx_destroy_fn cuCtxDestroy = NULL;
  mem_alloc_fn cuMemAlloc = NULL;
  memset_d8_fn cuMemsetD8 = NULL;
  ctx_sync_fn cuCtxSynchronize = NULL;
  mem_free_fn cuMemFree = NULL;

  if (!lib) { fprintf(stderr, "cuda_driver_library_unavailable\n"); return 1; }
  LOAD(cuInit, "cuInit");
  LOAD(cuDeviceGet, "cuDeviceGet");
  LOAD(cuCtxCreate, "cuCtxCreate_v2");
  LOAD(cuCtxDestroy, "cuCtxDestroy_v2");
  LOAD(cuMemAlloc, "cuMemAlloc_v2");
  LOAD(cuMemsetD8, "cuMemsetD8_v2");
  LOAD(cuCtxSynchronize, "cuCtxSynchronize");
  LOAD(cuMemFree, "cuMemFree_v2");

  if ((result = cuInit(0)) != 0) goto cuda_error;
  if ((result = cuDeviceGet(&device, 0)) != 0) goto cuda_error;
  if ((result = cuCtxCreate(&ctx, 0, device)) != 0) goto cuda_error;
  if ((result = cuMemAlloc(&device_mem, bytes)) != 0) goto cuda_error;
  if ((result = cuMemsetD8(device_mem, 0x5a, bytes)) != 0) goto cuda_error;
  if ((result = cuCtxSynchronize()) != 0) goto cuda_error;

  printf("framebuffer_witness_allocated_bytes=%zu\n", bytes);
  fflush(stdout);
  struct timespec remaining = { .tv_sec = 120, .tv_nsec = 0 };
  while (nanosleep(&remaining, &remaining) != 0) {
    if (errno != EINTR) { perror("nanosleep"); goto done; }
  }
  if ((result = cuMemFree(device_mem)) != 0) goto cuda_error;
  device_mem = 0;
  if ((result = cuCtxSynchronize()) != 0) goto cuda_error;
  if ((result = cuCtxDestroy(ctx)) != 0) goto cuda_error;
  ctx = NULL;
  if (dlclose(lib) != 0) { fprintf(stderr, "cuda_driver_library_close_failed\n"); lib = NULL; goto done; }
  lib = NULL;
  printf("framebuffer_witness_released=1\nFRAMEBUFFER_WITNESS_PASS\n");
  rc = 0;
  goto done;

cuda_error:
  fprintf(stderr, "cuda_driver_call_failed=%d\n", result);
done:
  if (device_mem && cuMemFree) cuMemFree(device_mem);
  if (ctx && cuCtxDestroy) cuCtxDestroy(ctx);
  if (lib) dlclose(lib);
  return rc;
}
