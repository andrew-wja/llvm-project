//=-- gsan_allocator.h ----------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of GenericSanitizer.
// Allocator for standalone GSan.
//
//===----------------------------------------------------------------------===//

#ifndef GSAN_ALLOCATOR_H
#define GSAN_ALLOCATOR_H

#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_common.h"
#include "gsan_common.h"

#if defined(GSAN_USE_SANITIZER_ALLOCATOR)

#include "sanitizer_common/sanitizer_allocator.h"

namespace __gsan {

void *Allocate(const StackTrace &stack, uptr size, uptr alignment,
               bool cleared);
void Deallocate(void *p);
void *Reallocate(const StackTrace &stack, void *p, uptr new_size,
                 uptr alignment);
uptr GetMallocUsableSize(const void *p);

template<typename Callable>
void ForEachChunk(const Callable &callback);

void GetAllocatorCacheRange(uptr *begin, uptr *end);
void AllocatorThreadFinish();
void InitializeAllocator();

const bool kAlwaysClearMemory = true;

struct ChunkMetadata {
  u8 allocated : 8;  // Must be first.
#if SANITIZER_WORDSIZE == 64
  uptr requested_size : 54;
#else
  uptr requested_size : 32;
  uptr padding : 22;
#endif
  u32 stack_trace_id;
};

#if defined(__mips64) || defined(__aarch64__) || defined(__i386__) || \
    defined(__arm__) || SANITIZER_RISCV64
template <typename AddressSpaceViewTy>
struct AP32 {
  static const uptr kSpaceBeg = 0;
  static const u64 kSpaceSize = SANITIZER_MMAP_RANGE_SIZE;
  static const uptr kMetadataSize = sizeof(ChunkMetadata);
  typedef __sanitizer::CompactSizeClassMap SizeClassMap;
  static const uptr kRegionSizeLog = 20;
  using AddressSpaceView = AddressSpaceViewTy;
  typedef NoOpMapUnmapCallback MapUnmapCallback;
  static const uptr kFlags = 0;
};
template <typename AddressSpaceView>
using PrimaryAllocatorASVT = SizeClassAllocator32<AP32<AddressSpaceView>>;
using PrimaryAllocator = PrimaryAllocatorASVT<LocalAddressSpaceView>;
#elif defined(__x86_64__) || defined(__powerpc64__) || defined(__s390x__)
# if SANITIZER_FUCHSIA
const uptr kAllocatorSpace = ~(uptr)0;
const uptr kAllocatorSize  =  0x40000000000ULL;  // 4T.
# elif defined(__powerpc64__)
const uptr kAllocatorSpace = 0xa0000000000ULL;
const uptr kAllocatorSize  = 0x20000000000ULL;  // 2T.
#elif defined(__s390x__)
const uptr kAllocatorSpace = 0x40000000000ULL;
const uptr kAllocatorSize = 0x40000000000ULL;  // 4T.
# else
const uptr kAllocatorSpace = 0x600000000000ULL;
const uptr kAllocatorSize  = 0x40000000000ULL;  // 4T.
# endif
template <typename AddressSpaceViewTy>
struct AP64 {  // Allocator64 parameters. Deliberately using a short name.
  static const uptr kSpaceBeg = kAllocatorSpace;
  static const uptr kSpaceSize = kAllocatorSize;
  static const uptr kMetadataSize = sizeof(ChunkMetadata);
  typedef DefaultSizeClassMap SizeClassMap;
  typedef NoOpMapUnmapCallback MapUnmapCallback;
  static const uptr kFlags = 0;
  using AddressSpaceView = AddressSpaceViewTy;
};

template <typename AddressSpaceView>
using PrimaryAllocatorASVT = SizeClassAllocator64<AP64<AddressSpaceView>>;
using PrimaryAllocator = PrimaryAllocatorASVT<LocalAddressSpaceView>;
#endif

template <typename AddressSpaceView>
using AllocatorASVT = CombinedAllocator<PrimaryAllocatorASVT<AddressSpaceView>>;
using Allocator = AllocatorASVT<LocalAddressSpaceView>;
using AllocatorCache = Allocator::AllocatorCache;

Allocator::AllocatorCache *GetAllocatorCache();

int gsan_posix_memalign(void **memptr, uptr alignment, uptr size,
                        const StackTrace &stack);
void *gsan_aligned_alloc(uptr alignment, uptr size, const StackTrace &stack);
void *gsan_memalign(uptr alignment, uptr size, const StackTrace &stack);
void *gsan_malloc(uptr size, const StackTrace &stack);
void gsan_free(void *p);
void *gsan_realloc(void *p, uptr size, const StackTrace &stack);
void *gsan_reallocarray(void *p, uptr nmemb, uptr size,
                        const StackTrace &stack);
void *gsan_calloc(uptr nmemb, uptr size, const StackTrace &stack);
void *gsan_valloc(uptr size, const StackTrace &stack);
void *gsan_pvalloc(uptr size, const StackTrace &stack);
uptr gsan_mz_size(const void *p);

}  // namespace __gsan

#else

namespace __gsan {

int gsan_posix_memalign(void **memptr, uptr alignment, uptr size,
                        const StackTrace &stack);
void *gsan_aligned_alloc(uptr alignment, uptr size, const StackTrace &stack);
void *gsan_memalign(uptr alignment, uptr size, const StackTrace &stack);
void *gsan_malloc(uptr size, const StackTrace &stack);
void gsan_free(void *p);
void *gsan_realloc(void *p, uptr size, const StackTrace &stack);
void *gsan_reallocarray(void *p, uptr nmemb, uptr size,
                        const StackTrace &stack);
void *gsan_calloc(uptr nmemb, uptr size, const StackTrace &stack);
void *gsan_valloc(uptr size, const StackTrace &stack);
void *gsan_pvalloc(uptr size, const StackTrace &stack);

#if defined(SANITIZER_LINUX)
uptr gsan_mz_size(void *p);
#else
uptr gsan_mz_size(const void *p);
#endif // SANITIZER_LINUX

}
#endif // GSAN_USE_SANITIZER_ALLOCATOR

#endif  // GSAN_ALLOCATOR_H
