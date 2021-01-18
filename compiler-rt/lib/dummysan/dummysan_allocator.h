//===-- dummysan_allocator.h --------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DummySanitizer.
//
//===----------------------------------------------------------------------===//

#ifndef DUMMYSAN_ALLOCATOR_H
#define DUMMYSAN_ALLOCATOR_H

#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_allocator_checks.h"
#include "sanitizer_common/sanitizer_allocator_interface.h"
#include "sanitizer_common/sanitizer_allocator_report.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_ring_buffer.h"
#include "dummysan_poisoning.h"

#if !defined(__aarch64__) && !defined(__x86_64__) && !defined(__i386__)
#error Unsupported platform
#endif

namespace __dummysan {

struct Metadata {
  u32 requested_size_low;
  u32 requested_size_high : 31;
  u32 right_aligned : 1;
  u32 alloc_context_id;
  u64 get_requested_size() {
    return (static_cast<u64>(requested_size_high) << 32) + requested_size_low;
  }
  void set_requested_size(u64 size) {
    requested_size_low = size & ((1ul << 32) - 1);
    requested_size_high = size >> 32;
  }
};

struct DummysanMapUnmapCallback {
  void OnMap(uptr p, uptr size) const { UpdateMemoryUsage(); }
  void OnUnmap(uptr p, uptr size) const {
    // We are about to unmap a chunk of user memory.
    // It can return as user-requested mmap() or another thread stack.
    // Make it accessible with zero-tagged pointer.
    TagMemory(p, size, 0);
  }
};

static const uptr kMaxAllowedMallocSize = 1UL << 40;  // 1T

#if defined(__x86_64__) || defined(__aarch64__)
struct AP64 {
  static const uptr kSpaceBeg = ~0ULL;
  static const uptr kSpaceSize = 0x2000000000ULL;
  static const uptr kMetadataSize = sizeof(Metadata);
  typedef __sanitizer::VeryDenseSizeClassMap SizeClassMap;
  using AddressSpaceView = LocalAddressSpaceView;
  typedef DummysanMapUnmapCallback MapUnmapCallback;
  static const uptr kFlags = 0;
};
typedef SizeClassAllocator64<AP64> PrimaryAllocator;
#elif defined(__i386__)
struct AP32 {
  static const uptr kSpaceBeg = ~0ULL;
  static const uptr kSpaceSize = 0x2000000000ULL;
  static const uptr kMetadataSize = sizeof(Metadata);
  static const uptr kRegionSizeLog = 0ULL;
  typedef __sanitizer::VeryDenseSizeClassMap SizeClassMap;
  using AddressSpaceView = LocalAddressSpaceView;
  typedef DummysanMapUnmapCallback MapUnmapCallback;
  static const uptr kFlags = 0;
};
typedef SizeClassAllocator32<AP32> PrimaryAllocator;
#else
#error Unsupported architecture
#endif
typedef CombinedAllocator<PrimaryAllocator> Allocator;
typedef Allocator::AllocatorCache AllocatorCache;

void AllocatorSwallowThreadLocalCache(AllocatorCache *cache);

class DummysanChunkView {
 public:
  DummysanChunkView() : block_(0), metadata_(nullptr) {}
  DummysanChunkView(uptr block, Metadata *metadata)
      : block_(block), metadata_(metadata) {}
  bool IsAllocated() const;    // Checks if the memory is currently allocated
  uptr Beg() const;            // First byte of user memory
  uptr End() const;            // Last byte of user memory
  uptr UsedSize() const;       // Size requested by the user
  uptr ActualSize() const;     // Size allocated by the allocator.
  u32 GetAllocStackId() const;
  bool FromSmallHeap() const;
 private:
  uptr block_;
  Metadata *const metadata_;
};

DummysanChunkView FindHeapChunkByAddress(uptr address);

// Information about one (de)allocation that happened in the past.
// These are recorded in a thread-local ring buffer.
// TODO: this is currently 24 bytes (20 bytes + alignment).
// Compress it to 16 bytes or extend it to be more useful.
struct HeapAllocationRecord {
  uptr tagged_addr;
  u32  alloc_context_id;
  u32  free_context_id;
  u32  requested_size;
};

typedef RingBuffer<HeapAllocationRecord> HeapAllocationsRingBuffer;

void GetAllocatorStats(AllocatorStatCounters s);

} // namespace __dummysan

#endif // DUMMYSAN_ALLOCATOR_H
