//===-- dummysan_allocator.cpp ------------------------ ---------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DummySanitizer.
//
// DummySanitizer allocator.
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_errno.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "dummysan.h"
#include "dummysan_allocator.h"
#include "dummysan_checks.h"
#include "dummysan_mapping.h"
#include "dummysan_malloc_bisect.h"
#include "dummysan_thread.h"
#include "dummysan_report.h"

namespace __dummysan {

static Allocator allocator;
static AllocatorCache fallback_allocator_cache;
static SpinMutex fallback_mutex;
static atomic_uint8_t dummysan_allocator_tagging_enabled;

static const tag_t kFallbackAllocTag = 0xBB;
static const tag_t kFallbackFreeTag = 0xBC;

enum RightAlignMode {
  kRightAlignNever,
  kRightAlignSometimes,
  kRightAlignAlways
};

// Initialized in DummysanAllocatorInit, an never changed.
static ALIGNED(16) u8 tail_magic[kShadowAlignment - 1];

bool DummysanChunkView::IsAllocated() const {
  return metadata_ && metadata_->alloc_context_id &&
         metadata_->get_requested_size();
}

// Aligns the 'addr' right to the granule boundary.
static uptr AlignRight(uptr addr, uptr requested_size) {
  uptr tail_size = requested_size % kShadowAlignment;
  if (!tail_size) return addr;
  return addr + kShadowAlignment - tail_size;
}

uptr DummysanChunkView::Beg() const {
  if (metadata_ && metadata_->right_aligned)
    return AlignRight(block_, metadata_->get_requested_size());
  return block_;
}
uptr DummysanChunkView::End() const {
  return Beg() + UsedSize();
}
uptr DummysanChunkView::UsedSize() const {
  return metadata_->get_requested_size();
}
u32 DummysanChunkView::GetAllocStackId() const {
  return metadata_->alloc_context_id;
}

uptr DummysanChunkView::ActualSize() const {
  return allocator.GetActuallyAllocatedSize(reinterpret_cast<void *>(block_));
}

bool DummysanChunkView::FromSmallHeap() const {
  return allocator.FromPrimary(reinterpret_cast<void *>(block_));
}

void GetAllocatorStats(AllocatorStatCounters s) {
  allocator.GetStats(s);
}

void DummysanAllocatorInit() {
  atomic_store_relaxed(&dummysan_allocator_tagging_enabled,
                       !flags()->disable_allocator_tagging);
  SetAllocatorMayReturnNull(common_flags()->allocator_may_return_null);
  allocator.Init(common_flags()->allocator_release_to_os_interval_ms);
  for (uptr i = 0; i < sizeof(tail_magic); i++)
    tail_magic[i] = GetCurrentThread()->GenerateRandomTag();
}

void AllocatorSwallowThreadLocalCache(AllocatorCache *cache) {
  allocator.SwallowCache(cache);
}

static uptr TaggedSize(uptr size) {
  if (!size) size = 1;
  uptr new_size = RoundUpTo(size, kShadowAlignment);
  CHECK_GE(new_size, size);
  return new_size;
}

static void *DummysanAllocate(StackTrace *stack, uptr orig_size, uptr alignment,
                            bool zeroise) {
  if (orig_size > kMaxAllowedMallocSize) {
    if (AllocatorMayReturnNull()) {
      Report("WARNING: DummySanitizer failed to allocate 0x%zx bytes\n",
             orig_size);
      return nullptr;
    }
    ReportAllocationSizeTooBig(orig_size, kMaxAllowedMallocSize, stack);
  }

  alignment = Max(alignment, kShadowAlignment);
  uptr size = TaggedSize(orig_size);
  Thread *t = GetCurrentThread();
  void *allocated;
  if (t) {
    allocated = allocator.Allocate(t->allocator_cache(), size, alignment);
  } else {
    SpinMutexLock l(&fallback_mutex);
    AllocatorCache *cache = &fallback_allocator_cache;
    allocated = allocator.Allocate(cache, size, alignment);
  }
  if (UNLIKELY(!allocated)) {
    SetAllocatorOutOfMemory();
    if (AllocatorMayReturnNull())
      return nullptr;
    ReportOutOfMemory(size, stack);
  }
  Metadata *meta =
      reinterpret_cast<Metadata *>(allocator.GetMetaData(allocated));
  meta->set_requested_size(orig_size);
  meta->alloc_context_id = StackDepotPut(*stack);
  meta->right_aligned = false;
  if (zeroise) {
    internal_memset(allocated, 0, size);
  } else if (flags()->max_malloc_fill_size > 0) {
    uptr fill_size = Min(size, (uptr)flags()->max_malloc_fill_size);
    internal_memset(allocated, flags()->malloc_fill_byte, fill_size);
  }
  if (size != orig_size) {
    internal_memcpy(reinterpret_cast<u8 *>(allocated) + orig_size, tail_magic,
                    size - orig_size - 1);
  }

  void *user_ptr = allocated;
  // Tagging can only be skipped when both tag_in_malloc and tag_in_free are
  // false. When tag_in_malloc = false and tag_in_free = true malloc needs to
  // retag to 0.
  if ((flags()->tag_in_malloc || flags()->tag_in_free) &&
      atomic_load_relaxed(&dummysan_allocator_tagging_enabled)) {
    if (flags()->tag_in_malloc && malloc_bisect(stack, orig_size)) {
      tag_t tag = t ? t->GenerateRandomTag() : kFallbackAllocTag;
      uptr tag_size = orig_size ? orig_size : 1;
      uptr full_granule_size = RoundDownTo(tag_size, kShadowAlignment);
      user_ptr =
          (void *)TagMemoryAligned((uptr)user_ptr, full_granule_size, tag);
      if (full_granule_size != tag_size) {
        u8 *short_granule =
            reinterpret_cast<u8 *>(allocated) + full_granule_size;
        TagMemoryAligned((uptr)short_granule, kShadowAlignment,
                         tag_size % kShadowAlignment);
        short_granule[kShadowAlignment - 1] = tag;
      }
    } else {
      user_ptr = (void *)TagMemoryAligned((uptr)user_ptr, size, 0);
    }
  }

  DUMMYSAN_MALLOC_HOOK(user_ptr, size);
  return user_ptr;
}

static bool PointerAndMemoryTagsMatch(void *tagged_ptr) {
  CHECK(tagged_ptr);
  uptr tagged_uptr = reinterpret_cast<uptr>(tagged_ptr);
  tag_t mem_tag = *reinterpret_cast<tag_t *>(
      MemToShadow(reinterpret_cast<uptr>(UntagPtr(tagged_ptr))));
  return PossiblyShortTagMatches(mem_tag, tagged_uptr, 1);
}

static void DummysanDeallocate(StackTrace *stack, void *tagged_ptr) {
  CHECK(tagged_ptr);
  DUMMYSAN_FREE_HOOK(tagged_ptr);

  if (!PointerAndMemoryTagsMatch(tagged_ptr))
    ReportInvalidFree(stack, reinterpret_cast<uptr>(tagged_ptr));

  void *untagged_ptr = UntagPtr(tagged_ptr);
  void *aligned_ptr = reinterpret_cast<void *>(
      RoundDownTo(reinterpret_cast<uptr>(untagged_ptr), kShadowAlignment));
  Metadata *meta =
      reinterpret_cast<Metadata *>(allocator.GetMetaData(aligned_ptr));
  uptr orig_size = meta->get_requested_size();
  u32 free_context_id = StackDepotPut(*stack);
  u32 alloc_context_id = meta->alloc_context_id;

  // Check tail magic.
  uptr tagged_size = TaggedSize(orig_size);
  if (flags()->free_checks_tail_magic && orig_size &&
      tagged_size != orig_size) {
    uptr tail_size = tagged_size - orig_size - 1;
    CHECK_LT(tail_size, kShadowAlignment);
    void *tail_beg = reinterpret_cast<void *>(
        reinterpret_cast<uptr>(aligned_ptr) + orig_size);
    if (tail_size && internal_memcmp(tail_beg, tail_magic, tail_size))
      ReportTailOverwritten(stack, reinterpret_cast<uptr>(tagged_ptr),
                            orig_size, tail_magic);
  }

  meta->set_requested_size(0);
  meta->alloc_context_id = 0;
  // This memory will not be reused by anyone else, so we are free to keep it
  // poisoned.
  Thread *t = GetCurrentThread();
  if (flags()->max_free_fill_size > 0) {
    uptr fill_size =
        Min(TaggedSize(orig_size), (uptr)flags()->max_free_fill_size);
    internal_memset(aligned_ptr, flags()->free_fill_byte, fill_size);
  }
  if (flags()->tag_in_free && malloc_bisect(stack, 0) &&
      atomic_load_relaxed(&dummysan_allocator_tagging_enabled))
    TagMemoryAligned(reinterpret_cast<uptr>(aligned_ptr), TaggedSize(orig_size),
                     t ? t->GenerateRandomTag() : kFallbackFreeTag);
  if (t) {
    allocator.Deallocate(t->allocator_cache(), aligned_ptr);
    if (auto *ha = t->heap_allocations())
      ha->push({reinterpret_cast<uptr>(tagged_ptr), alloc_context_id,
                free_context_id, static_cast<u32>(orig_size)});
  } else {
    SpinMutexLock l(&fallback_mutex);
    AllocatorCache *cache = &fallback_allocator_cache;
    allocator.Deallocate(cache, aligned_ptr);
  }
}

static void *DummysanReallocate(StackTrace *stack, void *tagged_ptr_old,
                              uptr new_size, uptr alignment) {
  if (!PointerAndMemoryTagsMatch(tagged_ptr_old))
    ReportInvalidFree(stack, reinterpret_cast<uptr>(tagged_ptr_old));

  void *tagged_ptr_new =
      DummysanAllocate(stack, new_size, alignment, false /*zeroise*/);
  if (tagged_ptr_old && tagged_ptr_new) {
    void *untagged_ptr_old =  UntagPtr(tagged_ptr_old);
    Metadata *meta =
        reinterpret_cast<Metadata *>(allocator.GetMetaData(untagged_ptr_old));
    internal_memcpy(
        UntagPtr(tagged_ptr_new), untagged_ptr_old,
        Min(new_size, static_cast<uptr>(meta->get_requested_size())));
    DummysanDeallocate(stack, tagged_ptr_old);
  }
  return tagged_ptr_new;
}

static void *DummysanCalloc(StackTrace *stack, uptr nmemb, uptr size) {
  if (UNLIKELY(CheckForCallocOverflow(size, nmemb))) {
    if (AllocatorMayReturnNull())
      return nullptr;
    ReportCallocOverflow(nmemb, size, stack);
  }
  return DummysanAllocate(stack, nmemb * size, sizeof(u64), true);
}

DummysanChunkView FindHeapChunkByAddress(uptr address) {
  void *block = allocator.GetBlockBegin(reinterpret_cast<void*>(address));
  if (!block)
    return DummysanChunkView();
  Metadata *metadata =
      reinterpret_cast<Metadata*>(allocator.GetMetaData(block));
  return DummysanChunkView(reinterpret_cast<uptr>(block), metadata);
}

static uptr AllocationSize(const void *tagged_ptr) {
  const void *untagged_ptr = UntagPtr(tagged_ptr);
  if (!untagged_ptr) return 0;
  const void *beg = allocator.GetBlockBegin(untagged_ptr);
  Metadata *b = (Metadata *)allocator.GetMetaData(untagged_ptr);
  if (b->right_aligned) {
    if (beg != reinterpret_cast<void *>(RoundDownTo(
                   reinterpret_cast<uptr>(untagged_ptr), kShadowAlignment)))
      return 0;
  } else {
    if (beg != untagged_ptr) return 0;
  }
  return b->get_requested_size();
}

void *dummysan_malloc(uptr size, StackTrace *stack) {
  return SetErrnoOnNull(DummysanAllocate(stack, size, sizeof(u64), false));
}

void *dummysan_calloc(uptr nmemb, uptr size, StackTrace *stack) {
  return SetErrnoOnNull(DummysanCalloc(stack, nmemb, size));
}

void *dummysan_realloc(void *ptr, uptr size, StackTrace *stack) {
  if (!ptr)
    return SetErrnoOnNull(DummysanAllocate(stack, size, sizeof(u64), false));
  if (size == 0) {
    DummysanDeallocate(stack, ptr);
    return nullptr;
  }
  return SetErrnoOnNull(DummysanReallocate(stack, ptr, size, sizeof(u64)));
}

void *dummysan_reallocarray(void *ptr, uptr nmemb, uptr size, StackTrace *stack) {
  if (UNLIKELY(CheckForCallocOverflow(size, nmemb))) {
    errno = errno_ENOMEM;
    if (AllocatorMayReturnNull())
      return nullptr;
    ReportReallocArrayOverflow(nmemb, size, stack);
  }
  return dummysan_realloc(ptr, nmemb * size, stack);
}

void *dummysan_valloc(uptr size, StackTrace *stack) {
  return SetErrnoOnNull(
      DummysanAllocate(stack, size, GetPageSizeCached(), false));
}

void *dummysan_pvalloc(uptr size, StackTrace *stack) {
  uptr PageSize = GetPageSizeCached();
  if (UNLIKELY(CheckForPvallocOverflow(size, PageSize))) {
    errno = errno_ENOMEM;
    if (AllocatorMayReturnNull())
      return nullptr;
    ReportPvallocOverflow(size, stack);
  }
  // pvalloc(0) should allocate one page.
  size = size ? RoundUpTo(size, PageSize) : PageSize;
  return SetErrnoOnNull(DummysanAllocate(stack, size, PageSize, false));
}

void *dummysan_aligned_alloc(uptr alignment, uptr size, StackTrace *stack) {
  if (UNLIKELY(!CheckAlignedAllocAlignmentAndSize(alignment, size))) {
    errno = errno_EINVAL;
    if (AllocatorMayReturnNull())
      return nullptr;
    ReportInvalidAlignedAllocAlignment(size, alignment, stack);
  }
  return SetErrnoOnNull(DummysanAllocate(stack, size, alignment, false));
}

void *dummysan_memalign(uptr alignment, uptr size, StackTrace *stack) {
  if (UNLIKELY(!IsPowerOfTwo(alignment))) {
    errno = errno_EINVAL;
    if (AllocatorMayReturnNull())
      return nullptr;
    ReportInvalidAllocationAlignment(alignment, stack);
  }
  return SetErrnoOnNull(DummysanAllocate(stack, size, alignment, false));
}

int dummysan_posix_memalign(void **memptr, uptr alignment, uptr size,
                        StackTrace *stack) {
  if (UNLIKELY(!CheckPosixMemalignAlignment(alignment))) {
    if (AllocatorMayReturnNull())
      return errno_EINVAL;
    ReportInvalidPosixMemalignAlignment(alignment, stack);
  }
  void *ptr = DummysanAllocate(stack, size, alignment, false);
  if (UNLIKELY(!ptr))
    // OOM error is already taken care of by DummysanAllocate.
    return errno_ENOMEM;
  CHECK(IsAligned((uptr)ptr, alignment));
  *(void **)UntagPtr(memptr) = ptr;
  return 0;
}

void dummysan_free(void *ptr, StackTrace *stack) {
  return DummysanDeallocate(stack, ptr);
}

}  // namespace __dummysan

using namespace __dummysan;

void __dummysan_enable_allocator_tagging() {
  atomic_store_relaxed(&dummysan_allocator_tagging_enabled, 1);
}

void __dummysan_disable_allocator_tagging() {
  atomic_store_relaxed(&dummysan_allocator_tagging_enabled, 0);
}

uptr __sanitizer_get_current_allocated_bytes() {
  uptr stats[AllocatorStatCount];
  allocator.GetStats(stats);
  return stats[AllocatorStatAllocated];
}

uptr __sanitizer_get_heap_size() {
  uptr stats[AllocatorStatCount];
  allocator.GetStats(stats);
  return stats[AllocatorStatMapped];
}

uptr __sanitizer_get_free_bytes() { return 1; }

uptr __sanitizer_get_unmapped_bytes() { return 1; }

uptr __sanitizer_get_estimated_allocated_size(uptr size) { return size; }

int __sanitizer_get_ownership(const void *p) { return AllocationSize(p) != 0; }

uptr __sanitizer_get_allocated_size(const void *p) { return AllocationSize(p); }
