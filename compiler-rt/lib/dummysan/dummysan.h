//===-- dummysan.h ------------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DummySanitizer.
//
// Private Dummysan header.
//===----------------------------------------------------------------------===//

#ifndef DUMMYSAN_H
#define DUMMYSAN_H

#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "dummysan_interface_internal.h"
#include "dummysan_flags.h"
#include "ubsan/ubsan_platform.h"

#ifndef DUMMYSAN_CONTAINS_UBSAN
# define DUMMYSAN_CONTAINS_UBSAN CAN_SANITIZE_UB
#endif

#ifndef DUMMYSAN_REPLACE_OPERATORS_NEW_AND_DELETE
#define DUMMYSAN_REPLACE_OPERATORS_NEW_AND_DELETE
#endif

typedef u8 tag_t;

// TBI (Top Byte Ignore) feature of AArch64: bits [63:56] are ignored in address
// translation and can be used to store a tag.
const unsigned kAddressTagShift = 56;
const uptr kAddressTagMask = 0xFFUL << kAddressTagShift;

// Minimal alignment of the shadow base address. Determines the space available
// for threads and stack histories. This is an ABI constant.
const unsigned kShadowBaseAlignment = 32;

const unsigned kRecordAddrBaseTagShift = 3;
const unsigned kRecordFPShift = 48;
const unsigned kRecordFPLShift = 4;
const unsigned kRecordFPModulus = 1 << (64 - kRecordFPShift + kRecordFPLShift);

static inline tag_t GetTagFromPointer(uptr p) {
  return p >> kAddressTagShift;
}

static inline uptr UntagAddr(uptr tagged_addr) {
  return tagged_addr & ~kAddressTagMask;
}

static inline void *UntagPtr(const void *tagged_ptr) {
  return reinterpret_cast<void *>(
      UntagAddr(reinterpret_cast<uptr>(tagged_ptr)));
}

static inline uptr AddTagToPointer(uptr p, tag_t tag) {
  return (p & ~kAddressTagMask) | ((uptr)tag << kAddressTagShift);
}

namespace __dummysan {

extern int dummysan_inited;
extern bool dummysan_init_is_running;
extern int dummysan_report_count;

bool InitShadow();
void InitPrctl();
void InitThreads();
void InitializeInterceptors();

void DummysanAllocatorInit();

void *dummysan_malloc(uptr size, StackTrace *stack);
void *dummysan_calloc(uptr nmemb, uptr size, StackTrace *stack);
void *dummysan_realloc(void *ptr, uptr size, StackTrace *stack);
void *dummysan_reallocarray(void *ptr, uptr nmemb, uptr size, StackTrace *stack);
void *dummysan_valloc(uptr size, StackTrace *stack);
void *dummysan_pvalloc(uptr size, StackTrace *stack);
void *dummysan_aligned_alloc(uptr alignment, uptr size, StackTrace *stack);
void *dummysan_memalign(uptr alignment, uptr size, StackTrace *stack);
int dummysan_posix_memalign(void **memptr, uptr alignment, uptr size,
                        StackTrace *stack);
void dummysan_free(void *ptr, StackTrace *stack);

void InstallAtExitHandler();

#define GET_MALLOC_STACK_TRACE                                            \
  BufferedStackTrace stack;                                               \
  if (dummysan_inited)                                                      \
    stack.Unwind(StackTrace::GetCurrentPc(), GET_CURRENT_FRAME(),         \
                 nullptr, common_flags()->fast_unwind_on_malloc,          \
                 common_flags()->malloc_context_size)

#define GET_FATAL_STACK_TRACE_PC_BP(pc, bp)              \
  BufferedStackTrace stack;                              \
  if (dummysan_inited)                                     \
    stack.Unwind(pc, bp, nullptr, common_flags()->fast_unwind_on_fatal)

#define GET_FATAL_STACK_TRACE_HERE \
  GET_FATAL_STACK_TRACE_PC_BP(StackTrace::GetCurrentPc(), GET_CURRENT_FRAME())

#define PRINT_CURRENT_STACK_CHECK() \
  {                                 \
    GET_FATAL_STACK_TRACE_HERE;     \
    stack.Print();                  \
  }

void DummysanTSDInit();
void DummysanTSDThreadInit();

void DummysanOnDeadlySignal(int signo, void *info, void *context);

void UpdateMemoryUsage();

void AppendToErrorMessageBuffer(const char *buffer);

void AndroidTestTlsSlot();

}  // namespace __dummysan

#define DUMMYSAN_MALLOC_HOOK(ptr, size)       \
  do {                                    \
    if (&__sanitizer_malloc_hook) {       \
      __sanitizer_malloc_hook(ptr, size); \
    }                                     \
    RunMallocHooks(ptr, size);            \
  } while (false)
#define DUMMYSAN_FREE_HOOK(ptr)       \
  do {                            \
    if (&__sanitizer_free_hook) { \
      __sanitizer_free_hook(ptr); \
    }                             \
    RunFreeHooks(ptr);            \
  } while (false)

#endif  // DUMMYSAN_H
