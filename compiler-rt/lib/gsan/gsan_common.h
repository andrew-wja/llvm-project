//=-- gsan_common.h -------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of GenericSanitizer.
// Private GSan header.
//
//===----------------------------------------------------------------------===//

#ifndef GSAN_COMMON_H
#define GSAN_COMMON_H

#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
#include "sanitizer_common/sanitizer_allocator.h"
#endif // GSAN_USE_SANITIZER_ALLOCATOR
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_platform.h"
#include "sanitizer_common/sanitizer_stoptheworld.h"
#include "sanitizer_common/sanitizer_symbolizer.h"

namespace __sanitizer {
class FlagParser;
class ThreadRegistry;
class ThreadContextBase;
struct DTLS;
}

namespace __gsan {

const u32 kInvalidTid = (u32) -1;

struct Flags {
#define GSAN_FLAG(Type, Name, DefaultValue, Description) Type Name;
#include "gsan_flags.inc"
#undef GSAN_FLAG

  void SetDefaults();
};

extern Flags gsan_flags;
inline Flags *flags() { return &gsan_flags; }
void RegisterGsanFlags(FlagParser *parser, Flags *f);

// Platform-specific functions.
void InitializePlatformSpecificModules();

void InitCommonGsan();
void DisableCounterUnderflow();
bool DisabledInThisThread();

// Used to implement __gsan::ScopedDisabler.
void DisableInThisThread();
void EnableInThisThread();
// Can be used to ignore memory allocated by an intercepted
// function.
struct ScopedInterceptorDisabler {
  ScopedInterceptorDisabler() { DisableInThisThread(); }
  ~ScopedInterceptorDisabler() { EnableInThisThread(); }
};

// According to Itanium C++ ABI array cookie is a one word containing
// size of allocated array.
static inline bool IsItaniumABIArrayCookie(uptr chunk_beg, uptr chunk_size,
                                           uptr addr) {
  return chunk_size == sizeof(uptr) && chunk_beg + chunk_size == addr &&
         *reinterpret_cast<uptr *>(chunk_beg) == 0;
}

// According to ARM C++ ABI array cookie consists of two words:
// struct array_cookie {
//   std::size_t element_size; // element_size != 0
//   std::size_t element_count;
// };
static inline bool IsARMABIArrayCookie(uptr chunk_beg, uptr chunk_size,
                                       uptr addr) {
  return chunk_size == 2 * sizeof(uptr) && chunk_beg + chunk_size == addr &&
         *reinterpret_cast<uptr *>(chunk_beg + sizeof(uptr)) == 0;
}

// Special case for "new T[0]" where T is a type with DTOR.
// new T[0] will allocate a cookie (one or two words) for the array size (0)
// and store a pointer to the end of allocated chunk. The actual cookie layout
// varies between platforms according to their C++ ABI implementation.
inline bool IsSpecialCaseOfOperatorNew0(uptr chunk_beg, uptr chunk_size,
                                        uptr addr) {
#if defined(__arm__)
  return IsARMABIArrayCookie(chunk_beg, chunk_size, addr);
#else
  return IsItaniumABIArrayCookie(chunk_beg, chunk_size, addr);
#endif
}

#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
void ForEachChunk(ForEachChunkCallback callback, void *arg);
// Returns the address range occupied by the global allocator object.
void GetAllocatorGlobalRange(uptr *begin, uptr *end);
// Wrappers for allocator's ForceLock()/ForceUnlock().
void LockAllocator();
void UnlockAllocator();
#endif // GSAN_USE_SANITIZER_ALLOCATOR

// Wrappers for ThreadRegistry access.
void LockThreadRegistry();
void UnlockThreadRegistry();
ThreadRegistry *GetThreadRegistryLocked();

#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
bool GetThreadRangesLocked(tid_t os_id, uptr *stack_begin, uptr *stack_end,
                           uptr *tls_begin, uptr *tls_end, uptr *cache_begin,
                           uptr *cache_end, DTLS **dtls);
void GetAllThreadAllocatorCachesLocked(InternalMmapVector<uptr> *caches);
#else
bool GetThreadRangesLocked(tid_t os_id, uptr *stack_begin, uptr *stack_end,
                           uptr *tls_begin, uptr *tls_end, DTLS **dtls);
#endif // GSAN_USE_SANITIZER_ALLOCATOR

// If called from the main thread, updates the main thread's TID in the thread
// registry. We need this to handle processes that fork() without a subsequent
// exec(), which invalidates the recorded TID. To update it, we must call
// gettid() from the main thread. Our solution is to call this function before
// leak checking and also before every call to pthread_create() (to handle cases
// where leak checking is initiated from a non-main thread).
void EnsureMainThreadIDIsCorrect();

// Return the linker module, if valid for the platform.
LoadedModule *GetLinker();

}  // namespace __gsan

extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE
const char *__gsan_default_options();

SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE
int __gsan_is_turned_off();

SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE
const char *__gsan_default_suppressions();
}  // extern "C"

#endif  // GSAN_COMMON_H
