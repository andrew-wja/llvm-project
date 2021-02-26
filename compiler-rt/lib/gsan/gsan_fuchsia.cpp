//=-- gsan_fuchsia.cpp ---------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===---------------------------------------------------------------------===//
//
// This file is a part of GenericSanitizer.
// Standalone GSan RTL code specific to Fuchsia.
//
//===---------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_platform.h"

#if SANITIZER_FUCHSIA
#include <zircon/sanitizer.h>

#include "gsan.h"
#include "gsan_allocator.h"

using namespace __gsan;

namespace __gsan {

void GsanOnDeadlySignal(int signo, void *siginfo, void *context) {}

ThreadContext::ThreadContext(int tid) : ThreadContextGsanBase(tid) {}

struct OnCreatedArgs {
  uptr stack_begin, stack_end;
};

// On Fuchsia, the stack bounds of a new thread are available before
// the thread itself has started running.
void ThreadContext::OnCreated(void *arg) {
  // Stack bounds passed through from __sanitizer_before_thread_create_hook
  // or InitializeMainThread.
  auto args = reinterpret_cast<const OnCreatedArgs *>(arg);
  stack_begin_ = args->stack_begin;
  stack_end_ = args->stack_end;
}

#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
struct OnStartedArgs {
  uptr cache_begin, cache_end;
};
#endif // GSAN_USE_SANITIZER_ALLOCATOR

void ThreadContext::OnStarted(void *arg) {
#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
  auto args = reinterpret_cast<const OnStartedArgs *>(arg);
  cache_begin_ = args->cache_begin;
  cache_end_ = args->cache_end;
#endif // GSAN_USE_SANITIZER_ALLOCATOR
}

void ThreadStart(u32 tid) {
#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
  OnStartedArgs args;
  GetAllocatorCacheRange(&args.cache_begin, &args.cache_end);
  CHECK_EQ(args.cache_end - args.cache_begin, sizeof(AllocatorCache));
  ThreadContextGsanBase::ThreadStart(tid, GetTid(), ThreadType::Regular, &args);
#else
  ThreadContextGsanBase::ThreadStart(tid, GetTid(), ThreadType::Regular, nullptr);
#endif // GSAN_USE_SANITIZER_ALLOCATOR
}

void InitializeMainThread() {
  OnCreatedArgs args;
  __sanitizer::GetThreadStackTopAndBottom(true, &args.stack_end,
                                          &args.stack_begin);
  u32 tid = ThreadCreate(0, GetThreadSelf(), true, &args);
  CHECK_EQ(tid, 0);
  ThreadStart(tid);
}

#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
void GetAllThreadAllocatorCachesLocked(InternalMmapVector<uptr> *caches) {
  GetThreadRegistryLocked()->RunCallbackForEachThreadLocked(
      [](ThreadContextBase *tctx, void *arg) {
        auto ctx = static_cast<ThreadContext *>(tctx);
        static_cast<decltype(caches)>(arg)->push_back(ctx->cache_begin());
      },
      caches);
}
#endif // GSAN_USE_SANITIZER_ALLOCATOR

}  // namespace __gsan

// These are declared (in extern "C") by <zircon/sanitizer.h>.
// The system runtime will call our definitions directly.

// This is called before each thread creation is attempted.  So, in
// its first call, the calling thread is the initial and sole thread.
void *__sanitizer_before_thread_create_hook(thrd_t thread, bool detached,
                                            const char *name, void *stack_base,
                                            size_t stack_size) {
  uptr user_id = reinterpret_cast<uptr>(thread);
  ENSURE_GSAN_INITED;
  EnsureMainThreadIDIsCorrect();
  OnCreatedArgs args;
  args.stack_begin = reinterpret_cast<uptr>(stack_base);
  args.stack_end = args.stack_begin + stack_size;
  u32 parent_tid = GetCurrentThread();
  u32 tid = ThreadCreate(parent_tid, user_id, detached, &args);
  return reinterpret_cast<void *>(static_cast<uptr>(tid));
}

// This is called after creating a new thread (in the creating thread),
// with the pointer returned by __sanitizer_before_thread_create_hook (above).
void __sanitizer_thread_create_hook(void *hook, thrd_t thread, int error) {
  u32 tid = static_cast<u32>(reinterpret_cast<uptr>(hook));
  // On success, there is nothing to do here.
  if (error != thrd_success) {
    // Clean up the thread registry for the thread creation that didn't happen.
    GetThreadRegistryLocked()->FinishThread(tid);
  }
}

// This is called in the newly-created thread before it runs anything else,
// with the pointer returned by __sanitizer_before_thread_create_hook (above).
void __sanitizer_thread_start_hook(void *hook, thrd_t self) {
  u32 tid = static_cast<u32>(reinterpret_cast<uptr>(hook));
  ThreadStart(tid);
}

// Each thread runs this just before it exits,
// with the pointer returned by BeforeThreadCreateHook (above).
// All per-thread destructors have already been called.
void __sanitizer_thread_exit_hook(void *hook, thrd_t self) { ThreadFinish(); }

#endif  // SANITIZER_FUCHSIA
