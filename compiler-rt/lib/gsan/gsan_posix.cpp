//=-- gsan_posix.cpp -----------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===---------------------------------------------------------------------===//
//
// This file is a part of GenericSanitizer.
// Standalone GSan RTL code common to POSIX-like systems.
//
//===---------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_platform.h"

#if SANITIZER_POSIX
#include "gsan.h"
#include "gsan_allocator.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_tls_get_addr.h"

namespace __gsan {

ThreadContext::ThreadContext(int tid) : ThreadContextGsanBase(tid) {}

struct OnStartedArgs {
  uptr stack_begin;
  uptr stack_end;

#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
  uptr cache_begin;
  uptr cache_end;
#endif // GSAN_USE_SANITIZER_ALLOCATOR

  uptr tls_begin;
  uptr tls_end;
  DTLS *dtls;
};

void ThreadContext::OnStarted(void *arg) {
  auto args = reinterpret_cast<const OnStartedArgs *>(arg);
  stack_begin_ = args->stack_begin;
  stack_end_ = args->stack_end;
  tls_begin_ = args->tls_begin;
  tls_end_ = args->tls_end;

#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
  cache_begin_ = args->cache_begin;
  cache_end_ = args->cache_end;
#endif // GSAN_USE_SANITIZER_ALLOCATOR

  dtls_ = args->dtls;
}

void ThreadStart(u32 tid, tid_t os_id, ThreadType thread_type) {
  OnStartedArgs args;
  uptr stack_size = 0;
  uptr tls_size = 0;
  GetThreadStackAndTls(tid == 0, &args.stack_begin, &stack_size,
                       &args.tls_begin, &tls_size);
  args.stack_end = args.stack_begin + stack_size;
  args.tls_end = args.tls_begin + tls_size;

#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
  GetAllocatorCacheRange(&args.cache_begin, &args.cache_end);
#endif // GSAN_USE_SANITIZER_ALLOCATOR

  args.dtls = DTLS_Get();
  ThreadContextGsanBase::ThreadStart(tid, os_id, thread_type, &args);
}

#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
bool GetThreadRangesLocked(tid_t os_id, uptr *stack_begin, uptr *stack_end,
                           uptr *tls_begin, uptr *tls_end, uptr *cache_begin,
                           uptr *cache_end, DTLS **dtls) {
  ThreadContext *context = static_cast<ThreadContext *>(
      GetThreadRegistryLocked()->FindThreadContextByOsIDLocked(os_id));
  if (!context)
    return false;
  *stack_begin = context->stack_begin();
  *stack_end = context->stack_end();
  *tls_begin = context->tls_begin();
  *tls_end = context->tls_end();
  *cache_begin = context->cache_begin();
  *cache_end = context->cache_end();
  *dtls = context->dtls();
  return true;
}
#else
bool GetThreadRangesLocked(tid_t os_id, uptr *stack_begin, uptr *stack_end,
                           uptr *tls_begin, uptr *tls_end, DTLS **dtls) {
  ThreadContext *context = static_cast<ThreadContext *>(
      GetThreadRegistryLocked()->FindThreadContextByOsIDLocked(os_id));
  if (!context)
    return false;
  *stack_begin = context->stack_begin();
  *stack_end = context->stack_end();
  *tls_begin = context->tls_begin();
  *tls_end = context->tls_end();
  *dtls = context->dtls();
  return true;
}
#endif // GSAN_USE_SANITIZER_ALLOCATOR

void InitializeMainThread() {
  u32 tid = ThreadCreate(0, 0, true);
  CHECK_EQ(tid, 0);
  ThreadStart(tid, GetTid());
}

static void OnStackUnwind(const SignalContext &sig, const void *,
                          BufferedStackTrace *stack) {
  stack->Unwind(StackTrace::GetNextInstructionPc(sig.pc), sig.bp, sig.context,
                common_flags()->fast_unwind_on_fatal);
}

void GsanOnDeadlySignal(int signo, void *siginfo, void *context) {
  HandleDeadlySignal(siginfo, context, GetCurrentThread(), &OnStackUnwind,
                     nullptr);
}

}  // namespace __gsan

#endif  // SANITIZER_POSIX
