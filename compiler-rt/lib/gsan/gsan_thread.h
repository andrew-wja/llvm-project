//=-- gsan_thread.h -------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of GenericSanitizer.
// Thread registry for standalone GSan.
//
//===----------------------------------------------------------------------===//

#ifndef GSAN_THREAD_H
#define GSAN_THREAD_H

#include "sanitizer_common/sanitizer_thread_registry.h"

namespace __gsan {

class ThreadContextGsanBase : public ThreadContextBase {
 public:
  explicit ThreadContextGsanBase(int tid);
  void OnFinished() override;
  uptr stack_begin() { return stack_begin_; }
  uptr stack_end() { return stack_end_; }
#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
  uptr cache_begin() { return cache_begin_; }
  uptr cache_end() { return cache_end_; }
#endif // GSAN_USE_SANITIZER_ALLOCATOR

  // The argument is passed on to the subclass's OnStarted member function.
  static void ThreadStart(u32 tid, tid_t os_id, ThreadType thread_type,
                          void *onstarted_arg);

 protected:
  ~ThreadContextGsanBase() {}
  uptr stack_begin_ = 0;
  uptr stack_end_ = 0;
#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
  uptr cache_begin_ = 0;
  uptr cache_end_ = 0;
#endif // GSAN_USE_SANITIZER_ALLOCATOR
};

// This subclass of ThreadContextGsanBase is declared in an OS-specific header.
class ThreadContext;

void InitializeThreadRegistry();
void InitializeMainThread();

u32 ThreadCreate(u32 tid, uptr uid, bool detached, void *arg = nullptr);
void ThreadFinish();
void ThreadDetach(u32 tid);
void ThreadJoin(u32 tid);
u32 ThreadTid(uptr uid);

u32 GetCurrentThread();
void SetCurrentThread(u32 tid);
ThreadContext *CurrentThreadContext();
void EnsureMainThreadIDIsCorrect();

}  // namespace __gsan

#endif  // GSAN_THREAD_H
