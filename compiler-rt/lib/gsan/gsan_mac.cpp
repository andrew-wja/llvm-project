//===-- gsan_mac.cpp ------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of GenericSanitizer, a memory leak checker.
//
// Mac-specific details.
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_platform.h"
#if SANITIZER_MAC

#include "interception/interception.h"
#include "gsan.h"
#include "gsan_allocator.h"
#include "gsan_thread.h"

#include <pthread.h>

namespace __gsan {
// Support for the following functions from libdispatch on Mac OS:
//   dispatch_async_f()
//   dispatch_async()
//   dispatch_sync_f()
//   dispatch_sync()
//   dispatch_after_f()
//   dispatch_after()
//   dispatch_group_async_f()
//   dispatch_group_async()
// TODO(glider): libdispatch API contains other functions that we don't support
// yet.
//
// dispatch_sync() and dispatch_sync_f() are synchronous, although chances are
// they can cause jobs to run on a thread different from the current one.
// TODO(glider): if so, we need a test for this (otherwise we should remove
// them).
//
// The following functions use dispatch_barrier_async_f() (which isn't a library
// function but is exported) and are thus supported:
//   dispatch_source_set_cancel_handler_f()
//   dispatch_source_set_cancel_handler()
//   dispatch_source_set_event_handler_f()
//   dispatch_source_set_event_handler()
//
// The reference manual for Grand Central Dispatch is available at
//   http://developer.apple.com/library/mac/#documentation/Performance/Reference/GCD_libdispatch_Ref/Reference/reference.html
// The implementation details are at
//   http://libdispatch.macosforge.org/trac/browser/trunk/src/queue.c

typedef void *dispatch_group_t;
typedef void *dispatch_queue_t;
typedef void *dispatch_source_t;
typedef u64 dispatch_time_t;
typedef void (*dispatch_function_t)(void *block);
typedef void *(*worker_t)(void *block);

// A wrapper for the ObjC blocks used to support libdispatch.
typedef struct {
  void *block;
  dispatch_function_t func;
  u32 parent_tid;
} gsan_block_context_t;

ALWAYS_INLINE
void gsan_register_worker_thread(int parent_tid) {
  if (GetCurrentThread() == kInvalidTid) {
    u32 tid = ThreadCreate(parent_tid, 0, true);
    ThreadStart(tid, GetTid());
    SetCurrentThread(tid);
  }
}

// For use by only those functions that allocated the context via
// alloc_gsan_context().
extern "C" void gsan_dispatch_call_block_and_release(void *block) {
  gsan_block_context_t *context = (gsan_block_context_t *)block;
  VReport(2,
          "gsan_dispatch_call_block_and_release(): "
          "context: %p, pthread_self: %p\n",
          block, pthread_self());
  gsan_register_worker_thread(context->parent_tid);
  // Call the original dispatcher for the block.
  context->func(context->block);
  gsan_free(context);
}

}  // namespace __gsan

using namespace __gsan;

// Wrap |ctxt| and |func| into an gsan_block_context_t.
// The caller retains control of the allocated context.
extern "C" gsan_block_context_t *alloc_gsan_context(void *ctxt,
                                                    dispatch_function_t func) {
  GET_STACK_TRACE_THREAD;
  gsan_block_context_t *gsan_ctxt =
      (gsan_block_context_t *)gsan_malloc(sizeof(gsan_block_context_t), stack);
  gsan_ctxt->block = ctxt;
  gsan_ctxt->func = func;
  gsan_ctxt->parent_tid = GetCurrentThread();
  return gsan_ctxt;
}

// Define interceptor for dispatch_*_f function with the three most common
// parameters: dispatch_queue_t, context, dispatch_function_t.
#define INTERCEPT_DISPATCH_X_F_3(dispatch_x_f)                        \
  INTERCEPTOR(void, dispatch_x_f, dispatch_queue_t dq, void *ctxt,    \
              dispatch_function_t func) {                             \
    gsan_block_context_t *gsan_ctxt = alloc_gsan_context(ctxt, func); \
    return REAL(dispatch_x_f)(dq, (void *)gsan_ctxt,                  \
                              gsan_dispatch_call_block_and_release);  \
  }

INTERCEPT_DISPATCH_X_F_3(dispatch_async_f)
INTERCEPT_DISPATCH_X_F_3(dispatch_sync_f)
INTERCEPT_DISPATCH_X_F_3(dispatch_barrier_async_f)

INTERCEPTOR(void, dispatch_after_f, dispatch_time_t when, dispatch_queue_t dq,
            void *ctxt, dispatch_function_t func) {
  gsan_block_context_t *gsan_ctxt = alloc_gsan_context(ctxt, func);
  return REAL(dispatch_after_f)(when, dq, (void *)gsan_ctxt,
                                gsan_dispatch_call_block_and_release);
}

INTERCEPTOR(void, dispatch_group_async_f, dispatch_group_t group,
            dispatch_queue_t dq, void *ctxt, dispatch_function_t func) {
  gsan_block_context_t *gsan_ctxt = alloc_gsan_context(ctxt, func);
  REAL(dispatch_group_async_f)
  (group, dq, (void *)gsan_ctxt, gsan_dispatch_call_block_and_release);
}

#if !defined(MISSING_BLOCKS_SUPPORT)
extern "C" {
void dispatch_async(dispatch_queue_t dq, void (^work)(void));
void dispatch_group_async(dispatch_group_t dg, dispatch_queue_t dq,
                          void (^work)(void));
void dispatch_after(dispatch_time_t when, dispatch_queue_t queue,
                    void (^work)(void));
void dispatch_source_set_cancel_handler(dispatch_source_t ds,
                                        void (^work)(void));
void dispatch_source_set_event_handler(dispatch_source_t ds,
                                       void (^work)(void));
}

#define GET_GSAN_BLOCK(work)                 \
  void (^gsan_block)(void);                  \
  int parent_tid = GetCurrentThread();       \
  gsan_block = ^(void) {                     \
    gsan_register_worker_thread(parent_tid); \
    work();                                  \
  }

INTERCEPTOR(void, dispatch_async, dispatch_queue_t dq, void (^work)(void)) {
  GET_GSAN_BLOCK(work);
  REAL(dispatch_async)(dq, gsan_block);
}

INTERCEPTOR(void, dispatch_group_async, dispatch_group_t dg,
            dispatch_queue_t dq, void (^work)(void)) {
  GET_GSAN_BLOCK(work);
  REAL(dispatch_group_async)(dg, dq, gsan_block);
}

INTERCEPTOR(void, dispatch_after, dispatch_time_t when, dispatch_queue_t queue,
            void (^work)(void)) {
  GET_GSAN_BLOCK(work);
  REAL(dispatch_after)(when, queue, gsan_block);
}

INTERCEPTOR(void, dispatch_source_set_cancel_handler, dispatch_source_t ds,
            void (^work)(void)) {
  if (!work) {
    REAL(dispatch_source_set_cancel_handler)(ds, work);
    return;
  }
  GET_GSAN_BLOCK(work);
  REAL(dispatch_source_set_cancel_handler)(ds, gsan_block);
}

INTERCEPTOR(void, dispatch_source_set_event_handler, dispatch_source_t ds,
            void (^work)(void)) {
  GET_GSAN_BLOCK(work);
  REAL(dispatch_source_set_event_handler)(ds, gsan_block);
}
#endif

#endif  // SANITIZER_MAC
