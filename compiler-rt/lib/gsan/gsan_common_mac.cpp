//=-- gsan_common_mac.cpp -------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of GenericSanitizer.
// Implementation of common leak checking functionality. Darwin-specific code.
//
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_platform.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "gsan_common.h"

#if SANITIZER_MAC

#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
#include "sanitizer_common/sanitizer_allocator_internal.h"
#endif // GSAN_USE_SANITIZER_ALLOCATOR
#include "gsan_allocator.h"

#include <pthread.h>

#include <mach/mach.h>

#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
// Only introduced in Mac OS X 10.9.
#ifdef VM_MEMORY_OS_ALLOC_ONCE
static const int kSanitizerVmMemoryOsAllocOnce = VM_MEMORY_OS_ALLOC_ONCE;
#else
static const int kSanitizerVmMemoryOsAllocOnce = 73;
#endif
#endif // GSAN_USE_SANITIZER_ALLOCATOR

namespace __gsan {

typedef struct {
  int disable_counter;
  u32 current_thread_id;
#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
  AllocatorCache cache;
#endif // GSAN_USE_SANITIZER_ALLOCATOR
} thread_local_data_t;

static pthread_key_t key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;

// The main thread destructor requires the current thread id,
// so we can't destroy it until it's been used and reset to invalid tid
void restore_tid_data(void *ptr) {
  thread_local_data_t *data = (thread_local_data_t *)ptr;
  if (data->current_thread_id != kInvalidTid)
    pthread_setspecific(key, data);
}

static void make_tls_key() {
  CHECK_EQ(pthread_key_create(&key, restore_tid_data), 0);
}

static thread_local_data_t *get_tls_val(bool alloc) {
  pthread_once(&key_once, make_tls_key);

  thread_local_data_t *ptr = (thread_local_data_t *)pthread_getspecific(key);
  if (ptr == NULL && alloc) {
    ptr = (thread_local_data_t *)InternalAlloc(sizeof(*ptr));
    ptr->disable_counter = 0;
    ptr->current_thread_id = kInvalidTid;
#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
    ptr->cache = AllocatorCache();
#endif // GSAN_USE_SANITIZER_ALLOCATOR
    pthread_setspecific(key, ptr);
  }

  return ptr;
}

bool DisabledInThisThread() {
  thread_local_data_t *data = get_tls_val(false);
  return data ? data->disable_counter > 0 : false;
}

void DisableInThisThread() { ++get_tls_val(true)->disable_counter; }

void EnableInThisThread() {
  int *disable_counter = &get_tls_val(true)->disable_counter;
  if (*disable_counter == 0) {
    DisableCounterUnderflow();
  }
  --*disable_counter;
}

u32 GetCurrentThread() {
  thread_local_data_t *data = get_tls_val(false);
  return data ? data->current_thread_id : kInvalidTid;
}

void SetCurrentThread(u32 tid) { get_tls_val(true)->current_thread_id = tid; }

#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
AllocatorCache *GetAllocatorCache() { return &get_tls_val(true)->cache; }
#endif // GSAN_USE_SANITIZER_ALLOCATOR

LoadedModule *GetLinker() { return nullptr; }

// Required on Linux for initialization of TLS behavior, but should not be
// required on Darwin.
void InitializePlatformSpecificModules() {}

} // namespace __gsan

#endif // SANITIZER_MAC
