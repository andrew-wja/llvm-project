//=-- gsan_common.cpp -----------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of GenericSanitizer.
//
//===----------------------------------------------------------------------===//

#include "gsan_common.h"

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_procmaps.h"
#include "sanitizer_common/sanitizer_report_decorator.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_suppressions.h"
#include "sanitizer_common/sanitizer_thread_registry.h"
#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
#include "sanitizer_common/sanitizer_tls_get_addr.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#endif // GSAN_USE_SANITIZER_ALLOCATOR

namespace __gsan {

BlockingMutex global_mutex(LINKER_INITIALIZED);

Flags gsan_flags;

void DisableCounterUnderflow() { }

void Flags::SetDefaults() {
#define GSAN_FLAG(Type, Name, DefaultValue, Description) Name = DefaultValue;
#include "gsan_flags.inc"
#undef GSAN_FLAG
}

void RegisterGsanFlags(FlagParser *parser, Flags *f) {
#define GSAN_FLAG(Type, Name, DefaultValue, Description) \
  RegisterFlag(parser, #Name, Description, &f->Name);
#include "gsan_flags.inc"
#undef GSAN_FLAG
}

#define LOG_POINTERS(...)                           \
  do {                                              \
    if (flags()->log_pointers) Report(__VA_ARGS__); \
  } while (0)

#define LOG_THREADS(...)                           \
  do {                                             \
    if (flags()->log_threads) Report(__VA_ARGS__); \
  } while (0)

void InitCommonGsan() {
  InitializePlatformSpecificModules();
}

static void ReportIfNotSuspended(ThreadContextBase *tctx, void *arg) {
  const InternalMmapVector<tid_t> &suspended_threads =
      *(const InternalMmapVector<tid_t> *)arg;
  if (tctx->status == ThreadStatusRunning) {
    uptr i = InternalLowerBound(suspended_threads, tctx->os_id);
    if (i >= suspended_threads.size() || suspended_threads[i] != tctx->os_id)
      Report("Running thread %d was not suspended. False leaks are possible.\n",
             tctx->os_id);
  }
}

#if SANITIZER_FUCHSIA

// Fuchsia provides a libc interface that guarantees all threads are
// covered, and SuspendedThreadList is never really used.
static void ReportUnsuspendedThreads(const SuspendedThreadsList &) {}

#else  // !SANITIZER_FUCHSIA

static void ReportUnsuspendedThreads(
    const SuspendedThreadsList &suspended_threads) {
  InternalMmapVector<tid_t> threads(suspended_threads.ThreadCount());
  for (uptr i = 0; i < suspended_threads.ThreadCount(); ++i)
    threads[i] = suspended_threads.GetThreadID(i);

  Sort(threads.data(), threads.size());

  GetThreadRegistryLocked()->RunCallbackForEachThreadLocked(
      &ReportIfNotSuspended, &threads);
}

#endif  // !SANITIZER_FUCHSIA

} // namespace __gsan

using namespace __gsan;

extern "C" {

SANITIZER_INTERFACE_ATTRIBUTE
void __gsan_disable() {
  __gsan::DisableInThisThread();
}

SANITIZER_INTERFACE_ATTRIBUTE
void __gsan_enable() {
  __gsan::EnableInThisThread();
}

SANITIZER_INTERFACE_WEAK_DEF(const char *, __gsan_default_options, void) {
  return "";
}

#if !SANITIZER_SUPPORTS_WEAK_HOOKS
SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE
int __gsan_is_turned_off() {
  return 0;
}

SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE
const char *__gsan_default_suppressions() {
  return "";
}
#endif
} // extern "C"
