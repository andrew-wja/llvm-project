//===-- simplesan.cpp --------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of SimpleSanitizer.
//
// SimpleSanitizer runtime.
//===----------------------------------------------------------------------===//

#include "simplesan.h"
#include "simplesan_interceptors.h"
#include <signal.h>

#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_procmaps.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_symbolizer.h"

#include <sys/ucontext.h>
#include <link.h>
extern ElfW(Dyn) _DYNAMIC[];

using namespace __sanitizer;

namespace __simplesan {

static Flags simplesan_flags;

Flags *flags() {
  return &simplesan_flags;
}

int simplesan_inited = 0;
int simplesan_instrumentation_inited = 0;
bool simplesan_init_is_running;

void Flags::SetDefaults() {
#define SIMPLESAN_FLAG(Type, Name, DefaultValue, Description) Name = DefaultValue;
#include "simplesan_flags.inc"
#undef SIMPLESAN_FLAG
}

static void RegisterSimplesanFlags(FlagParser *parser, Flags *f) {
#define SIMPLESAN_FLAG(Type, Name, DefaultValue, Description) \
  RegisterFlag(parser, #Name, Description, &f->Name);
#include "simplesan_flags.inc"
#undef SIMPLESAN_FLAG
}

static void InitializeFlags() {
  SetCommonFlagsDefaults();
  {
    CommonFlags cf;
    cf.CopyFrom(*common_flags());
    cf.external_symbolizer_path = GetEnv("SIMPLESAN_SYMBOLIZER_PATH");
    // Sigtrap is used in error reporting.
    cf.handle_sigtrap = kHandleSignalExclusive;
    OverrideCommonFlags(cf);
  }

  Flags *f = flags();
  f->SetDefaults();

  FlagParser parser;
  RegisterSimplesanFlags(&parser, f);
  RegisterCommonFlags(&parser);

  parser.ParseStringFromEnv("SIMPLESAN_OPTIONS");

  InitializeCommonFlags();

  if (Verbosity()) ReportUnrecognizedFlags();

  if (common_flags()->help) parser.PrintFlagDescriptions();
}

static void SimplesanCheckFailed(const char *file, int line, const char *cond,
                              u64 v1, u64 v2) {
  Report("SimpleSanitizer CHECK failed: %s:%d \"%s\" (0x%zx, 0x%zx)\n", file,
         line, cond, (uptr)v1, (uptr)v2);
  PRINT_CURRENT_STACK_CHECK();
  Die();
}

static bool SimplesanOnSIGTRAP(int signo, siginfo_t *info, ucontext_t *uc) {
  SignalContext sig{info, uc};
  // Handle things here
  // return false for unhandled to fall through to the next signal handler
  return true;
}

static void OnStackUnwind(const SignalContext &sig, const void *,
                          BufferedStackTrace *stack) {
  stack->Unwind(StackTrace::GetNextInstructionPc(sig.pc), sig.bp, sig.context,
                common_flags()->fast_unwind_on_fatal);
}

void SimplesanOnDeadlySignal(int signo, void *info, void *context) {
  if (signo == SIGTRAP)
    if (SimplesanOnSIGTRAP(signo, (siginfo_t *)info, (ucontext_t*)context))
      return;

  HandleDeadlySignal(info, context, GetTid(), &OnStackUnwind, nullptr);
}

void *CheckNoStaticLinkage() {
  // This will fail to link with -static.
  return &_DYNAMIC;
}

static void SimplesanDie() {
  static atomic_uint32_t num_calls;
  if (atomic_fetch_add(&num_calls, 1, memory_order_relaxed) != 0) {
    // Don't die twice - run a busy loop.
    while (1) { }
  }
}

} // namespace __simplesan

using namespace __simplesan;

void __sanitizer::BufferedStackTrace::UnwindImpl(
    uptr pc, uptr bp, void *context, bool request_fast, u32 max_depth) {
  return;
}

// Prepare to run instrumented code on the main thread.
static void InitInstrumentation() {
  if (simplesan_instrumentation_inited) {
    return;
  } else {
    simplesan_metadata.malloc_count = 0;
    simplesan_metadata.free_count = 0;
    simplesan_metadata.read_count = 0;
    simplesan_metadata.write_count = 0;
    simplesan_instrumentation_inited = 1;
  }
}

static void SimplesanInitInternal() {
  if (LIKELY(simplesan_inited)) return;
  SanitizerToolName = "SimpleSanitizer";
  CHECK(!simplesan_init_is_running);
  simplesan_init_is_running = 1;

  CacheBinaryName();

  // Initialize flags. This must be done early, because most of the
  // initialization steps look at flags().
  InitializeFlags();

  // Make sure we are not statically linked.
  CheckNoStaticLinkage();

  // Install tool-specific callbacks in sanitizer_common.
  AddDieCallback(SimplesanDie);
  SetCheckFailedCallback(SimplesanCheckFailed);

  __sanitizer_set_report_path(common_flags()->log_path);

  __sanitizer::InitializePlatformEarly();

  InitializeSimplesanInterceptors();

  DisableCoreDumperIfNecessary();

  InstallDeadlySignalHandlers(SimplesanOnDeadlySignal);

  // Initialize our instrumentation data
  InitInstrumentation();

  simplesan_inited = 1;
  simplesan_init_is_running = 0;

  if (flags()->atexit)
    Atexit(__simplesan_atexit);

  InitializeCoverage(common_flags()->coverage, common_flags()->coverage_dir);

  SanitizerInitializeUnwinder();

  VPrintf(1, "SimpleSanitizer init done\n");
}

extern "C" {

SANITIZER_INTERFACE_ATTRIBUTE __attribute__((constructor(0)))
void __simplesan_init() {
  SimplesanInitInternal();
}

SANITIZER_INTERFACE_ATTRIBUTE
void NOINLINE __simplesan_read() {
  simplesan_metadata.read_count += 1;
}

SANITIZER_INTERFACE_ATTRIBUTE
void NOINLINE __simplesan_write() {
  simplesan_metadata.write_count += 1;
}

SANITIZER_INTERFACE_ATTRIBUTE
void NOINLINE __simplesan_atexit() {
  Printf("Simplesan: saw %d malloc calls, %d free calls, %d memory reads, %d memory writes\n",
         simplesan_metadata.malloc_count, simplesan_metadata.free_count,
         simplesan_metadata.read_count, simplesan_metadata.write_count);
  return;
}

} // extern "C"

#if !SANITIZER_SUPPORTS_WEAK_HOOKS
extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE
const char* __simplesan_default_options() { return ""; }
}  // extern "C"
#endif

extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_print_stack_trace() {
  GET_FATAL_STACK_TRACE_PC_BP(StackTrace::GetCurrentPc(), GET_CURRENT_FRAME());
  stack.Print();
}
} // extern "C"
