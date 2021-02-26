//=-- gsan.cpp ------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of GenericSanitizer.
// Standalone GSan RTL.
//
//===----------------------------------------------------------------------===//

#include "gsan.h"

#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "gsan_allocator.h"
#include "gsan_common.h"
#include "gsan_thread.h"

bool gsan_inited;
bool gsan_init_is_running;

namespace __gsan {

///// Interface to the common GSan module. /////
bool WordIsPoisoned(uptr addr) {
  return false;
}

}  // namespace __gsan

void __sanitizer::BufferedStackTrace::UnwindImpl(
    uptr pc, uptr bp, void *context, bool request_fast, u32 max_depth) {
  using namespace __gsan;
  uptr stack_top = 0, stack_bottom = 0;
  ThreadContext *t;
  if (StackTrace::WillUseFastUnwind(request_fast) &&
      (t = CurrentThreadContext())) {
    stack_top = t->stack_end();
    stack_bottom = t->stack_begin();
  }
  if (!SANITIZER_MIPS || IsValidFrame(bp, stack_top, stack_bottom)) {
    if (StackTrace::WillUseFastUnwind(request_fast))
      Unwind(max_depth, pc, bp, nullptr, stack_top, stack_bottom, true);
    else
      Unwind(max_depth, pc, 0, context, 0, 0, false);
  }
}

using namespace __gsan;

static void InitializeFlags() {
  // Set all the default values.
  SetCommonFlagsDefaults();
  {
    CommonFlags cf;
    cf.CopyFrom(*common_flags());
    cf.external_symbolizer_path = GetEnv("GSAN_SYMBOLIZER_PATH");
    // what is this?
    cf.malloc_context_size = 30;
    // what is this?
    cf.intercept_tls_get_addr = true;
    // what is this?
    cf.exitcode = 23;
    OverrideCommonFlags(cf);
  }

  Flags *f = flags();
  f->SetDefaults();

  FlagParser parser;
  RegisterGsanFlags(&parser, f);
  RegisterCommonFlags(&parser);

  // Override from user-specified string.
  const char *gsan_default_options = __gsan_default_options();
  parser.ParseString(gsan_default_options);
  parser.ParseStringFromEnv("GSAN_OPTIONS");

  InitializeCommonFlags();

  if (Verbosity()) ReportUnrecognizedFlags();

  if (common_flags()->help) parser.PrintFlagDescriptions();

  __sanitizer_set_report_path(common_flags()->log_path);
}

extern "C" void __gsan_init() {
  CHECK(!gsan_init_is_running);
  if (gsan_inited)
    return;
  gsan_init_is_running = true;
  SanitizerToolName = "GenericSanitizer";
  CacheBinaryName();
  AvoidCVE_2016_2143();
  InitializeFlags();
  InitCommonGsan();
#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
  InitializeAllocator();
  ReplaceSystemMalloc();
#endif
  InitializeInterceptors();
  InitializeThreadRegistry();
#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
  InstallDeadlySignalHandlers(GsanOnDeadlySignal);
#endif
  InitializeMainThread();

  InitializeCoverage(common_flags()->coverage, common_flags()->coverage_dir);

  gsan_inited = true;
  gsan_init_is_running = false;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_print_stack_trace() {
  GET_STACK_TRACE_FATAL;
  stack.Print();
}
