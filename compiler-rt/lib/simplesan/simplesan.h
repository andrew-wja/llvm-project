//===-- simplesan.h ------------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of SimpleSanitizer.
//
// Private Simplesan header.
//===----------------------------------------------------------------------===//

#ifndef SIMPLESAN_H
#define SIMPLESAN_H

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "simplesan_flags.h"

namespace __simplesan {

extern int simplesan_inited;
extern bool simplesan_init_is_running;

static struct {
  u64 malloc_count;
  u64 free_count;
  u64 read_count;
  u64 write_count;
} simplesan_metadata;

#define GET_FATAL_STACK_TRACE_PC_BP(pc, bp)              \
  BufferedStackTrace stack;                              \
  if (simplesan_inited)                                     \
    stack.Unwind(pc, bp, nullptr, common_flags()->fast_unwind_on_fatal)

#define GET_FATAL_STACK_TRACE_HERE \
  GET_FATAL_STACK_TRACE_PC_BP(StackTrace::GetCurrentPc(), GET_CURRENT_FRAME())

#define PRINT_CURRENT_STACK_CHECK() \
  {                                 \
    GET_FATAL_STACK_TRACE_HERE;     \
    stack.Print();                  \
  }

extern "C" {

SANITIZER_INTERFACE_ATTRIBUTE
void __simplesan_atexit();

SANITIZER_INTERFACE_ATTRIBUTE
void __simplesan_init();

} // extern "C"

void SimplesanOnDeadlySignal(int signo, void *info, void *context);

// Forward declarations

void __sanitizer_free(void *ptr);
void * __sanitizer_malloc(uptr size);

}  // namespace __simplesan

#endif  // SIMPLESAN_H
