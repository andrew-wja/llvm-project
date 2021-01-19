//===-- simplesan_interceptors.h --------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of SimpleSanitizer.
//
//===----------------------------------------------------------------------===//
#ifndef SIMPLESAN_INTERCEPTORS_H
#define SIMPLESAN_INTERCEPTORS_H

#include "simplesan.h"
#include "interception/interception.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_linux.h"
#include "sanitizer_common/sanitizer_platform.h"
#include "sanitizer_common/sanitizer_platform_interceptors.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
// TODO: start using the common interceptor infrastructure
// #include "sanitizer_common/sanitizer_common_interceptors.inc"

#if SANITIZER_LINUX

#if SANITIZER_POSIX
#include "sanitizer_common/sanitizer_posix.h"
#endif

namespace __simplesan {

void InitializeSimplesanInterceptors();

// This is here (as opposed to in simplesan.h) because interceptors *must* be
// set up before anything else has a chance to call functions that we might
// want to intercept.

#define ENSURE_SIMPLESAN_INITED()      \
  do {                                 \
    CHECK(!simplesan_init_is_running); \
    if (UNLIKELY(!simplesan_inited)) { \
      __simplesan_init();              \
    }                                  \
  } while (0)

}  // namespace __simplesan

#endif // SANITIZER_LINUX

#endif // SIMPLESAN_INTERCEPTORS_H
