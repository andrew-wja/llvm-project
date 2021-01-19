//===-- simplesan_interceptors.cpp ----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of SimpleSanitizer.
//
// Intercept various libc functions.
//===----------------------------------------------------------------------===//

#include "interception/interception.h"
#include "simplesan.h"
#include "simplesan_interceptors.h"
#include "sanitizer_common/sanitizer_platform_limits_posix.h"
#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_allocator_interface.h"
#include "sanitizer_common/sanitizer_allocator_internal.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_errno.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_linux.h"
#include "sanitizer_common/sanitizer_tls_get_addr.h"

#include <stdarg.h>

#if SANITIZER_LINUX

using namespace __simplesan;

INTERCEPTOR(void, free, void *ptr) {
  simplesan_metadata.free_count += 1;
  REAL(free)(ptr);
}

INTERCEPTOR(void *, malloc, SIZE_T size) {
  simplesan_metadata.malloc_count += 1;
  return REAL(malloc)(size);
}

namespace __simplesan {

void InitializeSimplesanInterceptors() {
  static bool was_called_once;
  CHECK(!was_called_once);
  was_called_once = true;

  INTERCEPT_FUNCTION(free);
  INTERCEPT_FUNCTION(malloc);

  VReport(1, "SimpleSanitizer: libc interceptors initialized\n");
}

}

#endif // SANITIZER_LINUX
