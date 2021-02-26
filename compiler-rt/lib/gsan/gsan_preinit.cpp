//===-- gsan_preinit.cpp --------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of GenericSanitizer.
//
// Call __gsan_init at the very early stage of process startup.
//===----------------------------------------------------------------------===//

#include "gsan.h"

#if SANITIZER_CAN_USE_PREINIT_ARRAY
  // We force __gsan_init to be called before anyone else by placing it into
  // .preinit_array section.
  __attribute__((section(".preinit_array"), used))
  void (*__local_gsan_preinit)(void) = __gsan_init;
#endif
