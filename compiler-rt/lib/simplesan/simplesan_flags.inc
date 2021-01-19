//===-- simplesan_flags.inc -------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Simplesan runtime flags.
//
//===----------------------------------------------------------------------===//
#ifndef SIMPLESAN_FLAG
# error "Define SIMPLESAN_FLAG prior to including this file!"
#endif

// SIMPLESAN_FLAG(Type, Name, DefaultValue, Description)
// See COMMON_FLAG in sanitizer_flags.inc for more details.

SIMPLESAN_FLAG(bool, halt_on_error, true, "")
SIMPLESAN_FLAG(bool, atexit, false, "")
