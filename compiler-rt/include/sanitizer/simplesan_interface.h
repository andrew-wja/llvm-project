//===-- sanitizer/simplesan_interface.h ------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of SimpleSanitizer.
//
// Public interface header.
//===----------------------------------------------------------------------===//
#ifndef SANITIZER_SIMPLESAN_INTERFACE_H
#define SANITIZER_SIMPLESAN_INTERFACE_H

#include <sanitizer/common_interface_defs.h>

#ifdef __cplusplus
extern "C" {
#endif

  // This function may be optionally provided by user and should return
  // a string containing default runtime options.
  // See simplesan_flags.h for details.
  const char* __simplesan_default_options(void);

  /* Sets the callback function to be called during error reporting. */
  void __simplesan_set_error_report_callback(void (*callback)(const char *));

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // SANITIZER_SIMPLESAN_INTERFACE_H
