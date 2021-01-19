//===-- simplesan_flags.h ---------------------------------------*- C++ -*-===//
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
#ifndef SIMPLESAN_FLAGS_H
#define SIMPLESAN_FLAGS_H

namespace __simplesan {

struct Flags {
#define SIMPLESAN_FLAG(Type, Name, DefaultValue, Description) Type Name;
#include "simplesan_flags.inc"
#undef SIMPLESAN_FLAG

  void SetDefaults();
};

Flags *flags();

}  // namespace __simplesan

#endif  // SIMPLESAN_FLAGS_H
