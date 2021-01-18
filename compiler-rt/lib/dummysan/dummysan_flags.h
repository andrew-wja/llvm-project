//===-- dummysan_flags.h ------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DummySanitizer.
//
//===----------------------------------------------------------------------===//
#ifndef DUMMYSAN_FLAGS_H
#define DUMMYSAN_FLAGS_H

namespace __dummysan {

struct Flags {
#define DUMMYSAN_FLAG(Type, Name, DefaultValue, Description) Type Name;
#include "dummysan_flags.inc"
#undef DUMMYSAN_FLAG

  void SetDefaults();
};

Flags *flags();

}  // namespace __dummysan

#endif  // DUMMYSAN_FLAGS_H
