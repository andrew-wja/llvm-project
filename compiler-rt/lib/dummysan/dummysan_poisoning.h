//===-- dummysan_poisoning.h --------------------------------------*- C++ -*-===//
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

#ifndef DUMMYSAN_POISONING_H
#define DUMMYSAN_POISONING_H

#include "dummysan.h"

namespace __dummysan {
uptr TagMemory(uptr p, uptr size, tag_t tag);
uptr TagMemoryAligned(uptr p, uptr size, tag_t tag);

}  // namespace __dummysan

#endif  // DUMMYSAN_POISONING_H
