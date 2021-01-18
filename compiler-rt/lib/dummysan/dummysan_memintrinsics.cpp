//===-- dummysan_memintrinsics.cpp --------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file is a part of DummySanitizer and contains DUMMYSAN versions of
/// memset, memcpy and memmove
///
//===----------------------------------------------------------------------===//

#include <string.h>
#include "dummysan.h"
#include "dummysan_checks.h"
#include "dummysan_flags.h"
#include "dummysan_interface_internal.h"
#include "sanitizer_common/sanitizer_libc.h"

using namespace __dummysan;

void *__dummysan_memset(void *block, int c, uptr size) {
  CheckAddressSized<ErrorAction::Recover, AccessType::Store>(
      reinterpret_cast<uptr>(block), size);
  return memset(UntagPtr(block), c, size);
}

void *__dummysan_memcpy(void *to, const void *from, uptr size) {
  CheckAddressSized<ErrorAction::Recover, AccessType::Store>(
      reinterpret_cast<uptr>(to), size);
  CheckAddressSized<ErrorAction::Recover, AccessType::Load>(
      reinterpret_cast<uptr>(from), size);
  return memcpy(UntagPtr(to), UntagPtr(from), size);
}

void *__dummysan_memmove(void *to, const void *from, uptr size) {
  CheckAddressSized<ErrorAction::Recover, AccessType::Store>(
      reinterpret_cast<uptr>(to), size);
  CheckAddressSized<ErrorAction::Recover, AccessType::Load>(
      reinterpret_cast<uptr>(from), size);
  return memmove(UntagPtr(to), UntagPtr(from), size);
}
