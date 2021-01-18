//===-- dummysan_globals.h ----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DummySanitizer.
//
// Private Dummysan header.
//===----------------------------------------------------------------------===//

#ifndef DUMMYSAN_GLOBALS_H
#define DUMMYSAN_GLOBALS_H

#include <link.h>

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"

namespace __dummysan {
// This object should only ever be casted over the global (i.e. not constructed)
// in the ELF PT_NOTE in order for `addr()` to work correctly.
struct dummysan_global {
  // The size of this global variable. Note that the size in the descriptor is
  // max 1 << 24. Larger globals have multiple descriptors.
  uptr size() const { return info & 0xffffff; }
  // The fully-relocated address of this global.
  uptr addr() const { return reinterpret_cast<uintptr_t>(this) + gv_relptr; }
  // The static tag of this global.
  u8 tag() const { return info >> 24; };

  // The relative address between the start of the descriptor for the Dummysan
  // global (in the PT_NOTE), and the fully relocated address of the global.
  s32 gv_relptr;
  u32 info;
};

// Walk through the specific DSO (as specified by the base, phdr, and phnum),
// and return the range of the [beginning, end) of the Dummysan globals descriptor
// array.
ArrayRef<const dummysan_global> DummysanGlobalsFor(ElfW(Addr) base,
                                               const ElfW(Phdr) * phdr,
                                               ElfW(Half) phnum);

}  // namespace __dummysan

#endif  // DUMMYSAN_GLOBALS_H
