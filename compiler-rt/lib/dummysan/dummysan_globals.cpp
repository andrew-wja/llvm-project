//===-- dummysan_globals.cpp ------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DummySanitizer.
//
// DummySanitizer globals-specific runtime.
//===----------------------------------------------------------------------===//

#include "dummysan_globals.h"

namespace __dummysan {

enum { NT_LLVM_DUMMYSAN_GLOBALS = 3 };
struct dummysan_global_note {
  s32 begin_relptr;
  s32 end_relptr;
};

// Check that the given library meets the code model requirements for tagged
// globals. These properties are not checked at link time so they need to be
// checked at runtime.
static void CheckCodeModel(ElfW(Addr) base, const ElfW(Phdr) * phdr,
                           ElfW(Half) phnum) {
  ElfW(Addr) min_addr = -1ull, max_addr = 0;
  for (unsigned i = 0; i != phnum; ++i) {
    if (phdr[i].p_type != PT_LOAD)
      continue;
    ElfW(Addr) lo = base + phdr[i].p_vaddr, hi = lo + phdr[i].p_memsz;
    if (min_addr > lo)
      min_addr = lo;
    if (max_addr < hi)
      max_addr = hi;
  }

  if (max_addr - min_addr > 1ull << 32) {
    Report("FATAL: DummySanitizer: library size exceeds 2^32\n");
    Die();
  }
  if (max_addr > 1ull << 48) {
    Report("FATAL: DummySanitizer: library loaded above address 2^48\n");
    Die();
  }
}

ArrayRef<const dummysan_global> DummysanGlobalsFor(ElfW(Addr) base,
                                               const ElfW(Phdr) * phdr,
                                               ElfW(Half) phnum) {
  // Read the phdrs from this DSO.
  for (unsigned i = 0; i != phnum; ++i) {
    if (phdr[i].p_type != PT_NOTE)
      continue;

    const char *note = reinterpret_cast<const char *>(base + phdr[i].p_vaddr);
    const char *nend = note + phdr[i].p_memsz;

    // Traverse all the notes until we find a Dummysan note.
    while (note < nend) {
      auto *nhdr = reinterpret_cast<const ElfW(Nhdr) *>(note);
      const char *name = note + sizeof(ElfW(Nhdr));
      const char *desc = name + RoundUpTo(nhdr->n_namesz, 4);

      // Discard non-Dummysan-Globals notes.
      if (nhdr->n_type != NT_LLVM_DUMMYSAN_GLOBALS ||
          internal_strcmp(name, "LLVM") != 0) {
        note = desc + RoundUpTo(nhdr->n_descsz, 4);
        continue;
      }

      // Only libraries with instrumented globals need to be checked against the
      // code model since they use relocations that aren't checked at link time.
      CheckCodeModel(base, phdr, phnum);

      auto *global_note = reinterpret_cast<const dummysan_global_note *>(desc);
      auto *globals_begin = reinterpret_cast<const dummysan_global *>(
          note + global_note->begin_relptr);
      auto *globals_end = reinterpret_cast<const dummysan_global *>(
          note + global_note->end_relptr);

      return {globals_begin, globals_end};
    }
  }

  return {};
}

}  // namespace __dummysan
