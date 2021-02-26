//=-- gsan_common_linux.cpp -----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of GenericSanitizer.
// Implementation of common leak checking functionality. Linux/NetBSD-specific
// code.
//
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_platform.h"
#include "gsan_common.h"

#if (SANITIZER_LINUX || SANITIZER_NETBSD)
#include <link.h>

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_getauxval.h"
#include "sanitizer_common/sanitizer_linux.h"
#include "sanitizer_common/sanitizer_stackdepot.h"

namespace __gsan {

static const char kLinkerName[] = "ld";

static char linker_placeholder[sizeof(LoadedModule)] ALIGNED(64);
static LoadedModule *linker = nullptr;

static bool IsLinker(const LoadedModule& module) {
#if SANITIZER_USE_GETAUXVAL
  return module.base_address() == getauxval(AT_BASE);
#else
  return LibraryNameIs(module.full_name(), kLinkerName);
#endif  // SANITIZER_USE_GETAUXVAL
}

__attribute__((tls_model("initial-exec")))
THREADLOCAL int disable_counter;
bool DisabledInThisThread() { return disable_counter > 0; }
void DisableInThisThread() { disable_counter++; }
void EnableInThisThread() {
  if (disable_counter == 0) {
    DisableCounterUnderflow();
  }
  disable_counter--;
}

void InitializePlatformSpecificModules() {
  ListOfModules modules;
  modules.init();
  for (LoadedModule &module : modules) {
    if (!IsLinker(module))
      continue;
    if (linker == nullptr) {
      linker = reinterpret_cast<LoadedModule *>(linker_placeholder);
      *linker = module;
      module = LoadedModule();
    } else {
      VReport(1, "GenericSanitizer: Multiple modules match \"%s\". "
              "TLS and other allocations originating from linker might be "
              "falsely reported as leaks.\n", kLinkerName);
      linker->clear();
      linker = nullptr;
      return;
    }
  }
  if (linker == nullptr) {
    VReport(1, "GenericSanitizer: Dynamic linker not found. TLS and other "
               "allocations originating from linker might be falsely reported "
                "as leaks.\n");
  }
}

#if SANITIZER_ANDROID && __ANDROID_API__ < 21
extern "C" __attribute__((weak)) int dl_iterate_phdr(
    int (*)(struct dl_phdr_info *, size_t, void *), void *);
#endif

LoadedModule *GetLinker() { return linker; }

} // namespace __gsan

#endif // (SANITIZER_LINUX || SANITIZER_NETBSD)
