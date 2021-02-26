//=-- gsan_common_fuchsia.cpp --------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===---------------------------------------------------------------------===//
//
// This file is a part of GenericSanitizer.
// Implementation of common leak checking functionality. Fuchsia-specific code.
//
//===---------------------------------------------------------------------===//

#include "gsan_common.h"
#include "sanitizer_common/sanitizer_platform.h"

#if SANITIZER_FUCHSIA
#include <zircon/sanitizer.h>

#include "gsan_allocator.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_stoptheworld_fuchsia.h"
#include "sanitizer_common/sanitizer_thread_registry.h"

// Ensure that the Zircon system ABI is linked in.
#pragma comment(lib, "zircon")

namespace __gsan {

void InitializePlatformSpecificModules() {}

LoadedModule *GetLinker() { return nullptr; }

__attribute__((tls_model("initial-exec"))) THREADLOCAL int disable_counter;
bool DisabledInThisThread() { return disable_counter > 0; }
void DisableInThisThread() { disable_counter++; }
void EnableInThisThread() {
  if (disable_counter == 0) {
    DisableCounterUnderflow();
  }
  disable_counter--;
}

}  // namespace __gsan

// This is declared (in extern "C") by <zircon/sanitizer.h>.
// _Exit calls this directly to intercept and change the status value.
int __sanitizer_process_exit_hook(int status) {
  return __gsan::ExitHook(status);
}

#endif // SANITIZER_FUSCHIA
