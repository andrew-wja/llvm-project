//=-- gsan_fuchsia.h ---------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===---------------------------------------------------------------------===//
//
// This file is a part of GenericSanitizer.
// Standalone GSan RTL code specific to Fuchsia.
//
//===---------------------------------------------------------------------===//

#ifndef GSAN_FUCHSIA_H
#define GSAN_FUCHSIA_H

#include "gsan_thread.h"
#include "sanitizer_common/sanitizer_platform.h"

#if !SANITIZER_FUCHSIA
#error "gsan_fuchsia.h is used only on Fuchsia systems (SANITIZER_FUCHSIA)"
#endif

namespace __gsan {

class ThreadContext final : public ThreadContextGsanBase {
 public:
  explicit ThreadContext(int tid);
  void OnCreated(void *arg) override;
  void OnStarted(void *arg) override;
};

}  // namespace __gsan

#endif  // GSAN_FUCHSIA_H
