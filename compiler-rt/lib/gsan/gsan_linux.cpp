//=-- gsan_linux.cpp ------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of GenericSanitizer. Linux/NetBSD/Fuchsia-specific code.
//
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_platform.h"

#if SANITIZER_LINUX || SANITIZER_NETBSD || SANITIZER_FUCHSIA

#include "gsan_allocator.h"

namespace __gsan {

static THREADLOCAL u32 current_thread_tid = kInvalidTid;
u32 GetCurrentThread() { return current_thread_tid; }
void SetCurrentThread(u32 tid) { current_thread_tid = tid; }

#if defined(GSAN_USE_SANITIZER_ALLOCATOR)
static THREADLOCAL AllocatorCache allocator_cache;
AllocatorCache *GetAllocatorCache() { return &allocator_cache; }
#endif // GSAN_USE_SANITIZER_ALLOCATOR
void ReplaceSystemMalloc() {}

} // namespace __gsan

#endif  // SANITIZER_LINUX || SANITIZER_NETBSD || SANITIZER_FUCHSIA
