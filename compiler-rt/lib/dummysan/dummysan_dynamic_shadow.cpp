//===-- dummysan_dynamic_shadow.cpp -------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file is a part of DummySanitizer. It reserves dynamic shadow memory
/// region and handles ifunc resolver case, when necessary.
///
//===----------------------------------------------------------------------===//

#include "dummysan.h"
#include "dummysan_dynamic_shadow.h"
#include "dummysan_mapping.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_posix.h"

#include <elf.h>
#include <link.h>

// The code in this file needs to run in an unrelocated binary. It should not
// access any external symbol, including its own non-hidden globals.

#if SANITIZER_ANDROID
extern "C" {

INTERFACE_ATTRIBUTE void __dummysan_shadow();
decltype(__dummysan_shadow)* __dummysan_premap_shadow();

}  // extern "C"

namespace __dummysan {

// Conservative upper limit.
static uptr PremapShadowSize() {
  return RoundUpTo(GetMaxVirtualAddress() >> kShadowScale,
                   GetMmapGranularity());
}

static uptr PremapShadow() {
  return MapDynamicShadow(PremapShadowSize(), kShadowScale,
                          kShadowBaseAlignment, kHighMemEnd);
}

static bool IsPremapShadowAvailable() {
  const uptr shadow = reinterpret_cast<uptr>(&__dummysan_shadow);
  const uptr resolver = reinterpret_cast<uptr>(&__dummysan_premap_shadow);
  // shadow == resolver is how Android KitKat and older handles ifunc.
  // shadow == 0 just in case.
  return shadow != 0 && shadow != resolver;
}

static uptr FindPremappedShadowStart(uptr shadow_size_bytes) {
  const uptr granularity = GetMmapGranularity();
  const uptr shadow_start = reinterpret_cast<uptr>(&__dummysan_shadow);
  const uptr premap_shadow_size = PremapShadowSize();
  const uptr shadow_size = RoundUpTo(shadow_size_bytes, granularity);

  // We may have mapped too much. Release extra memory.
  UnmapFromTo(shadow_start + shadow_size, shadow_start + premap_shadow_size);
  return shadow_start;
}

}  // namespace __dummysan

extern "C" {

decltype(__dummysan_shadow)* __dummysan_premap_shadow() {
  // The resolver might be called multiple times. Map the shadow just once.
  static __sanitizer::uptr shadow = 0;
  if (!shadow)
    shadow = __dummysan::PremapShadow();
  return reinterpret_cast<decltype(__dummysan_shadow)*>(shadow);
}

// __dummysan_shadow is a "function" that has the same address as the first byte
// of the shadow mapping.
INTERFACE_ATTRIBUTE __attribute__((ifunc("__dummysan_premap_shadow")))
void __dummysan_shadow();

extern __attribute((weak, visibility("hidden"))) ElfW(Rela) __rela_iplt_start[],
    __rela_iplt_end[];

}  // extern "C"

namespace __dummysan {

void InitShadowGOT() {
  // Call the ifunc resolver for __dummysan_shadow and fill in its GOT entry. This
  // needs to be done before other ifunc resolvers (which are handled by libc)
  // because a resolver might read __dummysan_shadow.
  typedef ElfW(Addr) (*ifunc_resolver_t)(void);
  for (ElfW(Rela) *r = __rela_iplt_start; r != __rela_iplt_end; ++r) {
    ElfW(Addr)* offset = reinterpret_cast<ElfW(Addr)*>(r->r_offset);
    ElfW(Addr) resolver = r->r_addend;
    if (resolver == reinterpret_cast<ElfW(Addr)>(&__dummysan_premap_shadow)) {
      *offset = reinterpret_cast<ifunc_resolver_t>(resolver)();
      break;
    }
  }
}

uptr FindDynamicShadowStart(uptr shadow_size_bytes) {
  if (IsPremapShadowAvailable())
    return FindPremappedShadowStart(shadow_size_bytes);
  return MapDynamicShadow(shadow_size_bytes, kShadowScale, kShadowBaseAlignment,
                          kHighMemEnd);
}

}  // namespace __dummysan
#else
namespace __dummysan {

void InitShadowGOT() {}

uptr FindDynamicShadowStart(uptr shadow_size_bytes) {
  return MapDynamicShadow(shadow_size_bytes, kShadowScale, kShadowBaseAlignment,
                          kHighMemEnd);
}

}  // namespace __dummysan

#endif  // SANITIZER_ANDROID
