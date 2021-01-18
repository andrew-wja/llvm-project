//===-- dummysan_interface_internal.h -----------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DummySanitizer.
//
// Private Dummysan interface header.
//===----------------------------------------------------------------------===//

#ifndef DUMMYSAN_INTERFACE_INTERNAL_H
#define DUMMYSAN_INTERFACE_INTERNAL_H

#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_platform_limits_posix.h"
#include <link.h>

extern "C" {

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_init_static();

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_init();

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_library_loaded(ElfW(Addr) base, const ElfW(Phdr) * phdr,
                             ElfW(Half) phnum);

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_library_unloaded(ElfW(Addr) base, const ElfW(Phdr) * phdr,
                               ElfW(Half) phnum);

using __sanitizer::uptr;
using __sanitizer::sptr;
using __sanitizer::uu64;
using __sanitizer::uu32;
using __sanitizer::uu16;
using __sanitizer::u64;
using __sanitizer::u32;
using __sanitizer::u16;
using __sanitizer::u8;

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_init_frames(uptr, uptr);

SANITIZER_INTERFACE_ATTRIBUTE
extern uptr __dummysan_shadow_memory_dynamic_address;

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_loadN(uptr, uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_load1(uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_load2(uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_load4(uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_load8(uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_load16(uptr);

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_loadN_noabort(uptr, uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_load1_noabort(uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_load2_noabort(uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_load4_noabort(uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_load8_noabort(uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_load16_noabort(uptr);

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_storeN(uptr, uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_store1(uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_store2(uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_store4(uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_store8(uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_store16(uptr);

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_storeN_noabort(uptr, uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_store1_noabort(uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_store2_noabort(uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_store4_noabort(uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_store8_noabort(uptr);
SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_store16_noabort(uptr);

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_tag_memory(uptr p, u8 tag, uptr sz);

SANITIZER_INTERFACE_ATTRIBUTE
uptr __dummysan_tag_pointer(uptr p, u8 tag);

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_tag_mismatch(uptr addr, u8 ts);

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_tag_mismatch4(uptr addr, uptr access_info, uptr *registers_frame,
                            size_t outsize);

SANITIZER_INTERFACE_ATTRIBUTE
u8 __dummysan_generate_tag();

// Returns the offset of the first tag mismatch or -1 if the whole range is
// good.
SANITIZER_INTERFACE_ATTRIBUTE
sptr __dummysan_test_shadow(const void *x, uptr size);

SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE
/* OPTIONAL */ const char* __dummysan_default_options();

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_print_shadow(const void *x, uptr size);

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_handle_longjmp(const void *sp_dst);

SANITIZER_INTERFACE_ATTRIBUTE
u16 __sanitizer_unaligned_load16(const uu16 *p);

SANITIZER_INTERFACE_ATTRIBUTE
u32 __sanitizer_unaligned_load32(const uu32 *p);

SANITIZER_INTERFACE_ATTRIBUTE
u64 __sanitizer_unaligned_load64(const uu64 *p);

SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_unaligned_store16(uu16 *p, u16 x);

SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_unaligned_store32(uu32 *p, u32 x);

SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_unaligned_store64(uu64 *p, u64 x);

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_enable_allocator_tagging();

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_disable_allocator_tagging();

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_thread_enter();

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_thread_exit();

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_print_memory_usage();

SANITIZER_INTERFACE_ATTRIBUTE
int __sanitizer_posix_memalign(void **memptr, uptr alignment, uptr size);

SANITIZER_INTERFACE_ATTRIBUTE
void * __sanitizer_memalign(uptr alignment, uptr size);

SANITIZER_INTERFACE_ATTRIBUTE
void * __sanitizer_aligned_alloc(uptr alignment, uptr size);

SANITIZER_INTERFACE_ATTRIBUTE
void * __sanitizer___libc_memalign(uptr alignment, uptr size);

SANITIZER_INTERFACE_ATTRIBUTE
void * __sanitizer_valloc(uptr size);

SANITIZER_INTERFACE_ATTRIBUTE
void * __sanitizer_pvalloc(uptr size);

SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_free(void *ptr);

SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_cfree(void *ptr);

SANITIZER_INTERFACE_ATTRIBUTE
uptr __sanitizer_malloc_usable_size(const void *ptr);

SANITIZER_INTERFACE_ATTRIBUTE
__dummysan::__sanitizer_struct_mallinfo __sanitizer_mallinfo();

SANITIZER_INTERFACE_ATTRIBUTE
int __sanitizer_mallopt(int cmd, int value);

SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_malloc_stats(void);

SANITIZER_INTERFACE_ATTRIBUTE
void * __sanitizer_calloc(uptr nmemb, uptr size);

SANITIZER_INTERFACE_ATTRIBUTE
void * __sanitizer_realloc(void *ptr, uptr size);

SANITIZER_INTERFACE_ATTRIBUTE
void * __sanitizer_reallocarray(void *ptr, uptr nmemb, uptr size);

SANITIZER_INTERFACE_ATTRIBUTE
void * __sanitizer_malloc(uptr size);

SANITIZER_INTERFACE_ATTRIBUTE
void *__dummysan_memcpy(void *dst, const void *src, uptr size);
SANITIZER_INTERFACE_ATTRIBUTE
void *__dummysan_memset(void *s, int c, uptr n);
SANITIZER_INTERFACE_ATTRIBUTE
void *__dummysan_memmove(void *dest, const void *src, uptr n);

SANITIZER_INTERFACE_ATTRIBUTE
void __dummysan_set_error_report_callback(void (*callback)(const char *));
}  // extern "C"

#endif  // DUMMYSAN_INTERFACE_INTERNAL_H
