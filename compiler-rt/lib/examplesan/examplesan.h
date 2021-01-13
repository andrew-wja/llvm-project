#ifndef EXAMPLESAN_H
#define EXAMPLESAN_H

#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_allocator_checks.h"
#include "sanitizer_common/sanitizer_allocator_interface.h"
#include "sanitizer_common/sanitizer_allocator_report.h"
#include "sanitizer_common/sanitizer_common.h"

#include "interception/interception.h"
#include "sanitizer_common/sanitizer_platform_interceptors.h"
#include "sanitizer_common/sanitizer_linux.h"

namespace __examplesan {

extern "C" {
void __examplesan_init();
void __examplesan_exit();
}
void examplesan_malloc_hook(const void* ptr, __sanitizer::uptr size);
void examplesan_free_hook(const void * ptr);
}

#endif // EXAMPLESAN_H
