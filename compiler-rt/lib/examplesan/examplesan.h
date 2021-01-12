#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "interception/interception.h"
#include "sanitizer_common/sanitizer_platform_interceptors.h"
#include "sanitizer_common/sanitizer_linux.h"

namespace __examplesan {

extern "C" {
void examplesan_AllocateShadowMemory();
void __examplesan_entry();
void __examplesan_exit();
void examplesan_AfterMalloc(char * addr);
}
void * examplesan_Malloc(__sanitizer::uptr size);
void examplesan_InitInterceptors();

}
