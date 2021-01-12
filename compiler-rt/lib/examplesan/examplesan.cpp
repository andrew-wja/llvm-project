#include "examplesan/examplesan.h"
#include <unistd.h>


using namespace __sanitizer;

INTERCEPTOR(void *, malloc, uptr size) {
  return __examplesan::examplesan_Malloc(size);
}

void NOINLINE __examplesan::examplesan_InitInterceptors() {
  INTERCEPT_FUNCTION(malloc);
}

namespace __examplesan {

static struct {
  int count;
} metadata;

}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void NOINLINE __examplesan::__examplesan_entry() {
  Printf("Examplesan: entry\n");
  return;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void NOINLINE __examplesan::__examplesan_hello() {
  Printf("Examplesan: hello!\n");
  return;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void NOINLINE __examplesan::__examplesan_exit() {
  Printf("Examplesan: exit\n");
  Printf("Saw %g malloc calls\n", metadata.count);
  return;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void NOINLINE examplesan_Init() __attribute__((constructor(0))) {
  //Set sanitizer tool name, not required.
  SanitizerToolName = "examplesan";

  //Sanitizers have a lot of flags (sanitizer_flags.inc)
  SetCommonFlagsDefaults();

  __examplesan::examplesan_InitInterceptors();

  metadata.count = 0;

  VReport(2, "Initialized examplesan runtime!\n");
}

// Interceptor implementations

void * NOINLINE __examplesan::examplesan_Malloc(uptr size) {
  void * ret = REAL(malloc)(size);
  Printf("Examplesan: malloc\n");
  metadata.count += 1;
  return ret;
}
