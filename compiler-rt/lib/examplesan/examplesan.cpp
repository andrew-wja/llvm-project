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
  int size;
  char * start;
  char * end;
} metadata;

}

void NOINLINE __examplesan::examplesan_AllocateShadowMemory() {
  metadata.size = 1000 * sizeof(*metadata.start);
  metadata.start = (char*)MmapNoReserveOrDie(metadata.size, "Simple Shadow Memory");
  metadata.end = metadata.start + metadata.size;

  VReport(1, "Shadow mem at %zx .. %zx\n", metadata.start, metadata.start + metadata.size);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void NOINLINE __examplesan::examplesan_AfterMalloc(char * value) {
  //Printf is sanitizer internal printf
  Printf("Malloc returned address %x\n", value);
  return;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void NOINLINE __examplesan::__examplesan_entry() {
  Printf("Examplesan: entry\n");
  return;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void NOINLINE __examplesan::__examplesan_exit() {
  Printf("Examplesan: exit\n");
  return;
}

void * NOINLINE __examplesan::examplesan_Malloc(uptr size) {
  //This is how you call real malloc
  //~ void * ret = REAL(malloc)(size);
  write(1, "Hooked malloc!\n", internal_strlen("Hooked malloc!\n"));
  //You don't have to return the real address, but program will crash
  return (void*)0xdeadbeef;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void NOINLINE examplesan_Init() __attribute__((constructor(0))) {
  //Set sanitizer tool name, not required.
  SanitizerToolName = "examplesan";

  //Sanitizers have a lot of flags (sanitizer_flags.inc)
  SetCommonFlagsDefaults();

  __examplesan::examplesan_InitInterceptors();

  //Try to allocate shadowmem, have it store 500 elements.
  __examplesan::examplesan_AllocateShadowMemory();
  VReport(2, "Initialized examplesan runtime!\n");
}
