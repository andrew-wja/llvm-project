#include "examplesan/examplesan.h"

using namespace __sanitizer;

// This example sanitizer tracks the number of times malloc() was called
namespace __examplesan {

static struct {
  int count;
} metadata;

}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void NOINLINE __examplesan::__examplesan_init() {
  Printf("Examplesan: init\n");
  //Set sanitizer tool name, not required.
  SanitizerToolName = "examplesan";

  //Sanitizers have a lot of flags (sanitizer_flags.inc)
  SetCommonFlagsDefaults();

  __examplesan::metadata.count = 0;

  __sanitizer_install_malloc_and_free_hooks(&__examplesan::examplesan_malloc_hook,
                                            &__examplesan::examplesan_free_hook);

  VReport(2, "Initialized examplesan runtime!\n");
  return;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void NOINLINE __examplesan::__examplesan_exit() {
  Printf("Examplesan: exit\n");
  Printf("Saw %d malloc calls\n", metadata.count);
  return;
}

void NOINLINE __examplesan::examplesan_malloc_hook(const void* ptr, uptr size) {
  __examplesan::metadata.count += 1;
  return;
}

void NOINLINE __examplesan::examplesan_free_hook(const void *ptr) {
  return;
}
