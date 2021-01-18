#include "dummysan_thread_list.h"

namespace __dummysan {
static ALIGNED(16) char thread_list_placeholder[sizeof(DummysanThreadList)];
static DummysanThreadList *dummysan_thread_list;

DummysanThreadList &dummysanThreadList() { return *dummysan_thread_list; }

void InitThreadList(uptr storage, uptr size) {
  CHECK(dummysan_thread_list == nullptr);
  dummysan_thread_list =
      new (thread_list_placeholder) DummysanThreadList(storage, size);
}

} // namespace
