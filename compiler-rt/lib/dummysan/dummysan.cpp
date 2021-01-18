//===-- dummysan.cpp --------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DummySanitizer.
//
// DummySanitizer runtime.
//===----------------------------------------------------------------------===//

#include "dummysan.h"

#include "dummysan_checks.h"
#include "dummysan_dynamic_shadow.h"
#include "dummysan_globals.h"
#include "dummysan_poisoning.h"
#include "dummysan_report.h"
#include "dummysan_thread.h"
#include "dummysan_thread_list.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_procmaps.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_symbolizer.h"
#include "ubsan/ubsan_flags.h"
#include "ubsan/ubsan_init.h"

// ACHTUNG! No system header includes in this file.

using namespace __sanitizer;

namespace __dummysan {

static Flags dummysan_flags;

Flags *flags() {
  return &dummysan_flags;
}

int dummysan_inited = 0;
int dummysan_instrumentation_inited = 0;
bool dummysan_init_is_running;

int dummysan_report_count = 0;

void Flags::SetDefaults() {
#define DUMMYSAN_FLAG(Type, Name, DefaultValue, Description) Name = DefaultValue;
#include "dummysan_flags.inc"
#undef DUMMYSAN_FLAG
}

static void RegisterDummysanFlags(FlagParser *parser, Flags *f) {
#define DUMMYSAN_FLAG(Type, Name, DefaultValue, Description) \
  RegisterFlag(parser, #Name, Description, &f->Name);
#include "dummysan_flags.inc"
#undef DUMMYSAN_FLAG
}

static void InitializeFlags() {
  SetCommonFlagsDefaults();
  {
    CommonFlags cf;
    cf.CopyFrom(*common_flags());
    cf.external_symbolizer_path = GetEnv("DUMMYSAN_SYMBOLIZER_PATH");
    cf.malloc_context_size = 20;
    cf.handle_ioctl = true;
    // FIXME: test and enable.
    cf.check_printf = false;
    cf.intercept_tls_get_addr = true;
    cf.exitcode = 99;
    // 8 shadow pages ~512kB, small enough to cover common stack sizes.
    cf.clear_shadow_mmap_threshold = 4096 * (SANITIZER_ANDROID ? 2 : 8);
    // Sigtrap is used in error reporting.
    cf.handle_sigtrap = kHandleSignalExclusive;

#if SANITIZER_ANDROID
    // Let platform handle other signals. It is better at reporting them then we
    // are.
    cf.handle_segv = kHandleSignalNo;
    cf.handle_sigbus = kHandleSignalNo;
    cf.handle_abort = kHandleSignalNo;
    cf.handle_sigill = kHandleSignalNo;
    cf.handle_sigfpe = kHandleSignalNo;
#endif
    OverrideCommonFlags(cf);
  }

  Flags *f = flags();
  f->SetDefaults();

  FlagParser parser;
  RegisterDummysanFlags(&parser, f);
  RegisterCommonFlags(&parser);

#if DUMMYSAN_CONTAINS_UBSAN
  __ubsan::Flags *uf = __ubsan::flags();
  uf->SetDefaults();

  FlagParser ubsan_parser;
  __ubsan::RegisterUbsanFlags(&ubsan_parser, uf);
  RegisterCommonFlags(&ubsan_parser);
#endif

  // Override from user-specified string.
  if (__dummysan_default_options)
    parser.ParseString(__dummysan_default_options());
#if DUMMYSAN_CONTAINS_UBSAN
  const char *ubsan_default_options = __ubsan_default_options();
  ubsan_parser.ParseString(ubsan_default_options);
#endif

  parser.ParseStringFromEnv("DUMMYSAN_OPTIONS");
#if DUMMYSAN_CONTAINS_UBSAN
  ubsan_parser.ParseStringFromEnv("UBSAN_OPTIONS");
#endif

  InitializeCommonFlags();

  if (Verbosity()) ReportUnrecognizedFlags();

  if (common_flags()->help) parser.PrintFlagDescriptions();
}

static void DummysanCheckFailed(const char *file, int line, const char *cond,
                              u64 v1, u64 v2) {
  Report("DummySanitizer CHECK failed: %s:%d \"%s\" (0x%zx, 0x%zx)\n", file,
         line, cond, (uptr)v1, (uptr)v2);
  PRINT_CURRENT_STACK_CHECK();
  Die();
}

static constexpr uptr kMemoryUsageBufferSize = 4096;

static void DummysanFormatMemoryUsage(InternalScopedString &s) {
  DummysanThreadList &thread_list = dummysanThreadList();
  auto thread_stats = thread_list.GetThreadStats();
  auto *sds = StackDepotGetStats();
  AllocatorStatCounters asc;
  GetAllocatorStats(asc);
  s.append(
      "DUMMYSAN pid: %d rss: %zd threads: %zd stacks: %zd"
      " thr_aux: %zd stack_depot: %zd uniq_stacks: %zd"
      " heap: %zd",
      internal_getpid(), GetRSS(), thread_stats.n_live_threads,
      thread_stats.total_stack_size,
      thread_stats.n_live_threads * thread_list.MemoryUsedPerThread(),
      sds->allocated, sds->n_uniq_ids, asc[AllocatorStatMapped]);
}

#if SANITIZER_ANDROID
static char *memory_usage_buffer = nullptr;

static void InitMemoryUsage() {
  memory_usage_buffer =
      (char *)MmapOrDie(kMemoryUsageBufferSize, "memory usage string");
  CHECK(memory_usage_buffer);
  memory_usage_buffer[0] = '\0';
  DecorateMapping((uptr)memory_usage_buffer, kMemoryUsageBufferSize,
                  memory_usage_buffer);
}

void UpdateMemoryUsage() {
  if (!flags()->export_memory_stats)
    return;
  if (!memory_usage_buffer)
    InitMemoryUsage();
  InternalScopedString s(kMemoryUsageBufferSize);
  DummysanFormatMemoryUsage(s);
  internal_strncpy(memory_usage_buffer, s.data(), kMemoryUsageBufferSize - 1);
  memory_usage_buffer[kMemoryUsageBufferSize - 1] = '\0';
}
#else
void UpdateMemoryUsage() {}
#endif

} // namespace __dummysan

using namespace __dummysan;

void __sanitizer::BufferedStackTrace::UnwindImpl(
    uptr pc, uptr bp, void *context, bool request_fast, u32 max_depth) {
  Thread *t = GetCurrentThread();
  if (!t) {
    // The thread is still being created, or has already been destroyed.
    size = 0;
    return;
  }
  Unwind(max_depth, pc, bp, context, t->stack_top(), t->stack_bottom(),
         request_fast);
}

static bool InitializeSingleGlobal(const dummysan_global &global) {
  uptr full_granule_size = RoundDownTo(global.size(), 16);
  TagMemoryAligned(global.addr(), full_granule_size, global.tag());
  if (global.size() % 16)
    TagMemoryAligned(global.addr() + full_granule_size, 16, global.size() % 16);
  return false;
}

static void InitLoadedGlobals() {
  dl_iterate_phdr(
      [](dl_phdr_info *info, size_t /* size */, void * /* data */) -> int {
        for (const dummysan_global &global : DummysanGlobalsFor(
                 info->dlpi_addr, info->dlpi_phdr, info->dlpi_phnum))
          InitializeSingleGlobal(global);
        return 0;
      },
      nullptr);
}

// Prepare to run instrumented code on the main thread.
static void InitInstrumentation() {
  if (dummysan_instrumentation_inited) return;

  InitPrctl();

  if (!InitShadow()) {
    Printf("FATAL: DummySanitizer cannot mmap the shadow memory.\n");
    DumpProcessMap();
    Die();
  }

  InitThreads();
  dummysanThreadList().CreateCurrentThread();

  dummysan_instrumentation_inited = 1;
}

// Interface.

uptr __dummysan_shadow_memory_dynamic_address;  // Global interface symbol.

// This function was used by the old frame descriptor mechanism. We keep it
// around to avoid breaking ABI.
void __dummysan_init_frames(uptr beg, uptr end) {}

void __dummysan_init_static() {
  InitShadowGOT();
  InitInstrumentation();

  // In the non-static code path we call dl_iterate_phdr here. But at this point
  // libc might not have been initialized enough for dl_iterate_phdr to work.
  // Fortunately, since this is a statically linked executable we can use the
  // linker-defined symbol __ehdr_start to find the only relevant set of phdrs.
  extern ElfW(Ehdr) __ehdr_start;
  for (const dummysan_global &global : DummysanGlobalsFor(
           /* base */ 0,
           reinterpret_cast<const ElfW(Phdr) *>(
               reinterpret_cast<const char *>(&__ehdr_start) +
               __ehdr_start.e_phoff),
           __ehdr_start.e_phnum))
    InitializeSingleGlobal(global);
}

void __dummysan_init() {
  CHECK(!dummysan_init_is_running);
  if (dummysan_inited) return;
  dummysan_init_is_running = 1;
  SanitizerToolName = "DummySanitizer";

  InitTlsSize();

  CacheBinaryName();
  InitializeFlags();

  // Install tool-specific callbacks in sanitizer_common.
  SetCheckFailedCallback(DummysanCheckFailed);

  __sanitizer_set_report_path(common_flags()->log_path);

  AndroidTestTlsSlot();

  DisableCoreDumperIfNecessary();

  InitInstrumentation();
  InitLoadedGlobals();

  // Needs to be called here because flags()->random_tags might not have been
  // initialized when InitInstrumentation() was called.
  GetCurrentThread()->InitRandomState();

  SetPrintfAndReportCallback(AppendToErrorMessageBuffer);
  // This may call libc -> needs initialized shadow.
  AndroidLogInit();

  InstallDeadlySignalHandlers(DummysanOnDeadlySignal);
  InstallAtExitHandler(); // Needs __cxa_atexit interceptor.

  InitializeCoverage(common_flags()->coverage, common_flags()->coverage_dir);

  DummysanTSDInit();
  DummysanTSDThreadInit();

  DummysanAllocatorInit();

#if DUMMYSAN_CONTAINS_UBSAN
  __ubsan::InitAsPlugin();
#endif

  VPrintf(1, "DummySanitizer init done\n");

  dummysan_init_is_running = 0;
  dummysan_inited = 1;
}

void __dummysan_library_loaded(ElfW(Addr) base, const ElfW(Phdr) * phdr,
                             ElfW(Half) phnum) {
  for (const dummysan_global &global : DummysanGlobalsFor(base, phdr, phnum))
    InitializeSingleGlobal(global);
}

void __dummysan_library_unloaded(ElfW(Addr) base, const ElfW(Phdr) * phdr,
                               ElfW(Half) phnum) {
  for (; phnum != 0; ++phdr, --phnum)
    if (phdr->p_type == PT_LOAD)
      TagMemory(base + phdr->p_vaddr, phdr->p_memsz, 0);
}

void __dummysan_print_shadow(const void *p, uptr sz) {
  uptr ptr_raw = UntagAddr(reinterpret_cast<uptr>(p));
  uptr shadow_first = MemToShadow(ptr_raw);
  uptr shadow_last = MemToShadow(ptr_raw + sz - 1);
  Printf("Dummysan shadow map for %zx .. %zx (pointer tag %x)\n", ptr_raw,
         ptr_raw + sz, GetTagFromPointer((uptr)p));
  for (uptr s = shadow_first; s <= shadow_last; ++s)
    Printf("  %zx: %x\n", ShadowToMem(s), *(tag_t *)s);
}

sptr __dummysan_test_shadow(const void *p, uptr sz) {
  if (sz == 0)
    return -1;
  tag_t ptr_tag = GetTagFromPointer((uptr)p);
  uptr ptr_raw = UntagAddr(reinterpret_cast<uptr>(p));
  uptr shadow_first = MemToShadow(ptr_raw);
  uptr shadow_last = MemToShadow(ptr_raw + sz - 1);
  for (uptr s = shadow_first; s <= shadow_last; ++s)
    if (*(tag_t *)s != ptr_tag) {
      sptr offset = ShadowToMem(s) - ptr_raw;
      return offset < 0 ? 0 : offset;
    }
  return -1;
}

u16 __sanitizer_unaligned_load16(const uu16 *p) {
  return *p;
}
u32 __sanitizer_unaligned_load32(const uu32 *p) {
  return *p;
}
u64 __sanitizer_unaligned_load64(const uu64 *p) {
  return *p;
}
void __sanitizer_unaligned_store16(uu16 *p, u16 x) {
  *p = x;
}
void __sanitizer_unaligned_store32(uu32 *p, u32 x) {
  *p = x;
}
void __sanitizer_unaligned_store64(uu64 *p, u64 x) {
  *p = x;
}

void __dummysan_loadN(uptr p, uptr sz) {
  CheckAddressSized<ErrorAction::Abort, AccessType::Load>(p, sz);
}
void __dummysan_load1(uptr p) {
  CheckAddress<ErrorAction::Abort, AccessType::Load, 0>(p);
}
void __dummysan_load2(uptr p) {
  CheckAddress<ErrorAction::Abort, AccessType::Load, 1>(p);
}
void __dummysan_load4(uptr p) {
  CheckAddress<ErrorAction::Abort, AccessType::Load, 2>(p);
}
void __dummysan_load8(uptr p) {
  CheckAddress<ErrorAction::Abort, AccessType::Load, 3>(p);
}
void __dummysan_load16(uptr p) {
  CheckAddress<ErrorAction::Abort, AccessType::Load, 4>(p);
}

void __dummysan_loadN_noabort(uptr p, uptr sz) {
  CheckAddressSized<ErrorAction::Recover, AccessType::Load>(p, sz);
}
void __dummysan_load1_noabort(uptr p) {
  CheckAddress<ErrorAction::Recover, AccessType::Load, 0>(p);
}
void __dummysan_load2_noabort(uptr p) {
  CheckAddress<ErrorAction::Recover, AccessType::Load, 1>(p);
}
void __dummysan_load4_noabort(uptr p) {
  CheckAddress<ErrorAction::Recover, AccessType::Load, 2>(p);
}
void __dummysan_load8_noabort(uptr p) {
  CheckAddress<ErrorAction::Recover, AccessType::Load, 3>(p);
}
void __dummysan_load16_noabort(uptr p) {
  CheckAddress<ErrorAction::Recover, AccessType::Load, 4>(p);
}

void __dummysan_storeN(uptr p, uptr sz) {
  CheckAddressSized<ErrorAction::Abort, AccessType::Store>(p, sz);
}
void __dummysan_store1(uptr p) {
  CheckAddress<ErrorAction::Abort, AccessType::Store, 0>(p);
}
void __dummysan_store2(uptr p) {
  CheckAddress<ErrorAction::Abort, AccessType::Store, 1>(p);
}
void __dummysan_store4(uptr p) {
  CheckAddress<ErrorAction::Abort, AccessType::Store, 2>(p);
}
void __dummysan_store8(uptr p) {
  CheckAddress<ErrorAction::Abort, AccessType::Store, 3>(p);
}
void __dummysan_store16(uptr p) {
  CheckAddress<ErrorAction::Abort, AccessType::Store, 4>(p);
}

void __dummysan_storeN_noabort(uptr p, uptr sz) {
  CheckAddressSized<ErrorAction::Recover, AccessType::Store>(p, sz);
}
void __dummysan_store1_noabort(uptr p) {
  CheckAddress<ErrorAction::Recover, AccessType::Store, 0>(p);
}
void __dummysan_store2_noabort(uptr p) {
  CheckAddress<ErrorAction::Recover, AccessType::Store, 1>(p);
}
void __dummysan_store4_noabort(uptr p) {
  CheckAddress<ErrorAction::Recover, AccessType::Store, 2>(p);
}
void __dummysan_store8_noabort(uptr p) {
  CheckAddress<ErrorAction::Recover, AccessType::Store, 3>(p);
}
void __dummysan_store16_noabort(uptr p) {
  CheckAddress<ErrorAction::Recover, AccessType::Store, 4>(p);
}

void __dummysan_tag_memory(uptr p, u8 tag, uptr sz) {
  TagMemoryAligned(p, sz, tag);
}

uptr __dummysan_tag_pointer(uptr p, u8 tag) {
  return AddTagToPointer(p, tag);
}

void __dummysan_handle_longjmp(const void *sp_dst) {
  uptr dst = (uptr)sp_dst;
  // Dummysan does not support tagged SP.
  CHECK(GetTagFromPointer(dst) == 0);

  uptr sp = (uptr)__builtin_frame_address(0);
  static const uptr kMaxExpectedCleanupSize = 64 << 20;  // 64M
  if (dst < sp || dst - sp > kMaxExpectedCleanupSize) {
    Report(
        "WARNING: Dummysan is ignoring requested __dummysan_handle_longjmp: "
        "stack top: %p; target %p; distance: %p (%zd)\n"
        "False positive error reports may follow\n",
        (void *)sp, (void *)dst, dst - sp);
    return;
  }
  TagMemory(sp, dst - sp, 0);
}

void __dummysan_print_memory_usage() {
  InternalScopedString s(kMemoryUsageBufferSize);
  DummysanFormatMemoryUsage(s);
  Printf("%s\n", s.data());
}

static const u8 kFallbackTag = 0xBB;

u8 __dummysan_generate_tag() {
  Thread *t = GetCurrentThread();
  if (!t) return kFallbackTag;
  return t->GenerateRandomTag();
}

#if !SANITIZER_SUPPORTS_WEAK_HOOKS
extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE
const char* __dummysan_default_options() { return ""; }
}  // extern "C"
#endif

extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_print_stack_trace() {
  GET_FATAL_STACK_TRACE_PC_BP(StackTrace::GetCurrentPc(), GET_CURRENT_FRAME());
  stack.Print();
}
} // extern "C"
