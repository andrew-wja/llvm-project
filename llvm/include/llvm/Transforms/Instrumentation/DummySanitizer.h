//===--------- Definition of the DummySanitizer class -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the Dummy Sanitizer class with the new PassManager infrastructure.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_DUMMYSANITIZERPASS_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_DUMMYSANITIZERPASS_H

#include "llvm/IR/Function.h"
#include "llvm/IR/PassManager.h"

namespace llvm {

/// This is a public interface to the dummy sanitizer pass for
/// instrumenting code to check for various memory errors at runtime, similar to
/// AddressSanitizer but based on partial hardware assistance.
class DummySanitizerPass : public PassInfoMixin<DummySanitizerPass> {
public:
  explicit DummySanitizerPass(bool CompileKernel = false,
                                  bool Recover = false);
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
  static bool isRequired() { return true; }

private:
  bool CompileKernel;
  bool Recover;
};

FunctionPass *createDummySanitizerLegacyPassPass(bool CompileKernel = false,
                                                     bool Recover = false);

namespace DummysanAccessInfo {

// Bit field positions for the accessinfo parameter to
// llvm.dummysan.check.memaccess. Shared between the pass and the backend. Bits
// 0-15 are also used by the runtime.
enum {
  AccessSizeShift = 0, // 4 bits
  IsWriteShift = 4,
  RecoverShift = 5,
  MatchAllShift = 16, // 8 bits
  HasMatchAllShift = 24,
  CompileKernelShift = 25,
};

enum { RuntimeMask = 0xffff };

} // namespace DummysanAccessInfo

} // namespace llvm

#endif
