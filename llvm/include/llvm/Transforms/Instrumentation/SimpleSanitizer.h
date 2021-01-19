//===--------- Definition of the SimpleSanitizer class -------*- C++ -*-===//
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
#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_SIMPLESANITIZERPASS_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_SIMPLESANITIZERPASS_H

#include "llvm/IR/Function.h"
#include "llvm/IR/PassManager.h"

namespace llvm {

/// This is a public interface to the simple sanitizer pass for
/// instrumenting code to check for various memory errors at runtime.
class SimpleSanitizerPass : public PassInfoMixin<SimpleSanitizerPass> {
public:
  explicit SimpleSanitizerPass(bool Recover = false);
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
  static bool isRequired() { return true; }

private:
  bool Recover;
};

FunctionPass *createSimpleSanitizerLegacyPassPass(bool Recover = false);

} // namespace llvm

#endif
