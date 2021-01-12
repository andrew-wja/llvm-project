#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_EXAMPLESANITIZERPASS_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_EXAMPLESANITIZERPASS_H

#include "llvm/IR/Function.h"
#include "llvm/IR/PassManager.h"

namespace llvm {

class ExampleSanitizerPass : public PassInfoMixin<ExampleSanitizerPass> {
public:
  explicit ExampleSanitizerPass();
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
  static bool isRequired() { return true; }
};

FunctionPass *createExampleSanitizerLegacyPassPass();

} // namespace llvm

#endif
