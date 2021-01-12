#include "llvm/Transforms/Instrumentation/ExampleSanitizer.h"
#include "llvm/ADT/MapVector.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Triple.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizerCommon.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include <sstream>

using namespace llvm;

#define DEBUG_TYPE "examplesan"

namespace {

class ExampleSanitizer {
public:
  explicit ExampleSanitizer(Module &M) : M(M) {
    initializeModule();
  }

  bool sanitizeFunction(Function &F);
  void initializeModule();
  void createExamplesanCtorComdat();

  void initializeCallbacks(Module &M);
  void emitPrologue(IRBuilder<> &IRB, bool WithFrameRecord);

private:
  LLVMContext *C;
  Module &M;
  Triple TargetTriple;

  Function *ExamplesanCtorFunction;
};

class ExampleSanitizerLegacyPass : public FunctionPass {
public:
  // Pass identification, replacement for typeid.
  static char ID;

  explicit ExampleSanitizerLegacyPass()
      : FunctionPass(ID) {
    initializeExampleSanitizerLegacyPassPass(
        *PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override { return "ExampleSanitizer"; }

  bool doInitialization(Module &M) override {
    ExampleSan = std::make_unique<ExampleSanitizer>(M);
    return true;
  }

  bool runOnFunction(Function &F) override {
    return ExampleSan->sanitizeFunction(F);
  }

  bool doFinalization(Module &M) override {
    ExampleSan.reset();
    return false;
  }

private:
  std::unique_ptr<ExampleSanitizer> ExampleSan;
};

} // end anonymous namespace

char ExampleSanitizerLegacyPass::ID = 0;

INITIALIZE_PASS_BEGIN(
    ExampleSanitizerLegacyPass, "examplesan",
    "ExampleSanitizer: a skeleton sanitizer for demonstration of the sanitizer machinery.", false,
    false)
INITIALIZE_PASS_END(
    ExampleSanitizerLegacyPass, "examplesan",
    "ExampleSanitizer: a skeleton sanitizer for demonstration of the sanitizer machinery.", false,
    false)

FunctionPass *llvm::createExampleSanitizerLegacyPassPass() {
  return new ExampleSanitizerLegacyPass();
}

ExampleSanitizerPass::ExampleSanitizerPass() {}

PreservedAnalyses ExampleSanitizerPass::run(Module &M,
                                              ModuleAnalysisManager &MAM) {
  ExampleSanitizer ExampleSan(M);
  bool Modified = false;
  for (Function &F : M)
    Modified |= ExampleSan.sanitizeFunction(F);
  if (Modified)
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}

/// Module-level initialization.
///
/// inserts a call to __examplesan_init to the module's constructor list.
void ExampleSanitizer::initializeModule() {
  LLVM_DEBUG(dbgs() << "Init " << M.getName() << "\n");
  auto &DL = M.getDataLayout();

  TargetTriple = Triple(M.getTargetTriple());

  Mapping.init(TargetTriple);

  C = &(M.getContext());

  ExamplesanCtorFunction = nullptr;
  createExamplesanCtorComdat();
}

void ExampleSanitizer::initializeCallbacks(Module &M) {
  IRBuilder<> IRB(*C);
  ExamplesanHelloFunc = M.getOrInsertFunction("__examplesan_hello", IRB.getVoidTy());
}

bool ExampleSanitizer::sanitizeFunction(Function &F) {
  IRBuilder<> IRB(*C);

  if (&F == ExamplesanCtorFunction)
    return false;

  if (F.getName().compare("main") == 0) {
    Instruction *InsertPt = &*F.getEntryBlock().begin();
    IRB.SetInsertPoint(InsertPt);
    Constant * examplesan_entry = F.getParent()->getOrInsertFunction("__examplesan_entry", IRB.getVoidTy());
    IRB.CreateCall(examplesan_entry, {});

    for (auto &BB : F) {
      for (auto &Inst : BB) {
        if (auto * ret = dyn_cast<ReturnInst>(&inst)) {
          IRB.SetInsertPoint(ret);
          Constant * examplesan_exit = F.getParent()->getOrInsertFunction("__examplesan_exit", IRB.getVoidTy());
          IRB.CreateCall(examplesan_exit, {});
        }
      }
    }
  }

  LLVM_DEBUG(dbgs() << "Function: " << F.getName() << "\n");

  initializeCallbacks(*F.getParent());

  return true;
}

