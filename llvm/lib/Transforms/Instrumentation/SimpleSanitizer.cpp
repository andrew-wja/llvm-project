//===- SimpleSanitizer.cpp - detector of uninitialized reads -------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
/// \file
/// This file is a part of SimpleSanitizer.
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Instrumentation/SimpleSanitizer.h"
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

#define DEBUG_TYPE "simplesan"

static cl::opt<bool> ClInstrumentReads("simplesan-instrument-reads",
                                       cl::desc("instrument read instructions"),
                                       cl::Hidden, cl::init(true));

static cl::opt<bool> ClInstrumentWrites(
    "simplesan-instrument-writes", cl::desc("instrument write instructions"),
    cl::Hidden, cl::init(true));

static cl::opt<bool> ClRecover(
    "simplesan-recover",
    cl::desc("Enable recovery mode (continue-after-error)."),
    cl::Hidden, cl::init(false));

static cl::opt<bool> ClInstrumentStack("simplesan-instrument-stack",
                                       cl::desc("instrument stack (allocas)"),
                                       cl::Hidden, cl::init(true));

namespace {

class SimpleSanitizer {
public:
  explicit SimpleSanitizer(Module &M, bool Recover = false) {
    this->Recover = ClRecover.getNumOccurrences() > 0 ? ClRecover : Recover;
  }

  bool sanitizeFunction(Function &F);
  bool ignoreAccess(Value *Ptr);

private:
  Triple TargetTriple;

  bool Recover;

};

class SimpleSanitizerLegacyPass : public FunctionPass {
public:
  // Pass identification, replacement for typeid.
  static char ID;

  explicit SimpleSanitizerLegacyPass(bool Recover = false)
      : FunctionPass(ID), Recover(Recover) {
    initializeSimpleSanitizerLegacyPassPass(
        *PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override { return "SimpleSanitizer"; }

  bool doInitialization(Module &M) override {
    Simplesan = std::make_unique<SimpleSanitizer>(M, Recover);
    return true;
  }

  bool runOnFunction(Function &F) override {
    return Simplesan->sanitizeFunction(F);
  }

  bool doFinalization(Module &M) override {
    Simplesan.reset();
    return false;
  }

private:
  std::unique_ptr<SimpleSanitizer> Simplesan;
  bool Recover;
};

} // end anonymous namespace

char SimpleSanitizerLegacyPass::ID = 0;

INITIALIZE_PASS_BEGIN(
    SimpleSanitizerLegacyPass, "simplesan",
    "SimpleSanitizer: a simple sanitizer.", false,
    false)
INITIALIZE_PASS_END(
    SimpleSanitizerLegacyPass, "simplesan",
    "SimpleSanitizer: a simple sanitizer.", false,
    false)

FunctionPass *llvm::createSimpleSanitizerLegacyPassPass(bool Recover) {
  assert(Recover);
  return new SimpleSanitizerLegacyPass(Recover);
}

SimpleSanitizerPass::SimpleSanitizerPass(bool Recover)
    : Recover(Recover) {}

PreservedAnalyses SimpleSanitizerPass::run(Module &M,
                                              ModuleAnalysisManager &MAM) {
  SimpleSanitizer Simplesan(M, Recover);
  bool Modified = false;
  for (Function &F : M)
    Modified |= Simplesan.sanitizeFunction(F);
  if (Modified)
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}

bool SimpleSanitizer::ignoreAccess(Value *Ptr) {
  // Do not instrument acesses from different address spaces; we cannot deal
  // with them.
  Type *PtrTy = cast<PointerType>(Ptr->getType()->getScalarType());
  if (PtrTy->getPointerAddressSpace() != 0)
    return true;

  // Ignore swifterror addresses.
  // swifterror memory addresses are mem2reg promoted by instruction
  // selection. As such they cannot have regular uses like an instrumentation
  // function and it makes no sense to track them as memory.
  if (Ptr->isSwiftError())
    return true;

  return false;
}

bool SimpleSanitizer::sanitizeFunction(Function &F) {
  LLVM_DEBUG(dbgs() << "Function: " << F.getName() << "\n");

  LLVMContext *C = &(F.getParent()->getContext());
  // General IR Builder
  IRBuilder<> IRB(*C);

  for (auto &BB : F) {
    for (Instruction &I : BB) {
      if (LoadInst *LI = dyn_cast<LoadInst>(&I)) {
        if (!ClInstrumentReads || ignoreAccess(LI->getPointerOperand()))
          continue;
        IRB.SetInsertPoint(LI);
        FunctionCallee simplesan_read = F.getParent()->getOrInsertFunction("__simplesan_read", IRB.getVoidTy());
        IRB.CreateCall(simplesan_read, {});
      } else if (StoreInst *SI = dyn_cast<StoreInst>(&I)) {
        if (!ClInstrumentWrites || ignoreAccess(SI->getPointerOperand()))
          continue;
        IRB.SetInsertPoint(SI);
        FunctionCallee simplesan_write = F.getParent()->getOrInsertFunction("__simplesan_write", IRB.getVoidTy());
        IRB.CreateCall(simplesan_write, {});
      } else {
        continue;
      }
    }
  }

  return true;
}

