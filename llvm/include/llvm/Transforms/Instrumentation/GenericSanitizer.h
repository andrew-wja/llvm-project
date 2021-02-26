//===--------- Definition of the GenericSanitizer class -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the GenericSanitizer class with the new PassManager infrastructure.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_GENERICSANITIZERPASS_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_GENERICSANITIZERPASS_H

#include "llvm/ADT/MapVector.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Triple.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/InitializePasses.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizerCommon.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include <queue>
#include <sstream>

using namespace llvm;

typedef IRBuilder<> BuilderTy;

class SoftBoundCETSImpl {

  BuilderTy *Builder;

  Function* m_introspect_metadata;
  Function* m_copy_metadata;
  Function* m_shadow_stack_allocate;
  Function* m_shadow_stack_deallocate;
  Function* m_shadow_stack_base_load;
  Function* m_shadow_stack_bound_load;
  Function* m_shadow_stack_key_load;
  Function* m_shadow_stack_lock_load;

  Function* m_shadow_stack_base_store;
  Function* m_shadow_stack_bound_store;
  Function* m_shadow_stack_key_store;
  Function* m_shadow_stack_lock_store;

  Function* m_spatial_load_dereference_check;
  Function* m_spatial_store_dereference_check;

  Function* m_temporal_stack_memory_allocation;
  Function* m_temporal_stack_memory_deallocation;

  Function* m_temporal_load_dereference_check;
  Function* m_temporal_store_dereference_check;
  Function* m_temporal_global_lock_function;

  Function* m_call_dereference_func;
  Function* m_memcopy_check;
  Function* m_memset_check;

  Function* m_metadata_map_func;
  Function* m_metadata_load_base_func;
  Function* m_metadata_load_bound_func;
  Function* m_metadata_load_key_func;
  Function* m_metadata_load_lock_func;

  /* Function Type of the function that loads the base and bound for
   * a given pointer
   */
  Function* m_load_base_bound_func;
  Function* m_metadata_load_vector_func;
  Function* m_metadata_store_vector_func;

  /* Function Type of the function that stores the base and bound
   * for a given pointer
   */
  Function* m_store_base_bound_func;

  /* void pointer type, used many times in the Softboundcets pass */
  Type* m_void_ptr_type;
  Type* m_sizet_ptr_type;
  FixedVectorType* m_base_bound_ty;
  FixedVectorType* m_key_lock_ty;

  /* constant null pointer which is the base and bound for most
   * non-pointers
   */
  ConstantPointerNull* m_void_null_ptr;
  ConstantPointerNull* m_sizet_null_ptr;
  Type* m_key_type;

  Constant* m_constantint_one;
  Constant* m_constantint_zero;

  Constant* m_constantint32ty_one;
  Constant* m_constantint32ty_zero;
  Constant* m_constantint64ty_one;
  Constant* m_constantint64ty_zero;

  /* Infinite bound where bound cannot be inferred in VarArg
   * functions
   */
  Value* m_infinite_bound_ptr;

  /* Dominance Tree and Dominance Frontier for avoiding load
   * dereference checks
   */

  DominatorTree* m_dominator_tree;

  /* Book-keeping structures for identifying original instructions in
   * the program, pointers and their corresponding base and bound
   */
  std::map<Value*, int> m_is_pointer;
  std::map<Value*, Value*> m_pointer_base;

  std::map<Value*, Value*> m_vector_pointer_base;
  std::map<Value*, Value*> m_vector_pointer_bound;

  std::map<Value*, Value*> m_pointer_bound;
  std::map<Value*, BasicBlock*> m_faulting_block;

  /* key associated with pointer */

  std::map<Value*, Value*> m_vector_pointer_key;
  std::map<Value*, Value*> m_vector_pointer_lock;

  std::map<Value*, Value*> m_pointer_key;
  /* address of the location to load the key from */
  std::map<Value*, Value*> m_pointer_lock;
  std::map<Value*, int> m_present_in_original;

  std::map<GlobalVariable*, int> m_initial_globals;

  /* Map of all functions for which Softboundcets Transformation must
   * be invoked
   */
  StringMap<bool> m_func_softboundcets_transform;

  /* Map of all functions that need to be transformed as they have
   * either pointer arguments or pointer return type and are
   * defined in the module
   */
  StringMap<bool> m_func_to_transform;

  /* Map of all functions defined by Softboundcets */
  StringMap<bool> m_func_def_softbound;

  StringMap<bool> m_func_wrappers_available;

  /* Map of all functions transformed */
  StringMap<bool> m_func_transformed;

  StringMap<Value*> m_func_global_lock;

  /* Boolean indicating whether bitcode generated is for 64bit or
     32bit */
  bool m_is_64_bit;

  /* Helper Functions */

  void identifyOriginalInst(Function*);
  bool isAllocaPresent(Function*);
  void emitInstrumentationPhase1(Function*);
  void emitInstrumentationPhase2(Function*);
  void emitInstrumentationPhase3(Function*);
  bool isFunctionToInstrument(Function*);
  bool isFuncDefSoftBound(const std::string &str);
  std::string transformFunctionName(const std::string &str);

  /* Specific LLVM instruction handlers */
  void handleAlloca(AllocaInst*, Value*, Value*,
                    Value*, BasicBlock*,
                    BasicBlock::iterator&);
  void handleBitCast(BitCastInst*);
  void handleCall(CallInst*);
  void handleExtractElement(ExtractElementInst*);
  void handleExtractValue(ExtractValueInst*);
  void handleGEP(GetElementPtrInst*);
  void handleIndirectCall(CallInst*);
  void handleIntToPtr(IntToPtrInst*);
  void handleLoad(LoadInst*);
  void handleMemcpy(CallInst*);
  void handlePHIPass1(PHINode*);
  void handlePHIPass2(PHINode*);
  void handleReturnInst(ReturnInst*);
  void handleSelect(SelectInst*, int);
  void handleStore(StoreInst*);
  void handleVectorStore(StoreInst*);

  void markFunctionsToInstrument(Module&);
  void renameFunctions(Module&);
  void renameFunctionName(Function*, Module&, bool);

  bool isByValDerived(Value*);

  bool checkBitcastShrinksBounds(Instruction* );
  void emitLoadStoreChecks(Instruction*,
                          std::map<Value*, int>&);
  void emitTemporalChecks(Instruction*,
                         std::map<Value*, int>&,
                         std::map<Value*, int>&);

  bool optimizeTemporalChecks(Instruction*,
                              std::map<Value*, int>&,
                              std::map<Value*,int>&);

  bool bbTemporalCheckElimination(Instruction*,
                                  std::map<Value*, int>&);

  bool funcTemporalCheckElimination(Instruction*,
                                    std::map<Value*, int>&);

  bool optimizeGlobalAndStackVariableChecks(Instruction*);
  bool checkLoadStoreSourceIsGEP(Instruction*, Value*);
  void addMemcopyMemsetCheck(CallInst*, Function*);
  bool isMemcopyFunction(Function*);

  void getFunctionKeyLock(Function*, Value* &, Value* &, Value* &);
  void freeFunctionKeyLock(Function*, Value* &, Value* &, Value* &);
  Value* getPointerLoadStore(Instruction*);
  void propagateMetadata(Value*, Instruction*, int);

  void getFunctionKeyLock(Function &, Value* &, Value* &, Value* &);
  void addMemoryAllocationCall(Function*, Value* &, Value* & ,
                               Instruction*) ;


  enum { SBCETS_BITCAST, SBCETS_GEP};
  /* Auxillary base and propagation functions */

  void handleGlobalSequentialTypeInitializer(Module&, GlobalVariable*);
  void handleGlobalStructTypeInitializer(Module& , StructType* ,
                                         Constant* , GlobalVariable*,
                                         std::vector<Constant*>, int) ;

  void addBaseBoundGlobals(Module&);
  Instruction* getGlobalInitInstruction(Module&);
  void markInitialGlobals(Module&);
  void getGlobalVariableBaseBound(Value*, Value* &, Value* &);
  void getConstantExprBaseBound(Constant*, Value* &, Value* &);
  void disassociateBaseBound(Value*);
  void disassociateKeyLock(Value*);

  /* Explicit Map manipulation functions */

  /* Single function that adds base/bound/key to the pointer map,
   * first argument - pointer operand
   * second argument - associated base
   * third argument - associated bound
   * fourth argument - associated key
   * fifth argument - associated lock
   */
  void associateBaseBoundKeyLock(Value*, Value*, Value*, Value*, Value*);
  void associateBaseBound(Value*, Value*, Value* );
  void associateKeyLock(Value*, Value*, Value*);

  Value* getAssociatedBase(Value*);
  Value* getAssociatedBound(Value*);
  Value* getAssociatedKey(Value*);
  Value* getAssociatedFuncLock(Value*);
  Value* getAssociatedLock(Value*, Value*);

  bool isBaseBoundMetadataPresent(Value*);
  bool isKeyLockMetadataPresent(Value*);

  void emitStoreBaseBound(Value*, Value*, Value*,Value*,
                          Value*, Value*, Value*, Instruction*);



  /* Other helper functions */

  Value* introduceGEPWithLoad(Value*, int, Instruction*);
  Value* storeShadowStackBaseForFunctionArgs(Instruction*, int);
  Value* storeShadowStackBoundForFunctionArgs(Instruction*, int);
  Value* storeShadowStackKeyForFunctionArgs(Instruction*, int);
  Value* storeShadowStackLockForFunctionArgs(Instruction*, int);

  Value* retrieveShadowStackBaseForFunctionArgs(Instruction*, int );
  Value* retrieveShadowStackBoundForFunctionArgs(Instruction*, int);
  Value* retrieveShadowStackKeyForFunctionArgs(Instruction*, int);
  Value* retrieveShadowStackLockForFunctionArgs(Instruction*, int);

  Value* introduceGlobalLockFunction(Instruction*);
  void introspectMetadata(Function*, Value*, Instruction*, int);
  void emitShadowStackChecks(Value*, Instruction*, int);
  void emitShadowStackAllocation(CallInst*);
  void emitShadowStackInitialization(CallInst*);
  void emitShadowStackInitialization(Value*, Instruction*, int);
  void emitShadowStackDeallocation(CallInst*, Instruction*);

public:
  void initialize(Module &M);
  bool sanitize(Function &F);
  void finalize(Module &M);
};

namespace llvm {

/// This is a public interface to the generic sanitizer pass.
class GenericSanitizerPass : public PassInfoMixin<GenericSanitizerPass> {
private:
  SoftBoundCETSImpl impl;
public:
  GenericSanitizerPass() {}
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
  static bool isRequired() { return true; }
};

ModulePass *createGenericSanitizerLegacyPassPass();

} // namespace llvm

#endif
