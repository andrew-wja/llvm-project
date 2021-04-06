//===- GenericSanitizer.cpp -------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
/// \file
/// This file is a part of GenericSanitizer.
//===----------------------------------------------------------------------===//

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

#include "llvm/Transforms/Instrumentation/GenericSanitizer.h"

using namespace llvm;

#define DEBUG_TYPE "gsan"

#if defined(SOFTBOUNDCETS_NO_ASSERTS)
#define SOFTBOUNDCETS_ASSERT(x)
#else
#define SOFTBOUNDCETS_ASSERT(x) assert(x)
#endif

namespace util {

// Miscellaneous utility functions

//
// Method: getNumPointerArgsAndReturn
//
// Description: Returns the number of pointers in the function signature
// (counts pointer arguments plus one if a pointer type is returned).
//

int getNumPointerArgsAndReturn(CallInst* call_inst){

  int total_pointer_count = 0;
  for(Value* arg_value : call_inst->args()){
    if (isa<PointerType>(arg_value->getType())){
      total_pointer_count++;
    }
  }

  if (total_pointer_count != 0) {
    // Reserve one for the return address if it has atleast one
    // pointer argument
    total_pointer_count++;
  } else{
    // Increment the pointer arg return if the call instruction
    // returns a pointer
    if (isa<PointerType>(call_inst->getType())){
      total_pointer_count++;
    }
  }
  return total_pointer_count;
}

//
// Method: getNextInstruction
//
// Description:
// This method returns the next instruction after the input instruction.
//

Instruction* getNextInstruction(Instruction* I){

  if (I->isTerminator()) {
    return I;
  } else {
    BasicBlock::iterator BBI(I);
    Instruction* temp = &*(++BBI);
    return temp;
  }
}

//
// Method: castToVoidPtr()
//
// Description:
//
// This function introduces a bitcast instruction in the IR when an
// input operand that is a pointer type is not of type i8*. This is
// required as all the SoftBound/CETS handlers take i8*s
//

Value* castToVoidPtr(Value* operand, Instruction* insert_at) {

  Type* vptrty = PointerType::getUnqual(Type::getInt8Ty(insert_at->getContext()));
  Value* cast_bitcast = operand;
  if (operand->getType() != vptrty) {
    cast_bitcast = new BitCastInst(operand, vptrty,
                                   "bitcast",
                                   insert_at);
  }
  return cast_bitcast;
}

//
// Method: getSizeOfType
//
// Description: This function returns the size of the memory access
// based on the type of the pointer which is being dereferenced.  This
// function is used to pass the size of the access in many checks to
// perform byte granularity checking.
//
// Comments: May we should use TargetData instead of m_is_64_bit
// according Criswell's comments.

Value* getSizeOfType(Type* input_type, bool m_is_64_bit) {

  // Create a Constant Pointer Null of the input type.  Then get a
  // getElementPtr of it with next element access cast it to unsigned
  // int

  const PointerType* ptr_type = dyn_cast<PointerType>(input_type);

  if (isa<FunctionType>(ptr_type->getElementType())) {
    if (m_is_64_bit) {
      return ConstantInt::get(Type::getInt64Ty(ptr_type->getContext()), 0);
    } else{
      return ConstantInt::get(Type::getInt32Ty(ptr_type->getContext()), 0);
    }
  }

  Constant* int64_size = NULL;
  StructType* struct_type = dyn_cast<StructType>(input_type);

  if (struct_type){
    if (struct_type->isOpaque()){
      if (m_is_64_bit) {
        return ConstantInt::get(Type::getInt64Ty(input_type->getContext()), 0);
      }
      else {
        return ConstantInt::get(Type::getInt32Ty(input_type->getContext()), 0);
      }
    }
  }

  if (m_is_64_bit) {

    if (!ptr_type->getElementType()->isSized()){
      return ConstantInt::get(Type::getInt64Ty(ptr_type->getContext()), 0);
    }
    int64_size = ConstantExpr::getSizeOf(ptr_type->getElementType());
    return int64_size;
  } else {

    // doing what ConstantExpr::getSizeOf() does
    Constant* gep_idx =
      ConstantInt::get(Type::getInt32Ty(input_type->getContext()), 1);

    PointerType* ptr_type2 = PointerType::getUnqual(ptr_type->getElementType());
    Constant* gep_temp = ConstantExpr::getNullValue(ptr_type2);

    Constant* gep = ConstantExpr::getGetElementPtr(nullptr, gep_temp,  gep_idx);

    Type* int64Ty = Type::getInt64Ty(input_type->getContext());
    return ConstantExpr::getPtrToInt(gep, int64Ty);
  }
  SOFTBOUNDCETS_ASSERT(0 && "not handled type?");

  return NULL;
}

// Method: checkPtrsInST
//
//
//Description: Check whether the pointed-to struct type has pointers
//

bool checkPtrsInST(StructType* struct_type){

  StructType::element_iterator I = struct_type->element_begin();


  bool ptr_flag = false;
  for(StructType::element_iterator E = struct_type->element_end(); I != E; ++I){

    Type* element_type = *I;

    if (isa<StructType>(element_type)){
      StructType* struct_element_type = dyn_cast<StructType>(element_type);
      bool recursive_flag = checkPtrsInST(struct_element_type);
      ptr_flag = ptr_flag | recursive_flag;
    }
    if (isa<PointerType>(element_type)){
      ptr_flag = true;
    }
    if (isa<ArrayType>(element_type)){
      ptr_flag = true;
    }
  }
  return ptr_flag;
}


// Method: checkTypeHasPtrs
//
//
//Description: Check whether the arguments type contains pointers
//

bool checkTypeHasPtrs(Argument* ptr_argument){

  if (!ptr_argument->hasByValAttr())
    return false;

  ArrayType* arr_type = dyn_cast<ArrayType>(ptr_argument->getType());
  PointerType* ptr_type = dyn_cast<PointerType>(ptr_argument->getType());

  SOFTBOUNDCETS_ASSERT((arr_type || ptr_type) && "byval attribute with non-sequential type pointer, not handled?");

  if (arr_type) {
    StructType* struct_type = dyn_cast<StructType>(arr_type->getElementType());

    if (struct_type){
      bool has_ptrs = checkPtrsInST(struct_type);
      return has_ptrs;
    }
    else{
      SOFTBOUNDCETS_ASSERT(0 && "non-struct byval parameters?");
    }
  } else {
    StructType* struct_type = dyn_cast<StructType>(ptr_type->getElementType());

    if (struct_type){
      bool has_ptrs = checkPtrsInST(struct_type);
      return has_ptrs;
    }
    else{
      SOFTBOUNDCETS_ASSERT(0 && "non-struct byval parameters?");
    }
  }

  // By default we assume any struct can return pointers
  return true;

}

} // namespace util

//
// Method: getAssociateFuncLock()
//
// Description:
//
// This method looks up the "lock" for global variables associated
// with the function. Every will have a getGlobalLockAddr function
// inserted at the beginning which will serve as the lock for all the
// global variables used in the function.
//
//
// Inputs:
//
// Pointer_inst: An instruction that is manipulating a global pointer
// value.
//
// Return value:
//
// Returns the "lock associated with the function. Should never return
// NULL.
//

Value*
SoftBoundCETSImpl::getAssociatedFuncLock(Value* PointerInst){

  Instruction* inst = dyn_cast<Instruction>(PointerInst);

  Value* tmp_lock = NULL;
  if (!inst) {
    SOFTBOUNDCETS_ASSERT(0 && "Function does not have global lock?");
    return NULL;
  }

  if (m_func_global_lock.count(inst->getParent()->getParent()->getName())) {
    tmp_lock = m_func_global_lock[inst->getParent()->getParent()->getName()];
  }

  return tmp_lock;
}



// Method: hasAllocaInst()
//
// Description:
//
// This function checks whether internal function has an alloca
// instruction in the function. This function is useful to determine
// whether we need to allocate a key and a lock for the function or
// not.
//
bool SoftBoundCETSImpl::isAllocaPresent(Function* func){

  for(Function::iterator bb_begin = func->begin(), bb_end = func->end();
      bb_begin != bb_end; ++bb_begin) {

    for(BasicBlock::iterator i_begin = bb_begin->begin(),
    i_end = bb_begin->end(); i_begin != i_end; ++i_begin){

      Instruction* alloca_inst = dyn_cast<Instruction>(i_begin);

      if (isa<AllocaInst>(alloca_inst) && m_present_in_original.count(alloca_inst)){
  return true;
      }
    }
  }
  return false;

}


//
// Method: getFunctionKeyLock()
//
// Description:
//
// This function introduces a memory allocation call for allocating a
// new "key" and "lock" for the stack frames on function entry.  This
// function also stores the key and lock in the reference Value*
// arguments provided to the function.  Further, key and lock is
// allocated only when temporal checking is performed.
//
// Inputs:
//
// func: Function* of the function performing the allocation
// func_key: Value* & is the reference argument to return the key
// func_lock: Value* & is the reference_argument to return the lock
// func_xmm_lock: Value* & is the reference argument that will be
// eventually used to return the key and lock as wide parameters.
//

void
SoftBoundCETSImpl::getFunctionKeyLock(Function* func,
                                      Value* & func_key,
                                      Value* & func_lock,
                                      Value* & func_xmm_key_lock) {

  Instruction* func_alloca_inst = NULL;
  func_key = NULL;
  func_lock = NULL;
  func_xmm_key_lock = NULL;

  if (!isAllocaPresent(func))
    return;

  func_alloca_inst = dyn_cast<Instruction>(func->begin()->begin());
  SOFTBOUNDCETS_ASSERT(func_alloca_inst && "func begin null?");
  addMemoryAllocationCall(func, func_key,
        func_lock, func_alloca_inst);

  return;
}

//
// Method: addMemoryAllocationCall()
//
// This function introduces a call to the C-handler function for
// allocating key and lock for stack frames. After the handler call,
// it performs the load of the key and the lock to use it as the
// metadata for pointers pointing to stack allocations in the
// function.
//
// Inputs:
//
// func: Function for which the key and the lock is being allocated
//
// ptr_key: Reference argument to return the key after the key and lock
// allocation
//
// ptr_lock: Reference argument to return the lock after
// the key and lock allocation
//
// insert_at: Instruction* before which the C-handler is introduced
//
// Outputs:
//
// A new key and lock is allocated by the C-handler and then returned
// via reference arguments that is used as key and lock for pointers
// pointing to stack allocations in the function.
//


void
SoftBoundCETSImpl::addMemoryAllocationCall(Function* func,
                                           Value* & ptr_key,
                                           Value* & ptr_lock,
                                           Instruction* insert_at) {

  SmallVector<Value*, 8> args;
  Instruction* first_inst_func = cast<Instruction>(func->begin()->begin());
  AllocaInst* lock_alloca = new AllocaInst(m_void_ptr_type, 0,
                                           "lock_alloca",
                                           first_inst_func);
  AllocaInst* key_alloca = new AllocaInst(Type::getInt64Ty(func->getContext()),
                                          0, "key_alloca", first_inst_func);
  args.push_back(lock_alloca);
  args.push_back(key_alloca);

  Instruction*
    flc_call = CallInst::Create(m_temporal_stack_memory_allocation,
        args, "", first_inst_func);

  //
  // Load the key and lock from the reference arguments passed to the
  // C-handler
  //

  Instruction* next_inst = util::getNextInstruction(flc_call);
  Instruction* alloca_lock = new LoadInst(m_void_ptr_type, lock_alloca,
                                          "lock.load", next_inst);
  Instruction* alloca_key = new LoadInst(Type::getInt64Ty(func->getContext()),
                                         key_alloca, "key.load", next_inst);

  ptr_key = alloca_key;
  ptr_lock = alloca_lock;
}

//
// Method: isFuncDefSoftBound
//
// Description:
//
// This function checks if the input function name is a
// SoftBound/CETS defined function
//

bool SoftBoundCETSImpl::isFuncDefSoftBound(const std::string &str) {
  if (m_func_def_softbound.getNumItems() == 0) {

    //~ m_func_wrappers_available["abort"] = true;
    //~ m_func_wrappers_available["abs"] = true;
    //~ m_func_wrappers_available["acos"] = true;
    //~ m_func_wrappers_available["atan2"] = true;
    //~ m_func_wrappers_available["atexit"] = true;
    //~ m_func_wrappers_available["atof"] = true;
    //~ m_func_wrappers_available["atoi"] = true;
    //~ m_func_wrappers_available["atol"] = true;
    m_func_wrappers_available["calloc"] = true;
    //~ m_func_wrappers_available["ceilf"] = true;
    //~ m_func_wrappers_available["ceil"] = true;
    //~ m_func_wrappers_available["chdir"] = true;
    //~ m_func_wrappers_available["chown"] = true;
    //~ m_func_wrappers_available["chroot"] = true;
    //~ m_func_wrappers_available["clock"] = true;
    //~ m_func_wrappers_available["closedir"] = true;
    //~ m_func_wrappers_available["close"] = true;
    //~ m_func_wrappers_available["cosf"] = true;
    //~ m_func_wrappers_available["cosl"] = true;
    //~ m_func_wrappers_available["cos"] = true;
    //~ m_func_wrappers_available["ctime"] = true;
    //~ m_func_wrappers_available["__ctype_b_loc"] = true;
    //~ m_func_wrappers_available["__ctype_tolower_loc"] = true;
    //~ m_func_wrappers_available["__ctype_toupper_loc"] = true;
    //~ m_func_wrappers_available["difftime"] = true;
    //~ m_func_wrappers_available["drand48"] = true;
    //~ m_func_wrappers_available["__errno_location"] = true;
    //~ m_func_wrappers_available["exit"] = true;
    //~ m_func_wrappers_available["exp2"] = true;
    //~ m_func_wrappers_available["expf"] = true;
    //~ m_func_wrappers_available["exp"] = true;
    //~ m_func_wrappers_available["fabsf"] = true;
    //~ m_func_wrappers_available["fabs"] = true;
    //~ m_func_wrappers_available["fclose"] = true;
    //~ m_func_wrappers_available["fdopen"] = true;
    //~ m_func_wrappers_available["feof"] = true;
    //~ m_func_wrappers_available["ferror"] = true;
    //~ m_func_wrappers_available["fflush"] = true;
    //~ m_func_wrappers_available["fgetc"] = true;
    //~ m_func_wrappers_available["fgets"] = true;
    //~ m_func_wrappers_available["fileno"] = true;
    //~ m_func_wrappers_available["floorf"] = true;
    //~ m_func_wrappers_available["floor"] = true;
    //~ m_func_wrappers_available["fopen"] = true;
    //~ m_func_wrappers_available["fputc"] = true;
    //~ m_func_wrappers_available["fputs"] = true;
    //~ m_func_wrappers_available["fread"] = true;
    m_func_wrappers_available["free"] = true;
    //~ m_func_wrappers_available["fseek"] = true;
    //~ m_func_wrappers_available["fstat"] = true;
    //~ m_func_wrappers_available["ftell"] = true;
    //~ m_func_wrappers_available["ftruncate"] = true;
    //~ m_func_wrappers_available["fwrite"] = true;
    //~ m_func_wrappers_available["getcwd"] = true;
    //~ m_func_wrappers_available["getenv"] = true;
    //~ m_func_wrappers_available["getrlimit"] = true;
    //~ m_func_wrappers_available["gets"] = true;
    //~ m_func_wrappers_available["gettimeofday"] = true;
    //~ m_func_wrappers_available["getuid"] = true;
    //~ m_func_wrappers_available["isatty"] = true;
    //~ m_func_wrappers_available["ldexp"] = true;
    //~ m_func_wrappers_available["localtime"] = true;
    //~ m_func_wrappers_available["log10"] = true;
    //~ m_func_wrappers_available["log"] = true;
    //~ m_func_wrappers_available["lrand48"] = true;
    //~ m_func_wrappers_available["lseek"] = true;
    m_func_wrappers_available["main"] = true;
    m_func_wrappers_available["malloc"] = true;
    //~ m_func_wrappers_available["memchr"] = true;
    //~ m_func_wrappers_available["memcmp"] = true;
    //~ m_func_wrappers_available["mkdir"] = true;
    //~ m_func_wrappers_available["mkstemp"] = true;
    m_func_wrappers_available["mmap"] = true;
    //~ m_func_wrappers_available["opendir"] = true;
    //~ m_func_wrappers_available["open"] = true;
    //~ m_func_wrappers_available["pclose"] = true;
    //~ m_func_wrappers_available["perror"] = true;
    //~ m_func_wrappers_available["popen"] = true;
    //~ m_func_wrappers_available["pow"] = true;
    //~ m_func_wrappers_available["putchar"] = true;
    //~ m_func_wrappers_available["qsort"] = true;
    //~ m_func_wrappers_available["rand"] = true;
    //~ m_func_wrappers_available["readdir"] = true;
    //~ m_func_wrappers_available["read"] = true;
    m_func_wrappers_available["realloc"] = true;
    //~ m_func_wrappers_available["remove"] = true;
    //~ m_func_wrappers_available["rename"] = true;
    //~ m_func_wrappers_available["rewind"] = true;
    //~ m_func_wrappers_available["rindex"] = true;
    //~ m_func_wrappers_available["rmdir"] = true;
    //~ m_func_wrappers_available["select"] = true;
    //~ m_func_wrappers_available["setbuf"] = true;
    //~ m_func_wrappers_available["setreuid"] = true;
    //~ m_func_wrappers_available["setrlimit"] = true;
    //~ m_func_wrappers_available["signal"] = true;
    //~ m_func_wrappers_available["sinf"] = true;
    //~ m_func_wrappers_available["sinl"] = true;
    //~ m_func_wrappers_available["sin"] = true;
    //~ m_func_wrappers_available["sleep"] = true;
    //~ m_func_wrappers_available["sqrtf"] = true;
    //~ m_func_wrappers_available["sqrt"] = true;
    //~ m_func_wrappers_available["srand48"] = true;
    //~ m_func_wrappers_available["srand"] = true;
    //~ m_func_wrappers_available["stat"] = true;
    //~ m_func_wrappers_available["strcasecmp"] = true;
    //~ m_func_wrappers_available["strcat"] = true;
    //~ m_func_wrappers_available["strchr"] = true;
    //~ m_func_wrappers_available["strcmp"] = true;
    //~ m_func_wrappers_available["strcpy"] = true;
    //~ m_func_wrappers_available["strcspn"] = true;
    //~ m_func_wrappers_available["strdup"] = true;
    //~ m_func_wrappers_available["strerror"] = true;
    //~ m_func_wrappers_available["strftime"] = true;
    //~ m_func_wrappers_available["strlen"] = true;
    //~ m_func_wrappers_available["strncasecmp"] = true;
    //~ m_func_wrappers_available["strncat"] = true;
    //~ m_func_wrappers_available["strncmp"] = true;
    //~ m_func_wrappers_available["strncpy"] = true;
    //~ m_func_wrappers_available["strpbrk"] = true;
    //~ m_func_wrappers_available["strrchr"] = true;
    //~ m_func_wrappers_available["strspn"] = true;
    //~ m_func_wrappers_available["strstr"] = true;
    //~ m_func_wrappers_available["strtod"] = true;
    //~ m_func_wrappers_available["strtok"] = true;
    //~ m_func_wrappers_available["strtol"] = true;
    //~ m_func_wrappers_available["strtoul"] = true;
    //~ m_func_wrappers_available["system"] = true;
    //~ m_func_wrappers_available["tanf"] = true;
    //~ m_func_wrappers_available["tanl"] = true;
    //~ m_func_wrappers_available["tan"] = true;
    //~ m_func_wrappers_available["times"] = true;
    //~ m_func_wrappers_available["time"] = true;
    //~ m_func_wrappers_available["tmpfile"] = true;
    //~ m_func_wrappers_available["tolower"] = true;
    //~ m_func_wrappers_available["toupper"] = true;
    //~ m_func_wrappers_available["umask"] = true;
    //~ m_func_wrappers_available["unlink"] = true;
    //~ m_func_wrappers_available["write"] = true;

    m_func_def_softbound["asprintf"] = true;
    m_func_def_softbound["compare_pic_by_pic_num_desc"] = true;
    m_func_def_softbound["dup2"] = true;
    m_func_def_softbound["dup"] = true;
    m_func_def_softbound["error"] = true;
    m_func_def_softbound["execlp"] = true;
    m_func_def_softbound["execl"] = true;
    m_func_def_softbound["execv"] = true;
    m_func_def_softbound["_exit"] = true;
    m_func_def_softbound["fcntl"] = true;
    m_func_def_softbound["fflush_unlocked"] = true;
    m_func_def_softbound["flockfile"] = true;
    m_func_def_softbound["fork"] = true;
    m_func_def_softbound["__fpending"] = true;
    m_func_def_softbound["fprintf"] = true;
    m_func_def_softbound["fscanf"] = true;
    m_func_def_softbound["full_write"] = true;
    m_func_def_softbound["funlockfile"] = true;
    m_func_def_softbound["fwrite_unlocked"] = true;
    m_func_def_softbound["__hashProbeAddrOfPtr"] = true;
    m_func_def_softbound["ioctl"] = true;
    m_func_def_softbound["_IO_getc"] = true;
    m_func_def_softbound["_IO_putc"] = true;
    m_func_def_softbound["longjmp"] = true;
    m_func_def_softbound["__memcopyCheck_i64"] = true;
    m_func_def_softbound["__memcopyCheck"] = true;
    m_func_def_softbound["__option_is_short"] = true;
    m_func_def_softbound["__overflow"] = true;
    m_func_def_softbound["pipe"] = true;
    m_func_def_softbound["printf"] = true;
    m_func_def_softbound["puts"] = true;
    m_func_def_softbound["safe_calloc"] = true;
    m_func_def_softbound["safe_free"] = true;
    m_func_def_softbound["safe_malloc"] = true;
    m_func_def_softbound["safe_mmap"] = true;
    m_func_def_softbound["safe_read"] = true;
    m_func_def_softbound["scanf"] = true;
    m_func_def_softbound["select"] = true;
    m_func_def_softbound["_setjmp"] = true;
    m_func_def_softbound["setuid"] = true;
    m_func_def_softbound["__shrinkBounds"] = true;
    m_func_def_softbound["snprintf"] = true;
    m_func_def_softbound["__softboundcets_abort"] = true;
    m_func_def_softbound["__softboundcets_add_to_free_map"] = true;
    m_func_def_softbound["__softboundcets_allocate_lock_location"] = true;
    m_func_def_softbound["__softboundcets_allocate_shadow_stack_space"] = true;
    m_func_def_softbound["__softboundcets_allocation_secondary_trie_allocate_range"] = true;
    m_func_def_softbound["__softboundcets_allocation_secondary_trie_allocate"] = true;
    m_func_def_softbound["__SOFTBOUNDCETS_ASSERT_fail"] = true;
    m_func_def_softbound["SOFTBOUNDCETS_ASSERT"] = true;
    m_func_def_softbound["__softboundcets_check_remove_from_free_map"] = true;
    m_func_def_softbound["__softboundcets_copy_metadata"] = true;
    m_func_def_softbound["__softboundcets_deallocate_shadow_stack_space"] = true;
    m_func_def_softbound["__softboundcets_dummy"] = true;
    m_func_def_softbound["__softboundcets_get_global_lock"] = true;
    m_func_def_softbound["__softboundcets_global_init"] = true;
    m_func_def_softbound["__softboundcets_init"] = true;
    m_func_def_softbound["__softboundcets_intermediate"]= true;
    m_func_def_softbound["__softboundcets_introspect_metadata"] = true;
    m_func_def_softbound["__softboundcets_load_base_shadow_stack"] = true;
    m_func_def_softbound["__softboundcets_load_bound_shadow_stack"] = true;
    m_func_def_softbound["__softboundcets_load_key_shadow_stack"] = true;
    m_func_def_softbound["__softboundcets_load_lock_shadow_stack"] = true;
    m_func_def_softbound["__softboundcets_memcopy_check"] = true;
    m_func_def_softbound["__softboundcets_memory_allocation"] = true;
    m_func_def_softbound["__softboundcets_memory_deallocation"] = true;
    m_func_def_softbound["__softboundcets_metadata_load"] = true;
    m_func_def_softbound["__softboundcets_metadata_load_vector"] = true;
    m_func_def_softbound["__softboundcets_metadata_store"] = true;
    m_func_def_softbound["__softboundcets_metadata_store_vector"] = true;
    m_func_def_softbound["__softboundcets_printf"] = true;
    m_func_def_softbound["__softboundcets_print_metadata"] = true;
    m_func_def_softbound["__softboundcets_spatial_call_dereference_check"] = true;
    m_func_def_softbound["__softboundcets_spatial_load_dereference_check"] = true;
    m_func_def_softbound["__softboundcets_spatial_store_dereference_check"] = true;
    m_func_def_softbound["__softboundcets_stack_memory_allocation"] = true;
    m_func_def_softbound["__softboundcets_stack_memory_deallocation"] = true;
    m_func_def_softbound["__softboundcets_store_base_shadow_stack"] = true;
    m_func_def_softbound["__softboundcets_store_bound_shadow_stack"] = true;
    m_func_def_softbound["__softboundcets_store_key_shadow_stack"] = true;
    m_func_def_softbound["__softboundcets_store_lock_shadow_stack"] = true;
    m_func_def_softbound["__softboundcets_stub"] = true;
    m_func_def_softbound["__softboundcets_temporal_load_dereference_check"] = true;
    m_func_def_softbound["__softboundcets_temporal_store_dereference_check"] = true;
    m_func_def_softbound["__softboundcets_trie_allocate"] = true;
    m_func_def_softbound["sprintf"] = true;
    m_func_def_softbound["sscanf"] = true;
    m_func_def_softbound["__strcspn_c2"] = true;
    m_func_def_softbound["__stroul_internal"] = true;
    m_func_def_softbound["__strspn_c2"] = true;
    m_func_def_softbound["__strtod_internal"] = true;
    m_func_def_softbound["__strtol_internal"] = true;
    m_func_def_softbound["__strtoul_internal"] = true;
    m_func_def_softbound["__uflow"] = true;
    m_func_def_softbound["vasprintf"] = true;
    m_func_def_softbound["vfprintf"] = true;
    m_func_def_softbound["vsnprintf"] = true;
    m_func_def_softbound["vsprintf"] = true;
    m_func_def_softbound["waitpid"] = true;
    m_func_def_softbound["wprintf"] = true;

  }

  // Is the function name in the above list?
  if (m_func_def_softbound.count(str) > 0) {
    return true;
  }

  // FIXME: handling new intrinsics which have isoc99 in their name
  if (str.find("isoc99") != std::string::npos){
    return true;
  }

  // If the function is an llvm intrinsic, don't transform it
  if (str.find("llvm.") == 0) {
    return true;
  }

  return false;
}

//
// Method: markFunctionsToInstrument
//
// Description: This function traverses the module and identifies the
// functions that need to be transformed by SoftBound/CETS
//

void SoftBoundCETSImpl::markFunctionsToInstrument(Module& module) {

  for (Module::iterator fb_it = module.begin(), fe_it = module.end();
      fb_it != fe_it; ++fb_it) {

    Function* func = dyn_cast<Function>(fb_it);
    SOFTBOUNDCETS_ASSERT(func && " Not a function");

    // Check if the function is defined in the module
    if (!func->isDeclaration()) {
      if (isFuncDefSoftBound(func->getName().str()))
        continue;

      m_func_softboundcets_transform[func->getName().str()] = true;

      const Type* ret_type = func->getReturnType();
      if (isa<PointerType>(ret_type)) {
        m_func_to_transform[func->getName().str()] = true;
      } else {
        for (Function::arg_iterator i = func->arg_begin(),
             e = func->arg_end(); i != e; ++i) {
          if (isa<PointerType>(i->getType())) {
            m_func_to_transform[func->getName().str()] = true;
          }
        }
      }
    }
  }
}

void SoftBoundCETSImpl::markInitialGlobals(Module& module) {

  for(Module::global_iterator it = module.global_begin(),
        ite = module.global_end();
      it != ite; ++it) {

    GlobalVariable* gv = dyn_cast<GlobalVariable>(it);
    if (gv) {
      m_initial_globals[gv] = true;
    }
  }
}

void SoftBoundCETSImpl::addBaseBoundGlobals(Module& M){
  for(Module::global_iterator it = M.global_begin(), ite = M.global_end(); it != ite; ++it){

    GlobalVariable* gv = dyn_cast<GlobalVariable>(it);

    if (!gv){
      continue;
    }

    if (StringRef(gv->getSection()) == "llvm.metadata"){
      continue;
    }

    if (gv->getName() == "llvm.global_ctors"){
      continue;
    }

    if (!gv->hasInitializer())
      continue;

    Constant* initializer = dyn_cast<Constant>(it->getInitializer());

    if (initializer){
      if (isa<StructType>(initializer->getType())){
        std::vector<Constant*> indices_addr_ptr;
        Constant* index1 = ConstantInt::get(Type::getInt32Ty(M.getContext()), 0);
        indices_addr_ptr.push_back(index1);
        StructType* struct_type = dyn_cast<StructType>(initializer->getType());
        handleGlobalStructTypeInitializer(M, struct_type, initializer, gv, indices_addr_ptr, 1);
        continue;
      }

      if (isa<ArrayType>(initializer->getType()) || isa<PointerType>(initializer->getType())){
        handleGlobalSequentialTypeInitializer(M, gv);
      }
    }

    ConstantArray* constant_array = dyn_cast<ConstantArray>(initializer);

    if (!constant_array) {
      continue;
    }

    int num_ca_opds = constant_array->getNumOperands();

    for(int i = 0; i < num_ca_opds; i++) {
      Value* initializer_opd = constant_array->getOperand(i);
      Instruction* first = getGlobalInitInstruction(M);
      Value* operand_base = NULL;
      Value* operand_bound = NULL;

      Constant* global_constant_initializer = dyn_cast<Constant>(initializer_opd);
      if (!isa<PointerType>(global_constant_initializer->getType())){
        break;
      }

      getConstantExprBaseBound(global_constant_initializer, operand_base, operand_bound);

      SmallVector<Value*, 8> args;
      Constant* index1 = ConstantInt::get(Type::getInt32Ty(M.getContext()), 0);
      Constant* index2 = ConstantInt::get(Type::getInt32Ty(M.getContext()), i);

      std::vector<Constant*> indices_addr_ptr;
      indices_addr_ptr.push_back(index1);
      indices_addr_ptr.push_back(index2);

      Constant* addr_of_ptr = ConstantExpr::getGetElementPtr(nullptr, gv, indices_addr_ptr);
      Type* initializer_type = initializer_opd->getType();
      Value* initializer_size = util::getSizeOfType(initializer_type, m_is_64_bit);

      Value* operand_key = m_constantint_one;
      Value* operand_lock = introduceGlobalLockFunction(first);

      emitStoreBaseBound(addr_of_ptr, operand_base, operand_bound, operand_key, operand_lock, initializer_opd, initializer_size, first);
    }
  }
}

//
// Method: introduceGlobalLockFunction()
//
// Description:
//
// This function introduces the function to retrieve the lock for the
// global variables. This function should be introduced only once for
// every function in the entry block of the function.
//

Value* SoftBoundCETSImpl::introduceGlobalLockFunction(Instruction* insert_at){

  SmallVector<Value*, 8> args;
  Value* call_inst = CallInst::Create(m_temporal_global_lock_function,
                                      args, "", insert_at);
  return call_inst;
}

//
// Method: emitStoreBaseBound
//
// Description:
//
// This function inserts metadata stores into the bitcode whenever a
// pointer is being stored to memory.
//
// Inputs:
//
// pointer_dest: address where the pointer being stored
//
// pointer_base, pointer_bound, pointer_key, pointer_lock: metadata
// associated with the pointer being stored
//
// pointer : pointer being stored to memory
//
// size_of_type: size of the access
//
// insert_at: the insertion point in the bitcode before which the
// metadata store is introduced.
//
void SoftBoundCETSImpl::emitStoreBaseBound(Value* pointer_dest,
                                           Value* pointer_base,
                                           Value* pointer_bound,
                                           Value* pointer_key,
                                           Value* pointer_lock,
                                           Value* pointer,
                                           Value* size_of_type,
                                           Instruction* insert_at) {

  Value* pointer_base_cast = util::castToVoidPtr(pointer_base, insert_at);
  Value* pointer_bound_cast = util::castToVoidPtr(pointer_bound, insert_at);
  Value* pointer_dest_cast = util::castToVoidPtr(pointer_dest, insert_at);

  SmallVector<Value*, 8> args;

  args.push_back(pointer_dest_cast);
  args.push_back(pointer_base_cast);
  args.push_back(pointer_bound_cast);
  args.push_back(pointer_key);
  args.push_back(pointer_lock);

  CallInst::Create(m_store_base_bound_func, args, "", insert_at);
}

//
// Method: propagateMetadata
//
// Descripton;
//
// This function propagates the metadata from the source to the
// destination in the map for pointer arithmetic operations~(gep) and
// bitcasts. This is the place where we need to shrink bounds.
//

void
SoftBoundCETSImpl::propagateMetadata(Value* pointer_operand,
                                     Instruction* inst,
                                     int instruction_type){

  if (isBaseBoundMetadataPresent(inst) && isKeyLockMetadataPresent(inst)) {
    return;
  }

  if (isa<ConstantPointerNull>(pointer_operand)) {
    associateBaseBound(inst, m_void_null_ptr, m_void_null_ptr);
    associateKeyLock(inst, m_constantint64ty_zero, m_void_null_ptr);
    return;
  }

  if (isBaseBoundMetadataPresent(pointer_operand)) {
    Value* tmp_base = getAssociatedBase(pointer_operand);
    Value* tmp_bound = getAssociatedBound(pointer_operand);

    associateBaseBound(inst, tmp_base, tmp_bound);
  } else {
    if (isa<Constant>(pointer_operand)) {
      Value* tmp_base = NULL;
      Value* tmp_bound = NULL;
      Constant* given_constant = dyn_cast<Constant>(pointer_operand);
      getConstantExprBaseBound(given_constant, tmp_base, tmp_bound);
      SOFTBOUNDCETS_ASSERT(tmp_base && "gep with cexpr and base null?");
      SOFTBOUNDCETS_ASSERT(tmp_bound && "gep with cexpr and bound null?");
      tmp_base = util::castToVoidPtr(tmp_base, inst);
      tmp_bound = util::castToVoidPtr(tmp_bound, inst);

      associateBaseBound(inst, tmp_base, tmp_bound);
    }
  }

  if (isKeyLockMetadataPresent(pointer_operand)){
    Value* tmp_key = getAssociatedKey(pointer_operand);
    Value* func_lock = getAssociatedFuncLock(inst);
    Value* tmp_lock = getAssociatedLock(pointer_operand, func_lock);

    associateKeyLock(inst, tmp_key, tmp_lock);
  } else {
    if (isa<Constant>(pointer_operand)){
      Value* func_lock =
        m_func_global_lock[inst->getParent()->getParent()->getName()];

      associateKeyLock(inst, m_constantint64ty_one, func_lock);
    }
  }
}

//
// Method: getGlobalVariableBaseBound

// Description: This function returns the base and bound for the
// global variables in the input reference arguments. This function
// may now be obsolete. We should try to use getConstantExprBaseBound
// instead in all places.
void
SoftBoundCETSImpl::getGlobalVariableBaseBound(Value* operand,
                                              Value* & operand_base,
                                              Value* & operand_bound){

  GlobalVariable* gv = dyn_cast<GlobalVariable>(operand);
  Module* module = gv->getParent();
  SOFTBOUNDCETS_ASSERT(gv && "[getGlobalVariableBaseBound] not a global variable?");

  std::vector<Constant*> indices_base;
  Constant* index_base =
    ConstantInt::get(Type::getInt32Ty(module->getContext()), 0);
  indices_base.push_back(index_base);

  Constant* base_exp = ConstantExpr::getGetElementPtr(nullptr, gv, indices_base);

  std::vector<Constant*> indices_bound;
  Constant* index_bound =
    ConstantInt::get(Type::getInt32Ty(module->getContext()), 1);
  indices_bound.push_back(index_bound);

  Constant* bound_exp = ConstantExpr::getGetElementPtr(nullptr, gv, indices_bound);

  operand_base = base_exp;
  operand_bound = bound_exp;
}

//
// Method: emitShadowStackAllocation
//
// Description: For every function call that has a pointer argument or
// a return value, shadow stack is used to propagate metadata. This
// function inserts the shadow stack allocation C-handler that
// reserves space in the shadow stack by reserving the requiste amount
// of space based on the input passed to it(number of pointer
// arguments/return).


void SoftBoundCETSImpl::emitShadowStackAllocation(CallInst* call_inst){

  // Count the number of pointer arguments and whether a pointer return
  int pointer_args_return = util::getNumPointerArgsAndReturn(call_inst);
  if (pointer_args_return == 0)
    return;
  Value* total_ptr_args;
  total_ptr_args =
    ConstantInt::get(Type::getInt32Ty(call_inst->getType()->getContext()),
                     pointer_args_return, false);

  SmallVector<Value*, 8> args;
  args.push_back(total_ptr_args);
  CallInst::Create(m_shadow_stack_allocate, args, "", call_inst);
}

//
// Method: emitShadowStackInitialization
//
// Description: This function inserts a call to the shadow stack store
// C-handler that stores the metadata, before the function call in the
// bitcode for pointer arguments.

void
SoftBoundCETSImpl::emitShadowStackInitialization(Value* ptr_value,
                                                 Instruction* insert_at,
                                                 int arg_no){
  if (!isa<PointerType>(ptr_value->getType()))
    return;

  Value* argno_value;
  argno_value =
    ConstantInt::get(Type::getInt32Ty(ptr_value->getType()->getContext()),
                     arg_no, false);

  Value* ptr_base = getAssociatedBase(ptr_value);
  Value* ptr_bound = getAssociatedBound(ptr_value);

  Value* ptr_base_cast = util::castToVoidPtr(ptr_base, insert_at);
  Value* ptr_bound_cast = util::castToVoidPtr(ptr_bound, insert_at);

  SmallVector<Value*, 8> args;
  args.push_back(ptr_base_cast);
  args.push_back(argno_value);
  CallInst::Create(m_shadow_stack_base_store, args, "", insert_at);

  args.clear();
  args.push_back(ptr_bound_cast);
  args.push_back(argno_value);
  CallInst::Create(m_shadow_stack_bound_store, args, "", insert_at);

  Value* ptr_key = getAssociatedKey(ptr_value);
  Value* func_lock = getAssociatedFuncLock(insert_at);
  Value* ptr_lock = getAssociatedLock(ptr_value, func_lock);

  args.clear();
  args.push_back(ptr_key);
  args.push_back(argno_value);
  CallInst::Create(m_shadow_stack_key_store, args, "", insert_at);

  args.clear();
  args.push_back(ptr_lock);
  args.push_back(argno_value);
  CallInst::Create(m_shadow_stack_lock_store, args, "", insert_at);
}

void SoftBoundCETSImpl::emitShadowStackInitialization(CallInst* call_inst) {

  int pointer_args_return = util::getNumPointerArgsAndReturn(call_inst);

  if (pointer_args_return == 0)
    return;

  int pointer_arg_no = 1;

  for(Value* arg_value : call_inst->args()){
    if (isa<PointerType>(arg_value->getType())){
      emitShadowStackInitialization(arg_value, call_inst, pointer_arg_no);
      pointer_arg_no++;
    }
  }
}

//
// Method: emitShadowStackDeallocation
//
// Description: This function inserts a call to the C-handler that
// deallocates the shadow stack space on function exit.

void SoftBoundCETSImpl::emitShadowStackDeallocation(CallInst* call_inst,
                                                    Instruction* insert_at) {

  int pointer_args_return = util::getNumPointerArgsAndReturn(call_inst);
  if (pointer_args_return == 0)
    return;
  SmallVector<Value*, 8> args;
  CallInst::Create(m_shadow_stack_deallocate, args, "", insert_at);
}

//
// Method: emitShadowStackChecks
//
// Description: This function introduces calls to the C-handlers that
// performs the loads from the shadow stack to retrieve the metadata.
// This function also associates the loaded metadata with the pointer
// arguments in the SoftBound/CETS maps.

void
SoftBoundCETSImpl::emitShadowStackChecks(Value* ptr_value,
                                         Instruction* insert_at,
                                         int arg_no) {

  if (!isa<PointerType>(ptr_value->getType()))
    return;

  Value* argno_value;
  argno_value =
    ConstantInt::get(Type::getInt32Ty(ptr_value->getType()->getContext()),
                     arg_no, false);

  SmallVector<Value*, 8> args;

  args.clear();
  args.push_back(argno_value);
  Value* base = CallInst::Create(m_shadow_stack_base_load, args, "",
                                 insert_at);
  args.clear();
  args.push_back(argno_value);
  Value* bound = CallInst::Create(m_shadow_stack_bound_load, args, "",
                                  insert_at);
  associateBaseBound(ptr_value, base, bound);

  args.clear();
  args.push_back(argno_value);
  Value* key = CallInst::Create(m_shadow_stack_key_load, args, "", insert_at);

  args.clear();
  args.push_back(argno_value);
  Value* lock = CallInst::Create(m_shadow_stack_lock_load, args, "",
                                 insert_at);
  associateKeyLock(ptr_value, key, lock);
}

//
// Method: disassociateKeyLock
//
// Description: This function removes the key lock metadata associated
// with the pointer operand in the SoftBound/CETS maps.

void SoftBoundCETSImpl::disassociateKeyLock(Value* pointer_operand){

    if (m_pointer_key.count(pointer_operand)){
      m_pointer_key.erase(pointer_operand);
    }
    if (m_pointer_lock.count(pointer_operand)){
      m_pointer_lock.erase(pointer_operand);
    }
    SOFTBOUNDCETS_ASSERT((m_pointer_key.count(pointer_operand) == 0) &&
           "dissociating key failed");
    SOFTBOUNDCETS_ASSERT((m_pointer_lock.count(pointer_operand) == 0) &&
           "dissociating lock failed");
}
//
// Method: disassociateBaseBound
//
// Description: This function removes the base/bound metadata
// associated with the pointer operand in the SoftBound/CETS maps.

void SoftBoundCETSImpl::disassociateBaseBound(Value* pointer_operand){

  if (m_pointer_base.count(pointer_operand)){
    m_pointer_base.erase(pointer_operand);
  }
  if (m_pointer_bound.count(pointer_operand)){
    m_pointer_bound.erase(pointer_operand);
  }
  SOFTBOUNDCETS_ASSERT((m_pointer_base.count(pointer_operand) == 0) &&
         "dissociating base failed\n");
  SOFTBOUNDCETS_ASSERT((m_pointer_bound.count(pointer_operand) == 0) &&
         "dissociating bound failed");
}

//
// Method: associateKeyLock
//
// Description: This function associates the key lock with the pointer
// operand in the SoftBound/CETS maps.

void SoftBoundCETSImpl::associateKeyLock(Value* pointer_operand,
                                         Value* pointer_key,
                                         Value* pointer_lock){

  if (m_pointer_key.count(pointer_operand)){
    disassociateKeyLock(pointer_operand);
  }

  if (pointer_key->getType() != m_key_type)
    SOFTBOUNDCETS_ASSERT(0 && "key does not the right type ");

  if (pointer_lock->getType() != m_void_ptr_type)
    SOFTBOUNDCETS_ASSERT(0 && "lock does not have the right type");

  m_pointer_key[pointer_operand] = pointer_key;
  if (m_pointer_lock.count(pointer_operand))
    SOFTBOUNDCETS_ASSERT(0 && "lock already has an entry in the map");

  m_pointer_lock[pointer_operand] = pointer_lock;
}

//
// Method: associateBaseBound
//
// Description: This function associates the base bound with the
// pointer operand in the SoftBound/CETS maps.


void SoftBoundCETSImpl::associateBaseBound(Value* pointer_operand,
                                           Value* pointer_base,
                                           Value* pointer_bound){

  if (m_pointer_base.count(pointer_operand)){
    disassociateBaseBound(pointer_operand);
  }

  if (pointer_base->getType() != m_void_ptr_type){
    SOFTBOUNDCETS_ASSERT(0 && "base does not have a void pointer type ");
  }
  m_pointer_base[pointer_operand] = pointer_base;
  if (m_pointer_bound.count(pointer_operand)){
    SOFTBOUNDCETS_ASSERT(0 && "bound map already has an entry in the map");
  }
  if (pointer_bound->getType() != m_void_ptr_type) {
    SOFTBOUNDCETS_ASSERT(0 && "bound does not have a void pointer type ");
  }
  m_pointer_bound[pointer_operand] = pointer_bound;

}

//
// Method: handleBitCast
//
// Description: Propagate metadata from source to destination with
// pointer bitcast operations.

void SoftBoundCETSImpl::handleBitCast(BitCastInst* bitcast_inst) {
  Value* pointer_operand = bitcast_inst->getOperand(0);
  propagateMetadata(pointer_operand, bitcast_inst, SBCETS_BITCAST);
}

//
// Method: handleSelect
//
// This function propagates the metadata with Select IR instruction.
// Select  instruction is also handled in two passes.

void SoftBoundCETSImpl::handleSelect(SelectInst* select_ins, int pass) {

  if (!isa<PointerType>(select_ins->getType()))
    return;

  Value* condition = select_ins->getCondition();
  Value* operand_base[2];
  Value* operand_bound[2];
  Value* operand_key[2];
  Value* operand_lock[2];

  for(unsigned m = 0; m < 2; m++) {
    Value* operand;
    if (m == 0 ) {
      operand = select_ins->getTrueValue();
    } else {
      operand = select_ins->getFalseValue();
    }

    operand_base[m] = NULL;
    operand_bound[m] = NULL;
    if (isBaseBoundMetadataPresent(operand)) {
      operand_base[m] = getAssociatedBase(operand);
      operand_bound[m] = getAssociatedBound(operand);
    }

    if (isa<ConstantPointerNull>(operand) &&
        !isBaseBoundMetadataPresent(operand)) {
      operand_base[m] = m_void_null_ptr;
      operand_bound[m] = m_void_null_ptr;
    }

    Constant* given_constant = dyn_cast<Constant>(operand);
    if (given_constant) {
      getConstantExprBaseBound(given_constant,
                               operand_base[m],
                               operand_bound[m]);
    }
    SOFTBOUNDCETS_ASSERT(operand_base[m] != NULL &&
           "operand doesn't have base with select?");
    SOFTBOUNDCETS_ASSERT(operand_bound[m] != NULL &&
           "operand doesn't have bound with select?");

    // Introduce a bit cast if the types don't match
    if (operand_base[m]->getType() != m_void_ptr_type) {
      operand_base[m] = new BitCastInst(operand_base[m], m_void_ptr_type,
                                        "select.base", select_ins);
    }

    if (operand_bound[m]->getType() != m_void_ptr_type) {
      operand_bound[m] = new BitCastInst(operand_bound[m], m_void_ptr_type,
                                         "select_bound", select_ins);
    }

    operand_key[m] = NULL;
    operand_lock[m] = NULL;
    if (isKeyLockMetadataPresent(operand)){
      operand_key[m] = getAssociatedKey(operand);
      Value* func_lock = getAssociatedFuncLock(select_ins);
      operand_lock[m] = getAssociatedLock(operand, func_lock);
    }

    if (isa<ConstantPointerNull>(operand) &&
        !isKeyLockMetadataPresent(operand)){
      operand_key[m] = m_constantint64ty_zero;
      operand_lock[m] = m_void_null_ptr;
    }

    if (given_constant){
      operand_key[m] = m_constantint64ty_one;
      operand_lock[m] =
        m_func_global_lock[select_ins->getParent()->getParent()->getName()];
    }

    SOFTBOUNDCETS_ASSERT(operand_key[m] != NULL &&
           "operand doesn't have key with select?");
    SOFTBOUNDCETS_ASSERT(operand_lock[m] != NULL &&
           "operand doesn't have lock with select?");

  } // for loop ends

  SelectInst* select_base = SelectInst::Create(condition,
                                               operand_base[0],
                                               operand_base[1],
                                               "select.base",
                                               select_ins);

  SelectInst* select_bound = SelectInst::Create(condition,
                                                operand_bound[0],
                                                operand_bound[1],
                                                "select.bound",
                                                select_ins);
  associateBaseBound(select_ins, select_base, select_bound);

  SelectInst* select_key = SelectInst::Create(condition,
                                              operand_key[0],
                                              operand_key[1],
                                              "select.key",
                                              select_ins);

  SelectInst* select_lock = SelectInst::Create(condition,
                                               operand_lock[0],
                                               operand_lock[1],
                                               "select.lock",
                                               select_ins);
  associateKeyLock(select_ins, select_key, select_lock);
}

//
// Method: isBaseBoundMetadataPresent()
//
// Description:
// Checks if the metadata is present in the SoftBound/CETS maps.

bool
SoftBoundCETSImpl::isBaseBoundMetadataPresent(Value* pointer_operand){

  if (m_pointer_base.count(pointer_operand) &&
     m_pointer_bound.count(pointer_operand)){
      return true;
  }
  return false;
}

//
// Method: isKeyLockMetadataPresent()
//
// Description:
// Checks if the metadata is present in the SoftBound/CETS maps.


bool
SoftBoundCETSImpl::isKeyLockMetadataPresent(Value* pointer_operand){

  if (m_pointer_key.count(pointer_operand) &&
     m_pointer_lock.count(pointer_operand)){
      return true;
  }
  return false;
}

//
// Method: handleReturnInst
//
// Description:
// This function inserts C-handler calls to store
// metadata for return values in the shadow stack.

void SoftBoundCETSImpl::handleReturnInst(ReturnInst* ret){

  Value* pointer = ret->getReturnValue();
  if (pointer == NULL){
    return;
  }
  if (isa<PointerType>(pointer->getType())){
    emitShadowStackInitialization(pointer, ret, 0);
  }
}

//
// Method: handleGlobalSequentialTypeInitializer
//
// Description: This performs the initialization of the metadata for
// the pointers in the global segments that are initialized with
// non-zero values.
//
// Comments: This function requires review and rewrite

void
SoftBoundCETSImpl::handleGlobalSequentialTypeInitializer(Module& module,
                                                         GlobalVariable* gv) {

  // Sequential type can be an array type, a pointer type
  const Type* init_seq_type = gv->getInitializer()->getType();

  Instruction* init_function_terminator = getGlobalInitInstruction(module);
  if (gv->getInitializer()->isNullValue())
    return;

  if (isa<ArrayType>(init_seq_type)){
    const ArrayType* init_array_type = dyn_cast<ArrayType>(init_seq_type);
    if (isa<StructType>(init_array_type->getElementType())){
      // It is an array of structures

      // Check whether the structure has a pointer, if it has a
      // pointer then, we need to store the base and bound of the
      // pointer into the metadata space. However, if the structure
      // does not have any pointer, we can make a quick exit in
      // processing this global
      //

      bool struct_has_pointers = false;
      StructType* init_struct_type =
        dyn_cast<StructType>(init_array_type->getElementType());

      SOFTBOUNDCETS_ASSERT(init_struct_type &&
             "Array of structures and struct type null?");
      unsigned num_struct_elements = init_struct_type->getNumElements();
      for(unsigned i = 0; i < num_struct_elements; i++) {
        Type* element_type = init_struct_type->getTypeAtIndex(i);
        if (isa<PointerType>(element_type)){
          struct_has_pointers = true;
        }
      }
      if (!struct_has_pointers)
        return;

      // Here implies, global variable is an array of structures with
      // a pointer. Thus for each pointer we need to store the base
      // and bound

      size_t num_array_elements = init_array_type->getNumElements();
      ConstantArray* const_array =
        dyn_cast<ConstantArray>(gv->getInitializer());
      if (!const_array)
        return;

      for( unsigned i = 0; i < num_array_elements ; i++) {
        Constant* struct_constant = const_array->getOperand(i);
        SOFTBOUNDCETS_ASSERT(struct_constant &&
               "Initializer structure type but not a constant?");
        // Constant has zero initializer
        if (struct_constant->isNullValue())
          continue;

        for( unsigned j = 0 ; j < num_struct_elements; j++) {
          const Type* element_type = init_struct_type->getTypeAtIndex(j);

          if (isa<PointerType>(element_type)){

            Value* initializer_opd = struct_constant->getOperand(j);
            Value* operand_base = NULL;
            Value* operand_bound = NULL;
            Constant* given_constant = dyn_cast<Constant>(initializer_opd);
            SOFTBOUNDCETS_ASSERT(given_constant &&
                   "[handleGlobalStructTypeInitializer] not a constant?");

            getConstantExprBaseBound(given_constant, operand_base, operand_bound);
            // Creating the address of ptr
            Constant* index0 =
              ConstantInt::get(Type::getInt32Ty(module.getContext()), 0);
            Constant* index1 =
              ConstantInt::get(Type::getInt32Ty(module.getContext()), i);
            Constant* index2 =
              ConstantInt::get(Type::getInt32Ty(module.getContext()), j);

            std::vector<Constant *> indices_addr_ptr;

            indices_addr_ptr.push_back(index0);
            indices_addr_ptr.push_back(index1);
            indices_addr_ptr.push_back(index2);

            Constant* Indices[3] = {index0, index1, index2};
            Constant* addr_of_ptr = ConstantExpr::getGetElementPtr(nullptr, gv, Indices);
            Type* initializer_type = initializer_opd->getType();
            Value* initializer_size = util::getSizeOfType(initializer_type, m_is_64_bit);

            Value* operand_key = NULL;
            Value* operand_lock = NULL;
            operand_key = m_constantint_one;
            operand_lock =
              introduceGlobalLockFunction(init_function_terminator);

            emitStoreBaseBound(addr_of_ptr, operand_base, operand_bound,
                                  operand_key, operand_lock, initializer_opd,
                                  initializer_size, init_function_terminator);
          }
        } // Iterating over struct element ends
      } // Iterating over array element ends
    }/// Array of Structures Ends

    if (isa<PointerType>(init_array_type->getElementType())){
      // It is a array of pointers
    }
  }  // Array type case ends

  if (isa<PointerType>(init_seq_type)){
    // individual pointer stores
    Value* initializer_base = NULL;
    Value* initializer_bound = NULL;
    Value* initializer = gv->getInitializer();
    Constant* given_constant = dyn_cast<Constant>(initializer);
    getConstantExprBaseBound(given_constant,
                             initializer_base,
                             initializer_bound);
    Type* initializer_type = initializer->getType();
    Value* initializer_size = util::getSizeOfType(initializer_type, m_is_64_bit);

    Value* operand_key = NULL;
    Value* operand_lock = NULL;
    operand_key = m_constantint_one;
    operand_lock =
      introduceGlobalLockFunction(init_function_terminator);

    emitStoreBaseBound(gv, initializer_base, initializer_bound, operand_key,
                          operand_lock, initializer, initializer_size,
                          init_function_terminator);
  }

}

// Method: handleGlobalStructTypeInitializer()
//
// Description: handles the global
// initialization for global variables which are of struct type and
// have a pointer as one of their fields and is globally
// initialized
//
// Comments: This function requires review and rewrite

void
SoftBoundCETSImpl::
handleGlobalStructTypeInitializer(Module& module,
                                  StructType* init_struct_type,
                                  Constant* initializer,
                                  GlobalVariable* gv,
                                  std::vector<Constant*> indices_addr_ptr,
                                  int length) {
  // TODO:URGENT: Do I handle nesxted structures
  // has zero initializer
  if (initializer->isNullValue())
    return;

  Instruction* first = getGlobalInitInstruction(module);
  unsigned num_elements = init_struct_type->getNumElements();
  Constant* constant = dyn_cast<Constant>(initializer);
  SOFTBOUNDCETS_ASSERT(constant &&
         "[handleGlobalStructTypeInit] global stype with init but not CA?");

  for(unsigned i = 0; i < num_elements ; i++) {

    StructType* struct_comp_type =
      dyn_cast<StructType>(init_struct_type);
    SOFTBOUNDCETS_ASSERT(struct_comp_type && "not a struct type?");

    Type* element_type = struct_comp_type->getTypeAtIndex(i);
    if (isa<PointerType>(element_type)){
      Value* initializer_opd = constant->getOperand(i);
      Value* operand_base = NULL;
      Value* operand_bound = NULL;

      Value* operand_key = NULL;
      Value* operand_lock = NULL;

      Constant* addr_of_ptr = NULL;

      operand_key = m_constantint_one;
      operand_lock = introduceGlobalLockFunction(first);

      Constant* given_constant = dyn_cast<Constant>(initializer_opd);
      SOFTBOUNDCETS_ASSERT(given_constant &&
             "[handleGlobalStructTypeInitializer] not a constant?");

      getConstantExprBaseBound(given_constant, operand_base, operand_bound);

      // Creating the address of ptr
        //      Constant* index1 =
        //                ConstantInt::get(Type::getInt32Ty(module.getContext()), 0);
      Constant* index2 = ConstantInt::get(Type::getInt32Ty(module.getContext()), i);

      //      indices_addr_ptr.push_back(index1);
      indices_addr_ptr.push_back(index2);
      length++;

      addr_of_ptr = ConstantExpr::getGetElementPtr(nullptr, gv, indices_addr_ptr);

      Type* initializer_type = initializer_opd->getType();
      Value* initializer_size = util::getSizeOfType(initializer_type, m_is_64_bit);
      emitStoreBaseBound(addr_of_ptr, operand_base,
                            operand_bound, operand_key,
                            operand_lock, initializer_opd,
                            initializer_size, first);

      //    if (true){
        indices_addr_ptr.pop_back();
        length--;
        //      }

      continue;
    }
    if (isa<StructType>(element_type)){
      StructType* child_element_type =
        dyn_cast<StructType>(element_type);
      Constant* struct_initializer =
        dyn_cast<Constant>(constant->getOperand(i));
      Constant* index2 =
        ConstantInt::get(Type::getInt32Ty(module.getContext()), i);
      indices_addr_ptr.push_back(index2);
      length++;
      handleGlobalStructTypeInitializer(module, child_element_type,
                                        struct_initializer, gv,
                                        indices_addr_ptr, length);
      indices_addr_ptr.pop_back();
      length--;
      continue;
    }
  }
}

//
// Method: getConstantExprBaseBound
//
// Description: This function uniform handles all global constant
// expression and obtains the base and bound for these expressions
// without introducing any extra IR modifications.

void SoftBoundCETSImpl::getConstantExprBaseBound(Constant* given_constant,
                                                 Value* & tmp_base,
                                                 Value* & tmp_bound){


  if (isa<ConstantPointerNull>(given_constant)){
    tmp_base = m_void_null_ptr;
    tmp_bound = m_void_null_ptr;
    return;
  }

  ConstantExpr* cexpr = dyn_cast<ConstantExpr>(given_constant);
  tmp_base = NULL;
  tmp_bound = NULL;

  if (cexpr) {

    SOFTBOUNDCETS_ASSERT(cexpr && "ConstantExpr and Value* is null??");
    switch(cexpr->getOpcode()) {

    case Instruction::GetElementPtr:
      {
        Constant* internal_constant = dyn_cast<Constant>(cexpr->getOperand(0));
        getConstantExprBaseBound(internal_constant, tmp_base, tmp_bound);
        break;
      }

    case BitCastInst::BitCast:
      {
        Constant* internal_constant = dyn_cast<Constant>(cexpr->getOperand(0));
        getConstantExprBaseBound(internal_constant, tmp_base, tmp_bound);
        break;
      }
    case Instruction::IntToPtr:
      {
        tmp_base = m_void_null_ptr;
        tmp_bound = m_void_null_ptr;
        return;
        break;
      }
    default:
      {
        break;
      }
    } // Switch ends

  } else { // not a constant expression -- perhaps a constant pointer

    const PointerType* func_ptr_type =
      dyn_cast<PointerType>(given_constant->getType());

    if (!func_ptr_type) {
      tmp_base = m_void_null_ptr;
      tmp_bound = m_infinite_bound_ptr;
      return;
    }

    if (isa<FunctionType>(func_ptr_type->getElementType())) {
      tmp_base = m_void_null_ptr;
      tmp_bound = m_infinite_bound_ptr;
      return;
    }
    // Create getElementPtrs to create the base and bound

    std::vector<Constant*> indices_base;
    std::vector<Constant*> indices_bound;

    GlobalVariable* gv = dyn_cast<GlobalVariable>(given_constant);

    // TODO: External globals get zero base and infinite_bound

    if (gv && !gv->hasInitializer()) {
      tmp_base = m_void_null_ptr;
      tmp_bound = m_infinite_bound_ptr;
      return;
    }

    Constant* index_base0 =
      Constant::
      getNullValue(Type::getInt32Ty(given_constant->getType()->getContext()));

    Constant* index_bound0 =
      ConstantInt::
      get(Type::getInt32Ty(given_constant->getType()->getContext()), 1);

    indices_base.push_back(index_base0);
    indices_bound.push_back(index_bound0);

    auto* gep_base = ConstantExpr::getGetElementPtr(nullptr,
              given_constant, indices_base);
    auto* gep_bound = ConstantExpr::getGetElementPtr(nullptr,
               given_constant, indices_bound);

    tmp_base = gep_base;
    tmp_bound = gep_bound;
  }
}


//
// Methods: getAssociatedBase, getAssociatedBound, getAssociatedKey,
// getAssociatedLock
//
// Description: Retrieves the metadata from SoftBound/CETS maps
//

Value*
SoftBoundCETSImpl::getAssociatedBase(Value* pointer_operand) {

  if (isa<Constant>(pointer_operand)){
    Value* base = NULL;
    Value* bound = NULL;
    Constant* ptr_constant = dyn_cast<Constant>(pointer_operand);
    getConstantExprBaseBound(ptr_constant, base, bound);

    if (base->getType() != m_void_ptr_type){
      Constant* base_given_const = dyn_cast<Constant>(base);
      SOFTBOUNDCETS_ASSERT(base_given_const!=NULL);
      Constant* base_const = ConstantExpr::getBitCast(base_given_const, m_void_ptr_type);
      return base_const;
    }
    return base;
  }

  if (!m_pointer_base.count(pointer_operand)){
    //~ pointer_operand->dump();
  }

  SOFTBOUNDCETS_ASSERT(m_pointer_base.count(pointer_operand) &&
         "Base absent. Try compiling with -simplifycfg option?");

  Value* pointer_base = m_pointer_base[pointer_operand];
  SOFTBOUNDCETS_ASSERT(pointer_base && "base present in the map but null?");

  if (pointer_base->getType() != m_void_ptr_type)
    SOFTBOUNDCETS_ASSERT(0 && "base in the map does not have the right type");

  return pointer_base;
}

Value*
SoftBoundCETSImpl::getAssociatedBound(Value* pointer_operand) {

  if (isa<Constant>(pointer_operand)){
    Value* base = NULL;
    Value* bound = NULL;
    Constant* ptr_constant = dyn_cast<Constant>(pointer_operand);
    getConstantExprBaseBound(ptr_constant, base, bound);

    if (bound->getType() != m_void_ptr_type){
      Constant* bound_given_const = dyn_cast<Constant>(bound);
      SOFTBOUNDCETS_ASSERT(bound_given_const != NULL);
      Constant* bound_const = ConstantExpr::getBitCast(bound_given_const, m_void_ptr_type);
      return bound_const;
    }

    return bound;
  }

  SOFTBOUNDCETS_ASSERT(m_pointer_bound.count(pointer_operand) &&
         "Bound absent.");
  Value* pointer_bound = m_pointer_bound[pointer_operand];
  SOFTBOUNDCETS_ASSERT(pointer_bound &&
         "bound present in the map but null?");

  if (pointer_bound->getType() != m_void_ptr_type)
    SOFTBOUNDCETS_ASSERT(0 && "bound in the map does not have the right type");

  return pointer_bound;
}


Value*
SoftBoundCETSImpl::getAssociatedKey(Value* pointer_operand) {

  if (isa<Constant>(pointer_operand)){
    return m_constantint_one;
  }

  if (!m_pointer_key.count(pointer_operand)){
    //~ pointer_operand->dump();
  }
  SOFTBOUNDCETS_ASSERT(m_pointer_key.count(pointer_operand) &&
         "Key absent. Try compiling with -simplifycfg option?");

  Value* pointer_key = m_pointer_key[pointer_operand];
  SOFTBOUNDCETS_ASSERT(pointer_key && "key present in the map but null?");

  if (pointer_key->getType() != m_key_type)
    SOFTBOUNDCETS_ASSERT(0 && "key in the map does not have the right type");

  return pointer_key;
}

Value*
SoftBoundCETSImpl::getAssociatedLock(Value* pointer_operand, Value* func_lock){

  if (isa<GlobalVariable>(pointer_operand)){
    return func_lock;
  }

  if (isa<Constant>(pointer_operand)){
    return func_lock;
  }

  if (!m_pointer_lock.count(pointer_operand)){
    //~ pointer_operand->dump();
  }
  SOFTBOUNDCETS_ASSERT(m_pointer_lock.count(pointer_operand) &&
         "Lock absent. Try compiling with -simplifycfg option?");

  Value* pointer_lock = m_pointer_lock[pointer_operand];
  SOFTBOUNDCETS_ASSERT(pointer_lock && "lock present in the map but null?");

  if (pointer_lock->getType() != m_void_ptr_type)
    SOFTBOUNDCETS_ASSERT(0 && "lock in the map does not have the right type");

  return pointer_lock;
}

//
// Method: transformFunctionName
//
// Description:
//
// This function returns the transformed name for the function. This
// function appends softboundcets_ to the input string.


std::string
SoftBoundCETSImpl::transformFunctionName(const std::string &str) {

  // If the function name starts with this prefix, don't just
  // concatenate, but instead transform the string
  return "softboundcets_" + str;
}


void SoftBoundCETSImpl::addMemcopyMemsetCheck(CallInst* call_inst,
                                              Function* called_func) {

  if (false)
    return;

  SmallVector<Value*, 8> args;

  if (called_func->getName().find("llvm.memcpy") == 0 ||
     called_func->getName().find("llvm.memmove") == 0){

    Value* dest_ptr = call_inst->getArgOperand(0);
    Value* src_ptr  = call_inst->getArgOperand(1);
    Value* size_ptr = call_inst->getArgOperand(2);

    args.push_back(dest_ptr);
    args.push_back(src_ptr);

    Value* cast_size_ptr = size_ptr;
    if (size_ptr->getType() != m_key_type){
      BitCastInst* bitcast = new BitCastInst(size_ptr, m_key_type,
                                             "", call_inst);

      cast_size_ptr = bitcast;

    }

    args.push_back(cast_size_ptr);

    Value* dest_base = getAssociatedBase(dest_ptr);
    Value* dest_bound =getAssociatedBound(dest_ptr);

    Value* src_base = getAssociatedBase(src_ptr);
    Value* src_bound = getAssociatedBound(src_ptr);

    args.push_back(dest_base);
    args.push_back(dest_bound);

    args.push_back(src_base);
    args.push_back(src_bound);

    Value* dest_key = getAssociatedKey(dest_ptr);
    Value* func_lock = getAssociatedFuncLock(call_inst);
    Value* dest_lock = getAssociatedLock(dest_ptr, func_lock);

    Value* src_key = getAssociatedKey(src_ptr);
    Value* src_lock = getAssociatedLock(src_ptr, func_lock);

    args.push_back(dest_key);
    args.push_back(dest_lock);
    args.push_back(src_key);
    args.push_back(src_lock);

    CallInst::Create(m_memcopy_check, args, "", call_inst);
    return;
  }

  if (called_func->getName().find("llvm.memset") == 0){

    args.clear();
    Value* dest_ptr = call_inst->getArgOperand(0);
    // Whats cs.getArgrument(1) return? Why am I not using it?
    Value* size_ptr = call_inst->getArgOperand(2);

    Value* cast_size_ptr = size_ptr;

    if (size_ptr->getType() != m_key_type){
      BitCastInst* bitcast = new BitCastInst(size_ptr, m_key_type,
                                             "", call_inst);
      cast_size_ptr = bitcast;
    }

    args.push_back(dest_ptr);
    args.push_back(cast_size_ptr);

    Value* dest_base = getAssociatedBase(dest_ptr);
    Value* dest_bound = getAssociatedBound(dest_ptr);
    args.push_back(dest_base);
    args.push_back(dest_bound);

    Value* dest_key = getAssociatedKey(dest_ptr);
    Value* func_lock = getAssociatedFuncLock(call_inst);
    Value* dest_lock = getAssociatedLock(dest_ptr, func_lock);

    args.push_back(dest_key);
    args.push_back(dest_lock);

    CallInst::Create(m_memset_check, args, "", call_inst);

    return;
  }
}

//
//
// Method: emitLoadStoreChecks
//
// Description: This function inserts calls to C-handler spatial
// safety check functions and elides the check if the map says it is
// not necessary to check.


void
SoftBoundCETSImpl::emitLoadStoreChecks(Instruction* load_store,
                                      std::map<Value*, int>& FDCE_map) {
  SmallVector<Value*, 8> args;
  Value* pointer_operand = NULL;

  if (isa<LoadInst>(load_store)) {
    if (!true)
      return;

    LoadInst* ldi = dyn_cast<LoadInst>(load_store);
    SOFTBOUNDCETS_ASSERT(ldi && "not a load instruction");
    pointer_operand = ldi->getPointerOperand();
  }

  if (isa<StoreInst>(load_store)){
    if (!true)
      return;

    StoreInst* sti = dyn_cast<StoreInst>(load_store);
    SOFTBOUNDCETS_ASSERT(sti && "not a store instruction");
    // The pointer where the element is being stored is the second
    // operand
    pointer_operand = sti->getOperand(1);
  }

  SOFTBOUNDCETS_ASSERT(pointer_operand && "pointer operand null?");

  if (!false){
    // If it is a null pointer which is being loaded, then it must seg
    // fault, no dereference check here
    if (isa<ConstantPointerNull>(pointer_operand))
      return;

    // Find all uses of pointer operand, then check if it dominates and
    //if so, make a note in the map

    GlobalVariable* gv = dyn_cast<GlobalVariable>(pointer_operand);
    if (gv && false && !(isa<ArrayType>(gv->getType()) || isa<PointerType>(gv->getType()))) {
      return;
    }

    if (true) {
      // Enable dominator based dereference check optimization only when
      // suggested

      if (FDCE_map.count(load_store)) {
        return;
      }

      // FIXME: Add more comments here Iterate over the uses

      for(Value::use_iterator ui = pointer_operand->use_begin(),
            ue = pointer_operand->use_end();
          ui != ue; ++ui) {

        Instruction* temp_inst = dyn_cast<Instruction>(*ui);
        if (!temp_inst)
          continue;

        if (temp_inst == load_store)
          continue;

        if (!isa<LoadInst>(temp_inst) && !isa<StoreInst>(temp_inst))
          continue;

        if (isa<StoreInst>(temp_inst)){
          if (temp_inst->getOperand(1) != pointer_operand){
            // When a pointer is a being stored at at a particular
            // address, don't elide the check
            continue;
          }
        }
      } // Iterating over uses ends
    } // true ends
  }

  Value* tmp_base = NULL;
  Value* tmp_bound = NULL;

  Constant* given_constant = dyn_cast<Constant>(pointer_operand);
  if (given_constant ) {
    if (false)
      return;

    getConstantExprBaseBound(given_constant, tmp_base, tmp_bound);
  }
  else {
    tmp_base = getAssociatedBase(pointer_operand);
    tmp_bound = getAssociatedBound(pointer_operand);
  }

  Value* bitcast_base = util::castToVoidPtr(tmp_base, load_store);
  args.push_back(bitcast_base);

  Value* bitcast_bound = util::castToVoidPtr(tmp_bound, load_store);
  args.push_back(bitcast_bound);

  Value* cast_pointer_operand_value = util::castToVoidPtr(pointer_operand,
                                                    load_store);
  args.push_back(cast_pointer_operand_value);

  // Pushing the size of the type
  Type* pointer_operand_type = pointer_operand->getType();
  Value* size_of_type = util::getSizeOfType(pointer_operand_type, m_is_64_bit);
  args.push_back(size_of_type);

  if (isa<LoadInst>(load_store)){

    CallInst::Create(m_spatial_load_dereference_check, args, "", load_store);
  }
  else{
    CallInst::Create(m_spatial_store_dereference_check, args, "", load_store);
  }

  return;
}

//
// Method: optimizeGlobalAndStackVariables
//
// Description: This function elides temporal safety checks for stack
// and global variables.


bool
SoftBoundCETSImpl::
optimizeGlobalAndStackVariableChecks(Instruction* load_store) {

  Value* pointer_operand = NULL;
  if (isa<LoadInst>(load_store)){
    pointer_operand = load_store->getOperand(0);
  } else{
    pointer_operand = load_store->getOperand(1);
  }

  while (true) {
    if (isa<AllocaInst>(pointer_operand)){
      if (true){
        return true;
      } else{
        return false;
      }
    }

    if (isa<GlobalVariable>(pointer_operand)){
      if (false){
        return true;
      } else{
        return false;
      }
    }

    if (isa<BitCastInst>(pointer_operand)){
      BitCastInst* bitcast_inst = dyn_cast<BitCastInst>(pointer_operand);
      pointer_operand = bitcast_inst->getOperand(0);
      continue;
    }

    if (isa<GetElementPtrInst>(pointer_operand)){
      GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(pointer_operand);
      pointer_operand = gep->getOperand(0);
      continue;
    } else{
      return false;
    }
  }
}

//
// Method: bbTemporalCheckElimination
//
// Description: This function eliminates the redundant temporal safety
// checks in the basic block
//
// Comments: Describe the algorithm here

bool
SoftBoundCETSImpl::bbTemporalCheckElimination(Instruction* load_store,
                                              std::map<Value*, int>& BBTCE_map){

  if (!true)
    return false;

  if (BBTCE_map.count(load_store))
    return true;

  // Check if the operand is a getelementptr, then get the first
  // operand and check for all other load/store instructions in the
  // current basic block and check if they are pointer operands are
  // getelementptrs. If so, check if it is same the pointer being
  // checked now

  Value* pointer_operand = getPointerLoadStore(load_store);

  Value* gep_source = NULL;
  if (isa<GetElementPtrInst>(pointer_operand)) {
    GetElementPtrInst* ptr_gep = cast<GetElementPtrInst>(pointer_operand);
    gep_source = ptr_gep->getOperand(0);
  } else {
    gep_source = pointer_operand;
  }

  // Iterate over all other instructions in this basic block and look
  // for gep_instructions with the same source
  BasicBlock* bb_curr = load_store->getParent();
  SOFTBOUNDCETS_ASSERT(bb_curr && "bb null?");

  Instruction* next_inst = util::getNextInstruction(load_store);
  BasicBlock* next_inst_bb = next_inst->getParent();
  while ((next_inst_bb == bb_curr) &&
        (next_inst != bb_curr->getTerminator())) {

    if (isa<CallInst>(next_inst) && false)
      break;

    if (checkLoadStoreSourceIsGEP(next_inst, gep_source)){
      BBTCE_map[next_inst] = 1;
    }

    next_inst = util::getNextInstruction(next_inst);
    next_inst_bb = next_inst->getParent();
  }
  return false;
}
//
// Method:getPointerLoadStore
//
// Description: This function obtains the pointer operand which is
// being dereferenced in the memory access.

Value*
SoftBoundCETSImpl::getPointerLoadStore(Instruction* load_store) {

  Value* pointer_operand  = NULL;
  if (isa<LoadInst>(load_store)) {
    pointer_operand = load_store->getOperand(0);
  }

  if (isa<StoreInst>(load_store)) {
    pointer_operand = load_store->getOperand(1);
  }
  SOFTBOUNDCETS_ASSERT((pointer_operand != NULL) && "pointer_operand null");
  return pointer_operand;
}

//
// Method : checkLoadSourceIsGEP
//
// Description: This function is used to optimize temporal checks by
// identifying the root object of the pointer being dereferenced.  If
// the pointer being deferenced is a bitcast or a GEP instruction then
// the source of GEP/bitcast is noted and checked to ascertain whether
// any check to the root object has been performed and not killed.
//
// Comments:
//
// TODO: A detailed algorithm here

bool
SoftBoundCETSImpl::checkLoadStoreSourceIsGEP(Instruction* load_store,
                                             Value* gep_source){

  Value* pointer_operand = NULL;

  if (!isa<LoadInst>(load_store) && !isa<StoreInst>(load_store))
    return false;

  if (isa<LoadInst>(load_store)){
    pointer_operand = load_store->getOperand(0);
  }

  if (isa<StoreInst>(load_store)){
    pointer_operand = load_store->getOperand(1);
  }

  SOFTBOUNDCETS_ASSERT(pointer_operand && "pointer_operand null?");

  if (!isa<GetElementPtrInst>(pointer_operand))
    return false;

  GetElementPtrInst* gep_ptr = dyn_cast<GetElementPtrInst>(pointer_operand);
  SOFTBOUNDCETS_ASSERT(gep_ptr && "gep_ptr null?");

  Value* gep_ptr_operand = gep_ptr->getOperand(0);

  if (gep_ptr_operand == gep_source)
    return true;

  return false;
}

//
// Method: funcTemporalCheckElimination
//
// Description: This function elides temporal checks for by performing
// root object identification at the function level.
bool
SoftBoundCETSImpl::funcTemporalCheckElimination(Instruction* load_store,
                                                std::map<Value*, int>& FTCE_map) {

  if (!true)
    return false;

  if (FTCE_map.count(load_store))
    return true;

  BasicBlock* bb_curr = load_store->getParent();
  SOFTBOUNDCETS_ASSERT(bb_curr && "bb null?");

  std::set<BasicBlock*> bb_visited;
  std::queue<BasicBlock*> bb_worklist;

  bb_worklist.push(bb_curr);
  BasicBlock* bb = NULL;
  while (bb_worklist.size() != 0){

    bb = bb_worklist.front();
    SOFTBOUNDCETS_ASSERT(bb && "Not a BasicBlock?");

    bb_worklist.pop();
    if (bb_visited.count(bb)){
      continue;
    }
    bb_visited.insert(bb);

    bool break_flag = false;

    // Iterating over the successors and adding the successors to the
    // work list

    // if this is the current basic block under question
    if (bb == bb_curr) {
      // bbTemporalCheckElimination should handle this
      Instruction* next_inst = util::getNextInstruction(load_store);
      BasicBlock* next_inst_bb = next_inst->getParent();
      while ((next_inst_bb == bb_curr) &&
            (next_inst != bb_curr->getTerminator())) {

        if (isa<CallInst>(next_inst) && false){
          break_flag = true;
          break;
        }

        next_inst = util::getNextInstruction(next_inst);
        next_inst_bb = next_inst->getParent();
      }
    } else {
      for(BasicBlock::iterator i = bb->begin(), ie = bb->end(); i != ie; ++i){
        Instruction* new_inst = dyn_cast<Instruction>(i);
        if (isa<CallInst>(new_inst) && false){
          break_flag = true;
          break;
        }
      } // Iterating over the instructions in the basic block ends
    }

    for(succ_iterator si = succ_begin(bb), se = succ_end(bb); si != se; ++si) {

      if (break_flag)
        break;

      BasicBlock* next_bb = cast<BasicBlock>(*si);
      bb_worklist.push(next_bb);
    }
  } // Worklist algorithm ends
  return false;
}

bool SoftBoundCETSImpl::optimizeTemporalChecks(Instruction* load_store,
                                          std::map<Value*, int>& BBTCE_map,
                                          std::map<Value*, int>& FTCE_map) {

  if (optimizeGlobalAndStackVariableChecks(load_store))
    return true;

  if (bbTemporalCheckElimination(load_store, BBTCE_map))
    return true;

  if (funcTemporalCheckElimination(load_store, FTCE_map))
    return true;

  return false;

}


void
SoftBoundCETSImpl::emitTemporalChecks(Instruction* load_store,
                                     std::map<Value*,int>& BBTCE_map,
                                     std::map<Value*,int>& FTCE_map) {

  SmallVector<Value*, 8> args;
  Value* pointer_operand = NULL;

  if (!false){
    if (optimizeTemporalChecks(load_store, BBTCE_map, FTCE_map))
      return;
  }

  if (isa<LoadInst>(load_store)) {
    if (!true)
      return;

    LoadInst* ldi = dyn_cast<LoadInst>(load_store);
    SOFTBOUNDCETS_ASSERT(ldi && "not a load instruction");
    pointer_operand = ldi->getPointerOperand();
  }

  if (isa<StoreInst>(load_store)){
    if (!true)
      return;

    StoreInst* sti = dyn_cast<StoreInst>(load_store);
    SOFTBOUNDCETS_ASSERT(sti && "not a store instruction");
    // The pointer where the element is being stored is the second
    // operand
    pointer_operand = sti->getOperand(1);
  }

  SOFTBOUNDCETS_ASSERT(pointer_operand && "pointer_operand null?");

  if (!false){
    if (isa<ConstantPointerNull>(pointer_operand))
      return;

    // Do not insert checks for globals and constant expressions
    GlobalVariable* gv = dyn_cast<GlobalVariable>(pointer_operand);
    if (gv) {
      return;
    }
    Constant* given_constant = dyn_cast<Constant>(pointer_operand);
    if (given_constant)
      return;
  }

  Value* tmp_key = NULL;
  Value* tmp_lock = NULL;
  Value* tmp_base = NULL;
  Value* tmp_bound = NULL;

  tmp_key = getAssociatedKey(pointer_operand);
  Value* func_tmp_lock = getAssociatedFuncLock(load_store);
  tmp_lock = getAssociatedLock(pointer_operand, func_tmp_lock);
  tmp_base = getAssociatedBase(pointer_operand);
  tmp_bound = getAssociatedBound(pointer_operand);

  SOFTBOUNDCETS_ASSERT(tmp_key && "[emitTemporalChecks] pointer does not have key?");
  SOFTBOUNDCETS_ASSERT(tmp_lock && "[emitTemporalChecks] pointer does not have lock?");

  Value* bitcast_lock = util::castToVoidPtr(tmp_lock, load_store);
  args.push_back(bitcast_lock);
  args.push_back(tmp_key);
  args.push_back(tmp_base);
  args.push_back(tmp_bound);

  if (isa<LoadInst>(load_store)){
    CallInst::Create(m_temporal_load_dereference_check, args, "", load_store);
  }
  else {
    CallInst::Create(m_temporal_store_dereference_check, args, "", load_store);
  }
  return;
}

void SoftBoundCETSImpl::renameFunctions(Module& module){

  bool change = false;

  do {
    change = false;
    for(Module::iterator ff_begin = module.begin(), ff_end = module.end();
        ff_begin != ff_end; ++ff_begin){

      Function* func_ptr = dyn_cast<Function>(ff_begin);

      if (m_func_transformed.count(func_ptr->getName().str()) ||
         isFuncDefSoftBound(func_ptr->getName().str())) {
        continue;
      }

      m_func_transformed[func_ptr->getName().str()] = true;
      m_func_transformed[transformFunctionName(func_ptr->getName().str())] = true;
      bool is_external = func_ptr->isDeclaration();
      renameFunctionName(func_ptr, module, is_external);
      change = true;
      break;
    }
  } while (change);
}


/* Renames a function by changing the function name to softboundcets_*
   for only those functions have wrappers
 */

void SoftBoundCETSImpl::renameFunctionName(Function* func,
                                            Module& module,
                                            bool external) {

  Type* ret_type = func->getReturnType();
  const FunctionType* fty = func->getFunctionType();
  std::vector<Type*> params;

  if (!m_func_wrappers_available.count(func->getName()))
    return;

  SmallVector<AttributeList, 8> param_attrs_vec;

  int arg_index = 1;

  for(Function::arg_iterator i = func->arg_begin(), e = func->arg_end();
      i != e; ++i, arg_index++) {

    params.push_back(i->getType());
  }

  FunctionType* nfty = FunctionType::get(ret_type, params, fty->isVarArg());
  Function* new_func = Function::Create(nfty, func->getLinkage(), transformFunctionName(func->getName().str()));
  new_func->copyAttributesFrom(func);
  new_func->setAttributes(AttributeList::get(func->getContext(), param_attrs_vec));
  func->getParent()->getFunctionList().insert(func->getIterator(), new_func);

  if (!external) {
    SmallVector<Value*, 16> call_args;
    new_func->getBasicBlockList().splice(new_func->begin(), func->getBasicBlockList());
    Function::arg_iterator arg_i2 = new_func->arg_begin();
    for(Function::arg_iterator arg_i = func->arg_begin(), arg_e = func->arg_end();
        arg_i != arg_e; ++arg_i) {

      arg_i->replaceAllUsesWith(&*arg_i2);
      arg_i2->takeName(&*arg_i);
      ++arg_i2;
      arg_index++;
    }
  }
  func->replaceAllUsesWith(new_func);
  func->eraseFromParent();
}


void SoftBoundCETSImpl::handleAlloca (AllocaInst* alloca_inst,
                                            Value* alloca_key,
                                            Value* alloca_lock,
                                            Value* func_xmm_key_lock,
                                            BasicBlock* bb,
                                            BasicBlock::iterator& i) {

  Value *alloca_inst_value = alloca_inst;

  /* Get the base type of the alloca object For alloca instructions,
   * instructions need to inserted after the alloca instruction LLVM
   * provides interface for inserting before.  So use the iterators
   * and handle the case
   */

  BasicBlock::iterator nextInst = i;
  nextInst++;
  Instruction* next = dyn_cast<Instruction>(nextInst);
  SOFTBOUNDCETS_ASSERT(next && "Cannot increment the instruction iterator?");

  unsigned num_operands = alloca_inst->getNumOperands();

  /* For any alloca instruction, base is bitcast of alloca, bound is bitcast of alloca_ptr + 1
   */
  PointerType* ptr_type = PointerType::get(alloca_inst->getAllocatedType(), 0);
  Type* ty1 = ptr_type;
  //    Value* alloca_inst_temp_value = alloca_inst;
  BitCastInst* ptr = new BitCastInst(alloca_inst, ty1, alloca_inst->getName(), next);

  Value* ptr_base = util::castToVoidPtr(alloca_inst_value, next);

  Value* intBound;

  if (num_operands == 0) {
    if (m_is_64_bit) {
      intBound = ConstantInt::get(Type::getInt64Ty(alloca_inst->getType()->getContext()), 1, false);
    }
    else{
      intBound = ConstantInt::get(Type::getInt32Ty(alloca_inst->getType()->getContext()), 1, false);
    }
  }
  else {
    // What can be operand of alloca instruction?
    intBound = alloca_inst->getOperand(0);
  }

  GetElementPtrInst* gep = GetElementPtrInst::Create(nullptr,
                 ptr,
                                                     intBound,
                                                     "mtmp",
                                                     next);
  Value *bound_ptr = gep;

  Value* ptr_bound = util::castToVoidPtr(bound_ptr, next);

  associateBaseBound(alloca_inst_value, ptr_base, ptr_bound);
  associateKeyLock(alloca_inst_value, alloca_key, alloca_lock);
}

//
// The metadata propagation for PHINode occurs in two passes. In the
// first pass, SoftBound/CETS transformation just creates the metadata
// PHINodes and records it in the maps maintained by
// SoftBound/CETS. In the second pass, it populates the incoming
// values of the PHINodes. This two pass approach ensures that every
// incoming value of the original PHINode will have metadata in the
// SoftBound/CETS maps
//

//
// Method: handlePHIPass1()
//
// Description:
//
// This function creates a PHINode for the metadata in the bitcode for
// pointer PHINodes. It is important to note that this function just
// creates the PHINode and does not populate the incoming values of
// the PHINode, which is handled by the handlePHIPass2.
//

void SoftBoundCETSImpl::handlePHIPass1(PHINode* phi_node) {

  if (!isa<PointerType>(phi_node->getType())) {
    return;
  }

  unsigned num_incoming_values = phi_node->getNumIncomingValues();

  PHINode* base_phi_node = PHINode::Create(m_void_ptr_type,
                                           num_incoming_values,
                                           "phi.base",
                                           phi_node);

  PHINode* bound_phi_node = PHINode::Create(m_void_ptr_type,
                                            num_incoming_values,
                                            "phi.bound",
                                            phi_node);

  Value* base_phi_node_value = base_phi_node;
  Value* bound_phi_node_value = bound_phi_node;

  associateBaseBound(phi_node, base_phi_node_value, bound_phi_node_value);

  PHINode* key_phi_node =
    PHINode::Create(Type::getInt64Ty(phi_node->getType()->getContext()),
                    num_incoming_values,
                    "phi.key", phi_node);

  PHINode* lock_phi_node = PHINode::Create(m_void_ptr_type,
                                           num_incoming_values,
                                           "phi.lock", phi_node);

  associateKeyLock(phi_node, key_phi_node, lock_phi_node);
}


//
// Method: handlePHIPass2()
//
// Description: This pass fills the incoming values for the metadata
// PHINodes inserted in the first pass. There are four cases that
// needs to be handled for each incoming value.  First, if the
// incoming value is a ConstantPointerNull, then base, bound, key,
// lock will be default values.  Second, the incoming value can be an
// undef which results in default metadata values.  Third, Global
// variables need to get the same base and bound for each
// occurence. So we maintain a map which maps the base and boundfor
// each global variable in the incoming value.  Fourth, by default it
// retrieves the metadata from the SoftBound/CETS maps.

void SoftBoundCETSImpl::handlePHIPass2(PHINode* phi_node) {

  if (!isa<PointerType>(phi_node->getType())) {
    return;
  }

  PHINode* base_phi_node = NULL;
  PHINode* bound_phi_node  = NULL;
  PHINode* key_phi_node = NULL;
  PHINode* lock_phi_node = NULL;

  // Obtain the metada PHINodes
  base_phi_node = dyn_cast<PHINode>(getAssociatedBase(phi_node));
  bound_phi_node = dyn_cast<PHINode>(getAssociatedBound(phi_node));
  key_phi_node = dyn_cast<PHINode>(getAssociatedKey(phi_node));
  Value* func_lock = getAssociatedFuncLock(phi_node);
  lock_phi_node= dyn_cast<PHINode>(getAssociatedLock(phi_node, func_lock));

  std::map<Value*, Value*> globals_base;
  std::map<Value*, Value*> globals_bound;
  std::map<Value*, Value*> globals_key;
  std::map<Value*, Value*> globals_lock;

  unsigned num_incoming_values = phi_node->getNumIncomingValues();
  for (unsigned m = 0; m < num_incoming_values; m++) {

    Value* incoming_value = phi_node->getIncomingValue(m);
    BasicBlock* bb_incoming = phi_node->getIncomingBlock(m);

    if (isa<ConstantPointerNull>(incoming_value)) {
      base_phi_node->addIncoming(m_void_null_ptr, bb_incoming);
      bound_phi_node->addIncoming(m_void_null_ptr, bb_incoming);
      key_phi_node->addIncoming(m_constantint64ty_zero, bb_incoming);
      lock_phi_node->addIncoming(m_void_null_ptr, bb_incoming);
      continue;
    }

    if (isa<UndefValue>(incoming_value)) {
      base_phi_node->addIncoming(m_void_null_ptr, bb_incoming);
      bound_phi_node->addIncoming(m_void_null_ptr, bb_incoming);
      key_phi_node->addIncoming(m_constantint64ty_zero, bb_incoming);
      lock_phi_node->addIncoming(m_void_null_ptr, bb_incoming);
      continue;
    }

    Value* incoming_value_base = NULL;
    Value* incoming_value_bound = NULL;
    Value* incoming_value_key  = NULL;
    Value* incoming_value_lock = NULL;

    GlobalVariable* gv = dyn_cast<GlobalVariable>(incoming_value);
    if (gv) {
      if (!globals_base.count(gv)) {
        Value* tmp_base = NULL;
        Value* tmp_bound = NULL;
        getGlobalVariableBaseBound(incoming_value, tmp_base, tmp_bound);
        SOFTBOUNDCETS_ASSERT(tmp_base && "base of a global variable null?");
        SOFTBOUNDCETS_ASSERT(tmp_bound && "bound of a global variable null?");

        Function * PHI_func = phi_node->getParent()->getParent();
        Instruction* PHI_func_entry = &*(PHI_func->begin()->begin());

        incoming_value_base = util::castToVoidPtr(tmp_base, PHI_func_entry);
        incoming_value_bound = util::castToVoidPtr(tmp_bound, PHI_func_entry);

        globals_base[incoming_value] = incoming_value_base;
        globals_bound[incoming_value] = incoming_value_bound;
      } else {
        incoming_value_base = globals_base[incoming_value];
        incoming_value_bound = globals_bound[incoming_value];
      }

      incoming_value_key = m_constantint64ty_one;
      Value* tmp_lock =
        m_func_global_lock[phi_node->getParent()->getParent()->getName()];
      incoming_value_lock = tmp_lock;
    }

    Constant* given_constant = dyn_cast<Constant>(incoming_value);
    if (given_constant) {
      if (!globals_base.count(incoming_value)) {
        Value* tmp_base = NULL;
        Value* tmp_bound = NULL;
        getConstantExprBaseBound(given_constant, tmp_base, tmp_bound);
        SOFTBOUNDCETS_ASSERT(tmp_base && tmp_bound  &&
               "[handlePHIPass2] tmp_base tmp_bound, null?");

        Function* PHI_func = phi_node->getParent()->getParent();
        Instruction* PHI_func_entry = &*(PHI_func->begin()->begin());

        incoming_value_base = util::castToVoidPtr(tmp_base, PHI_func_entry);
        incoming_value_bound = util::castToVoidPtr(tmp_bound, PHI_func_entry);

        globals_base[incoming_value] = incoming_value_base;
        globals_bound[incoming_value] = incoming_value_bound;
      } else{
        incoming_value_base = globals_base[incoming_value];
        incoming_value_bound = globals_bound[incoming_value];
      }

      incoming_value_key = m_constantint64ty_one;
      Value* tmp_lock =
        m_func_global_lock[phi_node->getParent()->getParent()->getName()];
      incoming_value_lock = tmp_lock;
    }

    // handle values having map based pointer base and bounds
    if (isBaseBoundMetadataPresent(incoming_value)){
      incoming_value_base = getAssociatedBase(incoming_value);
      incoming_value_bound = getAssociatedBound(incoming_value);
    }

    if (isKeyLockMetadataPresent(incoming_value)){
      incoming_value_key = getAssociatedKey(incoming_value);
      Value* func_lock = getAssociatedFuncLock(phi_node);
      incoming_value_lock = getAssociatedLock(incoming_value, func_lock);
    }

    SOFTBOUNDCETS_ASSERT(incoming_value_base &&
           "[handlePHIPass2] incoming_value doesn't have base?");
    SOFTBOUNDCETS_ASSERT(incoming_value_bound &&
           "[handlePHIPass2] incoming_value doesn't have bound?");

    base_phi_node->addIncoming(incoming_value_base, bb_incoming);
    bound_phi_node->addIncoming(incoming_value_bound, bb_incoming);

    SOFTBOUNDCETS_ASSERT(incoming_value_key &&
           "[handlePHIPass2] incoming_value doesn't have key?");
    SOFTBOUNDCETS_ASSERT(incoming_value_lock &&
           "[handlePHIPass2] incoming_value doesn't have lock?");

    key_phi_node->addIncoming(incoming_value_key, bb_incoming);
    lock_phi_node->addIncoming(incoming_value_lock, bb_incoming);
  }

  SOFTBOUNDCETS_ASSERT(base_phi_node && "[handlePHIPass2] base_phi_node null?");
  SOFTBOUNDCETS_ASSERT(bound_phi_node && "[handlePHIPass2] bound_phi_node null?");
  SOFTBOUNDCETS_ASSERT(key_phi_node && "[handlePHIPass2] key_phi_node null?");
  SOFTBOUNDCETS_ASSERT(lock_phi_node && "[handlePHIPass2] lock_phi_node null?");

#if !defined(SOFTBOUNDCETS_NO_ASSERTS)
  unsigned n_values = phi_node->getNumIncomingValues();
  unsigned n_base_values = base_phi_node->getNumIncomingValues();
  unsigned n_bound_values = bound_phi_node->getNumIncomingValues();
  SOFTBOUNDCETS_ASSERT((n_values == n_base_values)  &&
         "[handlePHIPass2] number of values different for base");
  SOFTBOUNDCETS_ASSERT((n_values == n_bound_values) &&
         "[handlePHIPass2] number of values different for bound");

  unsigned n_key_values = key_phi_node->getNumIncomingValues();
  unsigned n_lock_values = lock_phi_node->getNumIncomingValues();
  SOFTBOUNDCETS_ASSERT((n_values == n_key_values)  &&
         "[handlePHIPass2] number of values different for key");
  SOFTBOUNDCETS_ASSERT((n_values == n_lock_values) &&
         "[handlePHIPass2] number of values different for lock");
#endif
}

void SoftBoundCETSImpl::handleVectorStore(StoreInst* store_inst){

  Value* operand = store_inst->getValueOperand();
  Value* pointer_dest = store_inst->getPointerOperand();
  Instruction* insert_at = util::getNextInstruction(store_inst);

  if (!m_vector_pointer_base.count(operand)){
    SOFTBOUNDCETS_ASSERT(0 && "vector base not found");
  }
  if (!m_vector_pointer_bound.count(operand)){
    SOFTBOUNDCETS_ASSERT(0 && "vector bound not found");
  }
  if (!m_vector_pointer_key.count(operand)){
    SOFTBOUNDCETS_ASSERT(0 && "vector key not found");
  }
  if (!m_vector_pointer_lock.count(operand)){
    SOFTBOUNDCETS_ASSERT(0 && "vector lock not found");
  }

  Value* vector_base = m_vector_pointer_base[operand];
  Value* vector_bound = m_vector_pointer_bound[operand];
  Value* vector_key = m_vector_pointer_key[operand];
  Value* vector_lock = m_vector_pointer_lock[operand];

  const FixedVectorType* vector_ty = dyn_cast<FixedVectorType>(operand->getType());
  uint64_t num_elements = vector_ty->getNumElements();
  if (num_elements > 2){
    SOFTBOUNDCETS_ASSERT(0 && "more than 2 element vectors not handled");
  }

  Value* pointer_operand_bitcast = util::castToVoidPtr(pointer_dest, insert_at);
  for (uint64_t i = 0; i < num_elements; i++){

    Constant* index = ConstantInt::get(Type::getInt32Ty(store_inst->getContext()), i);

    Value* ptr_base = ExtractElementInst::Create(vector_base, index,"", insert_at);
    Value* ptr_bound = ExtractElementInst::Create(vector_bound, index, "", insert_at);
    Value* ptr_key = ExtractElementInst::Create(vector_key, index, "", insert_at);
    Value* ptr_lock = ExtractElementInst::Create(vector_lock, index, "", insert_at);

    SmallVector<Value*, 8> args;
    args.clear();

    args.push_back(pointer_operand_bitcast);
    args.push_back(ptr_base);
    args.push_back(ptr_bound);
    args.push_back(ptr_key);
    args.push_back(ptr_lock);
    args.push_back(index);

    CallInst::Create(m_metadata_store_vector_func, args, "", insert_at);
  }

}

void SoftBoundCETSImpl::handleStore(StoreInst* store_inst) {

  Value* operand = store_inst->getValueOperand();
  Value* pointer_dest = store_inst->getPointerOperand();
  Instruction* insert_at = util::getNextInstruction(store_inst);

  /*
  if (isa<FixedVectorType>(operand->getType())){
    const FixedVectorType* vector_ty = dyn_cast<FixedVectorType>(operand->getType());
    if (isa<PointerType>(vector_ty->getElementType())){
      handleVectorStore(store_inst);
      return;
    }
  }
  */

  /* If a pointer is being stored, then the base and bound
   * corresponding to the pointer must be stored in the shadow space
   */
  if (!isa<PointerType>(operand->getType()))
    return;


  if (isa<ConstantPointerNull>(operand)) {
    /* it is a constant pointer null being stored
     * store null to the shadow space
     */
    Value* size_of_type = NULL;

    emitStoreBaseBound(pointer_dest, m_void_null_ptr,
                       m_void_null_ptr, m_constantint64ty_zero,
                       m_void_null_ptr, m_void_null_ptr,
                       size_of_type, insert_at);

    return;
  }


  /* if it is a global expression being stored, then add add
   * suitable base and bound
   */

  Value* tmp_base = NULL;
  Value* tmp_bound = NULL;
  Value* tmp_key = NULL;
  Value* tmp_lock = NULL;

  //  Value* xmm_base_bound = NULL;
  //  Value* xmm_key_lock = NULL;

  Constant* given_constant = dyn_cast<Constant>(operand);
  if (given_constant) {
    getConstantExprBaseBound(given_constant, tmp_base, tmp_bound);
    SOFTBOUNDCETS_ASSERT(tmp_base && "global doesn't have base");
    SOFTBOUNDCETS_ASSERT(tmp_bound && "global doesn't have bound");
    tmp_key = m_constantint_one;
    Value* func_lock = m_func_global_lock[store_inst->getParent()->getParent()->getName()];
    tmp_lock = func_lock;
  }
  else {
    /* storing an external function pointer */
    if (!isBaseBoundMetadataPresent(operand)) {
      return;
    }

    if (!isKeyLockMetadataPresent(operand)){
      return;
    }

    tmp_base = getAssociatedBase(operand);
    tmp_bound = getAssociatedBound(operand);
    tmp_key = getAssociatedKey(operand);
    Value* func_lock = getAssociatedFuncLock(store_inst);
    tmp_lock = getAssociatedLock(operand, func_lock);
  }

  /* Store the metadata into the metadata space
   */

  //  Type* stored_pointer_type = operand->getType();
  Value* size_of_type = NULL;
  //    Value* size_of_type  = getSizeOfType(stored_pointer_type, m_is_64_bit);
  emitStoreBaseBound(pointer_dest, tmp_base, tmp_bound, tmp_key, tmp_lock, operand,  size_of_type, insert_at);
}

// Currently just a placeholder for functions introduced by us
bool SoftBoundCETSImpl::isFunctionToInstrument(Function* func) {

  if (isFuncDefSoftBound(func->getName().str()))
    return false;

  if (func->isDeclaration())
    return false;

  return true;
}


Instruction* SoftBoundCETSImpl::getGlobalInitInstruction(Module& module){
  Function* global_init_function = module.getFunction("__softboundcets_global_init");
  SOFTBOUNDCETS_ASSERT(global_init_function && "no __softboundcets_global_init function??");
  Instruction *global_init_terminator = NULL;
  for(Function::iterator fi = global_init_function->begin(), fe = global_init_function->end(); fi != fe; ++fi) {

    BasicBlock* bb = dyn_cast<BasicBlock>(fi);
    SOFTBOUNDCETS_ASSERT(bb && "basic block null");
    Instruction* bb_term = dyn_cast<Instruction>(bb->getTerminator());
    SOFTBOUNDCETS_ASSERT(bb_term && "terminator null?");

    if (isa<ReturnInst>(bb_term)) {
      global_init_terminator = dyn_cast<ReturnInst>(bb_term);
      SOFTBOUNDCETS_ASSERT(global_init_terminator && "return inst null?");
    }
  }
  SOFTBOUNDCETS_ASSERT(global_init_terminator && "global init does not have return");
  return global_init_terminator;
}

void SoftBoundCETSImpl::handleGEP(GetElementPtrInst* gep_inst) {
  Value* getelementptr_operand = gep_inst->getPointerOperand();
  propagateMetadata(getelementptr_operand, gep_inst, SBCETS_GEP);
}

void SoftBoundCETSImpl::handleMemcpy(CallInst* call_inst){

  if (false)
    return;

  Function* func = call_inst->getCalledFunction();
  if (!func)
    return;

  SOFTBOUNDCETS_ASSERT(func && "function is null?");

  Value* arg1 = call_inst->getArgOperand(0);
  Value* arg2 = call_inst->getArgOperand(1);
  Value* arg3 = call_inst->getArgOperand(2);

  SmallVector<Value*, 8> args;
  args.push_back(arg1);
  args.push_back(arg2);
  args.push_back(arg3);

  if (arg3->getType() == Type::getInt64Ty(arg3->getContext())){
    CallInst::Create(m_copy_metadata, args, "", call_inst);
  }
  else{
    //    CallInst::Create(m_copy_metadata, args, "", call_inst);
  }

  return;
}

void SoftBoundCETSImpl::handleExtractElement(ExtractElementInst* EEI){

  if (!isa<PointerType>(EEI->getType()))
     return;

  Value* EEIOperand = EEI->getVectorOperand();

  if (isa<FixedVectorType>(EEIOperand->getType())){

    if (!m_vector_pointer_lock.count(EEIOperand) ||
       !m_vector_pointer_base.count(EEIOperand) ||
       !m_vector_pointer_bound.count(EEIOperand) ||
       !m_vector_pointer_key.count(EEIOperand)){
      SOFTBOUNDCETS_ASSERT(0 && "Extract element does not have vector metadata");
    }

    if (!m_vector_pointer_base.count(EEIOperand)){
      SOFTBOUNDCETS_ASSERT(0 && "vector base not found");
    }
    if (!m_vector_pointer_bound.count(EEIOperand)){
      SOFTBOUNDCETS_ASSERT(0 && "vector bound not found");
    }
    if (!m_vector_pointer_key.count(EEIOperand)){
      SOFTBOUNDCETS_ASSERT(0 && "vector key not found");
    }
    if (!m_vector_pointer_lock.count(EEIOperand)){
      SOFTBOUNDCETS_ASSERT(0 && "vector lock not found");
    }

    Value* vector_base = m_vector_pointer_base[EEIOperand];
    Value* vector_bound = m_vector_pointer_bound[EEIOperand];
    Value* vector_key = m_vector_pointer_key[EEIOperand];
    Value* vector_lock = m_vector_pointer_lock[EEIOperand];

    Value* ptr_base = ExtractElementInst::Create(vector_base, EEI->getIndexOperand(), "", EEI);
    Value* ptr_bound = ExtractElementInst::Create(vector_bound, EEI->getIndexOperand(), "", EEI);
    Value* ptr_key = ExtractElementInst::Create(vector_key, EEI->getIndexOperand(), "", EEI);
    Value* ptr_lock = ExtractElementInst::Create(vector_lock, EEI->getIndexOperand(), "", EEI);

    associateBaseBound(EEI, ptr_base, ptr_bound);
    associateKeyLock(EEI, ptr_key, ptr_lock);
    return;
  }

  SOFTBOUNDCETS_ASSERT (0 && "ExtractElement is returning a pointer, possibly some vectorization going on, not handled, try running with O0 or O1 or O2");

}


void SoftBoundCETSImpl::handleExtractValue(ExtractValueInst* EVI){

  if (isa<PointerType>(EVI->getType())){
    SOFTBOUNDCETS_ASSERT(0 && "ExtractValue is returning a pointer, possibly some vectorization going on, not handled, try running with O0 or O1 or O2");
  }

  associateBaseBound(EVI, m_void_null_ptr, m_infinite_bound_ptr);
  Value* func_temp_lock = getAssociatedFuncLock(EVI);
  associateKeyLock(EVI, m_constantint64ty_one, func_temp_lock);
  return;
}

void SoftBoundCETSImpl::handleCall(CallInst* call_inst) {

  Value* mcall = call_inst;

  Function* func = call_inst->getCalledFunction();
  if (func && ((func->getName().find("llvm.memcpy") == 0) ||
              (func->getName().find("llvm.memmove") == 0))){
    addMemcopyMemsetCheck(call_inst, func);
    handleMemcpy(call_inst);
    return;
  }

  if (func && func->getName().find("llvm.memset") == 0){
    addMemcopyMemsetCheck(call_inst, func);
  }

  if (func && isFuncDefSoftBound(func->getName().str())){

    if (!isa<PointerType>(call_inst->getType())){
      return;
    }

    associateBaseBound(call_inst, m_void_null_ptr, m_void_null_ptr);
    associateKeyLock(call_inst, m_constantint64ty_zero, m_void_null_ptr);
    return;
  }

  Instruction* insert_at = util::getNextInstruction(call_inst);

  emitShadowStackAllocation(call_inst);
  emitShadowStackInitialization(call_inst);

  if (isa<PointerType>(mcall->getType())) {
      /* ShadowStack for the return value is 0 */
      emitShadowStackChecks(call_inst, insert_at, 0);
  }
  emitShadowStackDeallocation(call_inst,insert_at);
}

void SoftBoundCETSImpl::handleIntToPtr(IntToPtrInst* inttoptrinst) {

  Value* inst = inttoptrinst;

  associateBaseBound(inst, m_void_null_ptr, m_void_null_ptr);
  associateKeyLock(inst, m_constantint64ty_zero, m_void_null_ptr);
}

void
SoftBoundCETSImpl::introspectMetadata(Function* func, Value* ptr_value,
                                      Instruction* insert_at, int arg_no){
  if (func->getName() != "debug_instrument_softboundcets")
    return;

  Value* ptr_base = getAssociatedBase(ptr_value);
  Value* ptr_bound = getAssociatedBound(ptr_value);

  Value* ptr_value_cast = util::castToVoidPtr(ptr_value, insert_at);
  Value* ptr_base_cast = util::castToVoidPtr(ptr_base, insert_at);
  Value* ptr_bound_cast = util::castToVoidPtr(ptr_bound, insert_at);

  Value* argno_value;

  argno_value = ConstantInt::get(Type::getInt32Ty(ptr_value->getType()->getContext()),
                                 arg_no, false);

  SmallVector<Value*, 8> args;

  args.push_back(ptr_value_cast);
  args.push_back(ptr_base_cast);
  args.push_back(ptr_bound_cast);
  args.push_back(argno_value);

  CallInst::Create(m_introspect_metadata, args, "", insert_at);

}


void
SoftBoundCETSImpl::freeFunctionKeyLock(Function* func, Value* & func_key,
                                       Value* & func_lock,
                                       Value* & func_xmm_key_lock) {


  if (func_key == NULL && func_lock == NULL){
    return;
  }

  if ((func_key == NULL && func_lock != NULL) && (func_key != NULL && func_lock == NULL)){
    SOFTBOUNDCETS_ASSERT(0 && "inconsistent key lock");
  }

  //  Function::iterator  bb_begin = func->begin();
  Instruction* next_inst = NULL;

  for(Function::iterator b = func->begin(), be = func->end(); b != be ; ++b) {

    BasicBlock* bb = dyn_cast<BasicBlock>(b);
    SOFTBOUNDCETS_ASSERT(bb && "basic block does not exist?");

    for(BasicBlock::iterator i = bb->begin(), ie = bb->end(); i != ie; ++i) {

      next_inst = dyn_cast<Instruction>(i);

      if (!isa<ReturnInst>(next_inst))
        continue;

      ReturnInst* ret = dyn_cast<ReturnInst>(next_inst);
      /* Insert a call to deallocate key and lock*/
      SmallVector<Value*, 8> args;
      SOFTBOUNDCETS_ASSERT(dyn_cast<Instruction>(func->begin()->begin()) && "function doesn't have any instruction ??");
      args.push_back(func_key);
      CallInst::Create(m_temporal_stack_memory_deallocation, args, "", ret);
    }
  }
}

void SoftBoundCETSImpl::emitInstrumentationPhase1 (Function * func) {

  Value* func_key = NULL;
  Value* func_lock = NULL;
  Value* func_xmm_key_lock = NULL;
  int arg_count= 0;

  /* Scan over the pointer arguments and introduce base and bound */

  for(Function::arg_iterator ib = func->arg_begin(), ie = func->arg_end();
      ib != ie; ++ib) {

    if (!isa<PointerType>(ib->getType()))
      continue;

    /* it is a pointer, so increment the arg count */
    arg_count++;

    Argument* ptr_argument = dyn_cast<Argument>(ib);
    Value* ptr_argument_value = ptr_argument;
    Instruction* fst_inst = &*(func->begin()->begin());

    /* Urgent: Need to think about what we need to do about byval attributes */
    if (ptr_argument->hasByValAttr()){

      if (util::checkTypeHasPtrs(ptr_argument)){
        SOFTBOUNDCETS_ASSERT(0 && "Pointer argument has byval attributes and the underlying structure returns pointers");
      }

      associateBaseBound(ptr_argument_value, m_void_null_ptr, m_infinite_bound_ptr);
      Value* func_temp_lock = getAssociatedFuncLock(&*(func->begin()->begin()));
      associateKeyLock(ptr_argument_value, m_constantint64ty_one, func_temp_lock);
    }
    else{
      emitShadowStackChecks(ptr_argument_value, fst_inst, arg_count);
    }
  }

  getFunctionKeyLock(func, func_key, func_lock, func_xmm_key_lock);

  /* WorkList Algorithm for propagating the base and bound. Each
   * basic block is visited only once. We start by visiting the
   * current basic block, then push all the successors of the
   * current basic block on to the queue if it has not been visited
   */
  std::set<BasicBlock*> bb_visited;
  std::queue<BasicBlock*> bb_worklist;
  Function:: iterator bb_begin = func->begin();

  BasicBlock* bb = dyn_cast<BasicBlock>(bb_begin);
  SOFTBOUNDCETS_ASSERT( bb && "Not a basic block and I am gathering base and bound?");
  bb_worklist.push(bb);

  while (bb_worklist.size() != 0) {

    bb = bb_worklist.front();
    SOFTBOUNDCETS_ASSERT(bb && "Not a BasicBlock?");

    bb_worklist.pop();
    if (bb_visited.count(bb)) {
      continue;
    }

    bb_visited.insert(bb);

    /* Iterating over the successors and adding the successors to
     * the work list
     */
    for(succ_iterator si = succ_begin(bb), se = succ_end(bb); si != se; ++si) {

      BasicBlock* next_bb = *si;
      SOFTBOUNDCETS_ASSERT(next_bb && "Not a basic block and I am adding to the base and bound worklist?");
      bb_worklist.push(next_bb);
    }

    for(BasicBlock::iterator i = bb->begin(), ie = bb->end(); i != ie; ++i){
      Value* v1 = dyn_cast<Value>(i);
      Instruction* new_inst = dyn_cast<Instruction>(i);

      if (!m_present_in_original.count(v1)) {
        continue;
      }

      switch(new_inst->getOpcode()) {

      case Instruction::Alloca:
        {
          AllocaInst* alloca_inst = dyn_cast<AllocaInst>(v1);
          SOFTBOUNDCETS_ASSERT(alloca_inst && "Not an Alloca inst?");
          handleAlloca(alloca_inst, func_key, func_lock, func_xmm_key_lock, bb, i);
        }
        break;

      case Instruction::Load:
        {
          LoadInst* load_inst = dyn_cast<LoadInst>(v1);
          SOFTBOUNDCETS_ASSERT(load_inst && "Not a Load inst?");
          handleLoad(load_inst);
        }
        break;

      case Instruction::GetElementPtr:
        {
          GetElementPtrInst* gep_inst = dyn_cast<GetElementPtrInst>(v1);
          SOFTBOUNDCETS_ASSERT(gep_inst && "Not a GEP inst?");
          handleGEP(gep_inst);
        }
        break;

      case BitCastInst::BitCast:
        {
          BitCastInst* bitcast_inst = dyn_cast<BitCastInst>(v1);
          SOFTBOUNDCETS_ASSERT(bitcast_inst && "Not a BitCast inst?");
          handleBitCast(bitcast_inst);
        }
        break;

      case Instruction::PHI:
        {
          PHINode* phi_node = dyn_cast<PHINode>(v1);
          SOFTBOUNDCETS_ASSERT(phi_node && "Not a phi node?");
          handlePHIPass1(phi_node);
        }
        break;

      case Instruction::Call:
        {
          CallInst* call_inst = dyn_cast<CallInst>(v1);
          SOFTBOUNDCETS_ASSERT(call_inst && "Not a Call inst?");
          handleCall(call_inst);
        }
        break;

      case Instruction::Select:
        {
          SelectInst* select_insn = dyn_cast<SelectInst>(v1);
          SOFTBOUNDCETS_ASSERT(select_insn && "Not a select inst?");
          int pass = 1;
          handleSelect(select_insn, pass);
        }
        break;

      case Instruction::Store:
        {
          break;
        }

      case Instruction::IntToPtr:
        {
          IntToPtrInst* inttoptrinst = dyn_cast<IntToPtrInst>(v1);
          SOFTBOUNDCETS_ASSERT(inttoptrinst && "Not a IntToPtrInst?");
          handleIntToPtr(inttoptrinst);
          break;
        }

      case Instruction::Ret:
        {
          ReturnInst* ret = dyn_cast<ReturnInst>(v1);
          SOFTBOUNDCETS_ASSERT(ret && "not a return inst?");
          handleReturnInst(ret);
        }
        break;

      case Instruction::ExtractElement:
        {
          ExtractElementInst * EEI = dyn_cast<ExtractElementInst>(v1);
          SOFTBOUNDCETS_ASSERT(EEI && "ExtractElementInst inst?");
          handleExtractElement(EEI);
        }
        break;

      case Instruction::ExtractValue:
        {
          ExtractValueInst * EVI = dyn_cast<ExtractValueInst>(v1);
          SOFTBOUNDCETS_ASSERT(EVI && "handle extract value inst?");
          handleExtractValue(EVI);
        }
        break;

      default:
        {
          if (isa<PointerType>(v1->getType())) {
            SOFTBOUNDCETS_ASSERT(!isa<PointerType>(v1->getType()) &&
                 "Generating Pointer and not being handled");
          }
        }
      }
    }
  }

  freeFunctionKeyLock(func, func_key, func_lock, func_xmm_key_lock);
}


void SoftBoundCETSImpl::emitInstrumentationPhase2(Function* func){

  /* WorkList Algorithm for propagating base and bound. Each basic
   * block is visited only once
   */
  std::set<BasicBlock*> bb_visited;
  std::queue<BasicBlock*> bb_worklist;
  Function::iterator bb_begin = func->begin();

  BasicBlock* bb = dyn_cast<BasicBlock>(bb_begin);
  SOFTBOUNDCETS_ASSERT(bb && "Not a basic block and gathering base bound in the next pass?");
  bb_worklist.push(bb);

  while ( bb_worklist.size() != 0) {

    bb = bb_worklist.front();
    SOFTBOUNDCETS_ASSERT(bb && "Not a BasicBlock?");

    bb_worklist.pop();
    if ( bb_visited.count(bb)) {
      /* Block already visited */

      continue;
    }
    /* If here implies basic block not visited */

    /* Insert the block into the set of visited blocks */
    bb_visited.insert(bb);

    /* Iterating over the successors and adding the successors to
     * the work list
     */
    for(succ_iterator si = succ_begin(bb), se = succ_end(bb); si != se; ++si) {

      BasicBlock* next_bb = *si;
      SOFTBOUNDCETS_ASSERT(next_bb && "Not a basic block and I am adding to the base and bound worklist?");
      bb_worklist.push(next_bb);
    }

    for(BasicBlock::iterator i = bb->begin(), ie = bb->end(); i != ie; ++i) {
      Value* v1 = dyn_cast<Value>(i);
      Instruction* new_inst = dyn_cast<Instruction>(i);

      if (!m_present_in_original.count(v1))
        continue;

      switch(new_inst->getOpcode()) {

      case Instruction::GetElementPtr:
        {
          GetElementPtrInst* gep_inst = dyn_cast<GetElementPtrInst>(v1);
          SOFTBOUNDCETS_ASSERT(gep_inst && "Not a GEP instruction?");
          handleGEP(gep_inst);
        }
        break;

      case Instruction::Store:
        {
          StoreInst* store_inst = dyn_cast<StoreInst>(v1);
          SOFTBOUNDCETS_ASSERT(store_inst && "Not a Store instruction?");
          handleStore(store_inst);
        }
        break;

      case Instruction::PHI:
        {
          PHINode* phi_node = dyn_cast<PHINode>(v1);
          SOFTBOUNDCETS_ASSERT(phi_node && "Not a PHINode?");
          handlePHIPass2(phi_node);
        }
        break;

      case BitCastInst::BitCast:
        {
          BitCastInst* bitcast_inst = dyn_cast<BitCastInst>(v1);
          SOFTBOUNDCETS_ASSERT(bitcast_inst && "Not a bitcast instruction?");
          handleBitCast(bitcast_inst);
        }
        break;

      default:
        break;
      }
    }
  }
}

void SoftBoundCETSImpl::emitInstrumentationPhase3(Function* func) {

  Function &F = *func;

  if (func->isVarArg())
    return;

  if (false)
    return;

  std::vector<Instruction*> CheckWorkList;
  std::map<Value*, bool> ElideSpatialCheck;
  std::map<Value*, bool> ElideTemporalCheck;

  // identify all the instructions where we need to insert the spatial checks
  for(inst_iterator i = inst_begin(F), e = inst_end(F); i != e; ++i){

    Instruction* I = &*i;

    if (!m_present_in_original.count(I)){
      continue;
    }
    // add check optimizations here
    // add checks for memory fences and atomic exchanges
    if (isa<LoadInst>(I) || isa<StoreInst>(I)){
      CheckWorkList.push_back(I);
    }
    if (isa<AtomicCmpXchgInst>(I) || isa<AtomicRMWInst>(I)){
      SOFTBOUNDCETS_ASSERT(0 && "Atomic Instructions not handled");
    }
  }

  /* intra-procedural load dererference check elimination map */
  std::map<Value*, int> func_deref_check_elim_map;
  std::map<Value*, int> func_temporal_check_elim_map;

  /* WorkList Algorithm for adding dereference checks. Each basic
   * block is visited only once. We start by visiting the current
   * basic block, then pushing all the successors of the current
   * basic block on to the queue if it has not been visited
   */

  std::set<BasicBlock*> bb_visited;
  std::queue<BasicBlock*> bb_worklist;
  Function:: iterator bb_begin = func->begin();

  BasicBlock* bb = dyn_cast<BasicBlock>(bb_begin);
  SOFTBOUNDCETS_ASSERT(bb && "Not a basic block  and I am adding dereference checks?");
  bb_worklist.push(bb);


  while (bb_worklist.size() != 0) {

    bb = bb_worklist.front();
    SOFTBOUNDCETS_ASSERT(bb && "Not a BasicBlock?");
    bb_worklist.pop();

    if (bb_visited.count(bb)) {
      /* Block already visited */
      continue;
    }

    /* If here implies basic block not visited */
    /* Insert the block into the set of visited blocks */
    bb_visited.insert(bb);

    /* Iterating over the successors and adding the successors to
     * the worklist
     */
    for(succ_iterator si = succ_begin(bb), se = succ_end(bb); si != se; ++si) {

      BasicBlock* next_bb = *si;
      SOFTBOUNDCETS_ASSERT(next_bb && "Not a basic block and I am adding to the base and bound worklist?");
      bb_worklist.push(next_bb);
    }

    /* basic block load deref check optimization */
    std::map<Value*, int> bb_deref_check_map;
    std::map<Value*, int> bb_temporal_check_elim_map;
    /* structure check optimization */
    std::map<Value*, int> bb_struct_check_opt;

    for(BasicBlock::iterator i = bb->begin(), ie = bb->end(); i != ie; ++i){
      Value* v1 = dyn_cast<Value>(i);
      Instruction* new_inst = dyn_cast<Instruction>(i);

      /* Do the dereference check stuff */
      if (!m_present_in_original.count(v1))
        continue;

      if (isa<LoadInst>(new_inst)){

        if (false)
          continue;

        emitLoadStoreChecks(new_inst, func_deref_check_elim_map);
        emitTemporalChecks(new_inst, bb_temporal_check_elim_map, func_temporal_check_elim_map);
        continue;
      }

      if (isa<StoreInst>(new_inst)){
        emitLoadStoreChecks(new_inst, func_deref_check_elim_map);
        emitTemporalChecks(new_inst, bb_temporal_check_elim_map, func_temporal_check_elim_map);
        continue;
      }

      /* check call through function pointers */
      if (isa<CallInst>(new_inst)) {

        /*
        SmallVector<Value*, 8> args;
        CallInst* call_inst = dyn_cast<CallInst>(new_inst);
        Value* tmp_base = NULL;
        Value* tmp_bound = NULL;

        SOFTBOUNDCETS_ASSERT(call_inst && "call instruction null?");

        Value* indirect_func_called = call_inst->getOperand(0);

        Constant* func_constant = dyn_cast<Constant>(indirect_func_called);
        if (func_constant) {
          getConstantExprBaseBound(func_constant, tmp_base, tmp_bound);
        }
        else {
          tmp_base = getAssociatedBase(indirect_func_called);
          tmp_bound = getAssociatedBound(indirect_func_called);
        }

        Value* bitcast_base = util::castToVoidPtr(tmp_base, new_inst);
        args.push_back(bitcast_base);

        Value* bitcast_bound = util::castToVoidPtr(tmp_bound, new_inst);
        args.push_back(bitcast_bound);

        Value* pointer_operand_value = util::castToVoidPtr(indirect_func_called, new_inst);
        args.push_back(pointer_operand_value);

        CallInst::Create(m_call_dereference_func, args, "", new_inst);
        */
        continue;
      } /* Call check ends */
    }
  }
}

/* handleLoad Takes a load_inst If the load is through a pointer
 * which is a global then inserts base and bound for that global
 * Also if the loaded value is a pointer then loads the base and
 * bound for for the pointer from the shadow space
 */

void SoftBoundCETSImpl::handleLoad(LoadInst* load_inst) {


  if (!isa<FixedVectorType>(load_inst->getType()) && !isa<PointerType>(load_inst->getType())){
    return;
  }

  if (isa<PointerType>(load_inst->getType())){
    AllocaInst* base_alloca;
    AllocaInst* bound_alloca;
    AllocaInst* key_alloca;
    AllocaInst* lock_alloca;

    Value* load_inst_value = load_inst;
    Value* pointer_operand = load_inst->getPointerOperand();
    Instruction* load = load_inst;

    Instruction* insert_at = util::getNextInstruction(load);

    /* If the load returns a pointer, then load the base and bound
     * from the shadow space
     */
    Value* pointer_operand_bitcast =  util::castToVoidPtr(pointer_operand, insert_at);
    Instruction* first_inst_func = dyn_cast<Instruction>(load_inst->getParent()->getParent()->begin()->begin());
    SOFTBOUNDCETS_ASSERT(first_inst_func && "function doesn't have any instruction and there is load???");

    SmallVector<Value*, 8> args;

    /* address of pointer being pushed */
    args.push_back(pointer_operand_bitcast);

    base_alloca = new AllocaInst(m_void_ptr_type, 0, "base.alloca", first_inst_func);
    bound_alloca = new AllocaInst(m_void_ptr_type, 0, "bound.alloca", first_inst_func);

    /* base */
    args.push_back(base_alloca);
    /* bound */
    args.push_back(bound_alloca);

    key_alloca = new AllocaInst(Type::getInt64Ty(load_inst->getType()->getContext()), 0, "key.alloca", first_inst_func);
    lock_alloca = new AllocaInst(m_void_ptr_type, 0, "lock.alloca", first_inst_func);

    args.push_back(key_alloca);
    args.push_back(lock_alloca);

    CallInst::Create(m_load_base_bound_func, args, "", insert_at);

    Instruction* base_load = new LoadInst(m_void_ptr_type, base_alloca, "base.load", insert_at);
    Instruction* bound_load = new LoadInst(m_void_ptr_type, bound_alloca, "bound.load", insert_at);
    associateBaseBound(load_inst_value, base_load, bound_load);

    Instruction* key_load = new LoadInst(Type::getInt64Ty(load_inst->getType()->getContext()), key_alloca, "key.load", insert_at);
    Instruction* lock_load = new LoadInst(m_void_ptr_type, lock_alloca, "lock.load", insert_at);
    associateKeyLock(load_inst_value, key_load, lock_load);

    return;
  }

  if (isa<FixedVectorType>(load_inst->getType())){

    if (!true || !true){
      SOFTBOUNDCETS_ASSERT(0 && "Loading and Storing Pointers as a first-class types");
      return;
    }

    // It should be a vector if here
    const FixedVectorType* vector_ty = dyn_cast<FixedVectorType>(load_inst->getType());
    // Introduce a series of metadata loads and associated it pointers
    if (!isa<PointerType>(vector_ty->getElementType()))
       return;

    Value* pointer_operand = load_inst->getPointerOperand();
    Instruction* insert_at = util::getNextInstruction(load_inst);

    Value* pointer_operand_bitcast =  util::castToVoidPtr(pointer_operand, insert_at);
    Instruction* first_inst_func = dyn_cast<Instruction>(load_inst->getParent()->getParent()->begin()->begin());
    SOFTBOUNDCETS_ASSERT(first_inst_func && "function doesn't have any instruction and there is load???");

    uint64_t num_elements = vector_ty->getNumElements();


    SmallVector<Value*, 8> vector_base;
    SmallVector<Value*, 8> vector_bound;
    SmallVector<Value*, 8> vector_key;
    SmallVector<Value*, 8> vector_lock;

    for (uint64_t i = 0; i < num_elements; i++) {
      AllocaInst* base_alloca;
      AllocaInst* bound_alloca;
      AllocaInst* key_alloca;
      AllocaInst* lock_alloca;

      SmallVector<Value*, 8> args;

      args.push_back(pointer_operand_bitcast);

      base_alloca = new AllocaInst(m_void_ptr_type, 0, "base.alloca", first_inst_func);
      bound_alloca = new AllocaInst(m_void_ptr_type, 0, "bound.alloca", first_inst_func);

      /* base */
      args.push_back(base_alloca);
      /* bound */
      args.push_back(bound_alloca);

      key_alloca = new AllocaInst(Type::getInt64Ty(load_inst->getType()->getContext()), 0, "key.alloca", first_inst_func);
      lock_alloca = new AllocaInst(m_void_ptr_type, 0, "lock.alloca", first_inst_func);

      args.push_back(key_alloca);
      args.push_back(lock_alloca);

      Constant* index = ConstantInt::get(Type::getInt32Ty(load_inst->getContext()), i);

      args.push_back(index);

      CallInst::Create(m_metadata_load_vector_func, args, "", insert_at);

      Instruction* base_load = new LoadInst(m_void_ptr_type, base_alloca, "base.load", insert_at);
      Instruction* bound_load = new LoadInst(m_void_ptr_type, bound_alloca, "bound.load", insert_at);
      Instruction* key_load = new LoadInst(Type::getInt64Ty(load_inst->getType()->getContext()), key_alloca, "key.load", insert_at);
      Instruction* lock_load = new LoadInst(m_void_ptr_type, lock_alloca, "lock.load", insert_at);

      vector_base.push_back(base_load);
      vector_bound.push_back(bound_load);
      vector_key.push_back(key_load);
      vector_lock.push_back(lock_load);
    }

    if (num_elements > 2){
      SOFTBOUNDCETS_ASSERT(0 && "Loading and Storing Pointers as a first-class types with more than 2 elements");
    }

    FixedVectorType* metadata_ptr_type = FixedVectorType::get(m_void_ptr_type, num_elements);
    FixedVectorType* key_vector_type = FixedVectorType::get(m_key_type, num_elements);

    Value *CV0 = ConstantInt::get(Type::getInt32Ty(load_inst->getContext()), 0);
    Value *CV1 = ConstantInt::get(Type::getInt32Ty(load_inst->getContext()), 1);

    Value* base_vector = InsertElementInst::Create(UndefValue::get(metadata_ptr_type),     vector_base[0],  CV0, "", insert_at);
    Value* base_vector_final = InsertElementInst::Create(base_vector, vector_base[1], CV1, "", insert_at);

    m_vector_pointer_base[load_inst] = base_vector_final;

    Value* bound_vector = InsertElementInst::Create(UndefValue::get(metadata_ptr_type),     vector_bound[0],  CV0, "", insert_at);
    Value* bound_vector_final = InsertElementInst::Create(bound_vector, vector_bound[1], CV1, "", insert_at);
    m_vector_pointer_bound[load_inst] = bound_vector_final;


    Value* key_vector = InsertElementInst::Create(UndefValue::get(key_vector_type), vector_key[0], CV0, "", insert_at);
    Value* key_vector_final = InsertElementInst::Create(key_vector, vector_key[1], CV1, "", insert_at);
    m_vector_pointer_key[load_inst] = key_vector_final;


    Value* lock_vector = InsertElementInst::Create(UndefValue::get(metadata_ptr_type),     vector_lock[0],  CV0, "", insert_at);
    Value* lock_vector_final = InsertElementInst::Create(lock_vector, vector_lock[1], CV1, "", insert_at);

    m_vector_pointer_lock[load_inst] = lock_vector_final;

    return;
  }
}

void SoftBoundCETSImpl::initialize(Module &M) {
  int LongSize = M.getDataLayout().getPointerSizeInBits();

  if (LongSize  == 64) {
    m_is_64_bit = true;
  } else {
    m_is_64_bit = false;
  }

  m_void_ptr_type = PointerType::getUnqual(Type::getInt8Ty(M.getContext()));

  size_t inf_bound;

  if (m_is_64_bit) {
    m_key_type = Type::getInt64Ty(M.getContext());
  } else {
    m_key_type = Type::getInt32Ty(M.getContext());
  }

  if (m_is_64_bit) {
    inf_bound = (size_t) pow(2, 48);
  } else {
    inf_bound = (size_t) (2147483647);
  }

  ConstantInt* infinite_bound;

  if (m_is_64_bit) {
    infinite_bound =
      ConstantInt::get(Type::getInt64Ty(M.getContext()), inf_bound, false);
  } else {
    infinite_bound =
      ConstantInt::get(Type::getInt32Ty(M.getContext()), inf_bound, false);
  }

  m_infinite_bound_ptr = ConstantExpr::getIntToPtr(infinite_bound,
                                                   m_void_ptr_type);

  PointerType* vptrty = dyn_cast<PointerType>(m_void_ptr_type);
  m_void_null_ptr = ConstantPointerNull::get(vptrty);

  PointerType* sizet_ptr_ty = NULL;
  if (m_is_64_bit) {
    sizet_ptr_ty =
      PointerType::getUnqual(Type::getInt64Ty(M.getContext()));
  } else{
    sizet_ptr_ty =
      PointerType::getUnqual(Type::getInt32Ty(M.getContext()));
  }

  m_sizet_ptr_type = sizet_ptr_ty;

  m_sizet_null_ptr = ConstantPointerNull::get(sizet_ptr_ty);

  m_constantint32ty_one =
    ConstantInt::get(Type::getInt32Ty(M.getContext()), 1);

  m_constantint32ty_zero =
    ConstantInt::get(Type::getInt32Ty(M.getContext()), 0);

  m_constantint64ty_one =
    ConstantInt::get(Type::getInt64Ty(M.getContext()), 1);

  m_constantint64ty_zero =
    ConstantInt::get(Type::getInt64Ty(M.getContext()), 0);

  if (m_is_64_bit) {
    m_constantint_one = m_constantint64ty_one;
    m_constantint_zero = m_constantint64ty_zero;
  } else {
    m_constantint_one = m_constantint32ty_one;
    m_constantint_zero = m_constantint32ty_zero;
  }

  // Only used here so not data members of the class
  Type *sizet_type;
  if (m_is_64_bit) {
    sizet_type =
      Type::getInt64Ty(M.getContext());
  } else{
    sizet_type =
      Type::getInt32Ty(M.getContext());
  }

  std::vector<Type*> args;
  args.push_back(m_void_ptr_type);
  args.push_back(m_void_ptr_type);
  args.push_back(m_void_ptr_type);
  args.push_back(sizet_type);

  M.getOrInsertFunction("__softboundcets_spatial_load_dereference_check",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_spatial_load_dereference_check =
    M.getFunction("__softboundcets_spatial_load_dereference_check");
  assert(m_spatial_load_dereference_check &&
         "__softboundcets_spatial_load_dereference_check function type null?");

  M.getOrInsertFunction("__softboundcets_spatial_store_dereference_check",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_spatial_store_dereference_check =
    M.getFunction("__softboundcets_spatial_store_dereference_check");
  assert(m_spatial_store_dereference_check &&
         "__softboundcets_spatial_store_dereference_check function type null?");

  args.clear();

  args.push_back(m_void_ptr_type);
  args.push_back(sizet_type);
  args.push_back(m_void_ptr_type);
  args.push_back(m_void_ptr_type);

  M.getOrInsertFunction("__softboundcets_temporal_load_dereference_check",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_temporal_load_dereference_check =
    M.getFunction("__softboundcets_temporal_load_dereference_check");
  assert(m_temporal_load_dereference_check &&
         "__softboundcets_temporal_load_dereference_check function type null?");

  M.getOrInsertFunction("__softboundcets_temporal_store_dereference_check",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_temporal_store_dereference_check =
    M.getFunction("__softboundcets_temporal_store_dereference_check");
  assert(m_temporal_store_dereference_check &&
         " __softboundcets_temporal_store_dereference_check function type null?");

  args.clear();

  M.getOrInsertFunction("__softboundcets_get_global_lock",
                        FunctionType::get(m_void_ptr_type,
                        args, false));
  m_temporal_global_lock_function =
    M.getFunction("__softboundcets_get_global_lock");
  assert(m_temporal_global_lock_function &&
         "__softboundcets_get_global_lock function type null?");

  args.clear();

  args.push_back(m_void_ptr_type);
  args.push_back(m_void_ptr_type);
  args.push_back(m_void_ptr_type);
  args.push_back(sizet_type);

  M.getOrInsertFunction("__softboundcets_introspect_metadata",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_introspect_metadata =
    M.getFunction("__softboundcets_introspect_metadata");
  assert(m_introspect_metadata &&
         "__softboundcets_introspect_metadata null?");

  args.clear();

  args.push_back(m_void_ptr_type);
  args.push_back(m_void_ptr_type);
  args.push_back(sizet_type);

  M.getOrInsertFunction("__softboundcets_copy_metadata",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_copy_metadata = M.getFunction("__softboundcets_copy_metadata");
  assert(m_copy_metadata && "__softboundcets_copy_metadata NULL?");

  args.clear();

  args.push_back(Type::getInt32Ty(M.getContext()));

  M.getOrInsertFunction("__softboundcets_allocate_shadow_stack_space",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_shadow_stack_allocate =
    M.getFunction("__softboundcets_allocate_shadow_stack_space");
  assert(m_shadow_stack_allocate &&
         "__softboundcets_allocate_shadow_stack_space NULL?");

  args.clear();

  M.getOrInsertFunction("__softboundcets_deallocate_shadow_stack_space",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_shadow_stack_deallocate =
    M.getFunction("__softboundcets_deallocate_shadow_stack_space");
  assert(m_shadow_stack_deallocate &&
         "__softboundcets_deallocate_shadow_stack_space NULL?");

  args.push_back(m_void_ptr_type);
  args.push_back(Type::getInt32Ty(M.getContext()));

  M.getOrInsertFunction("__softboundcets_store_base_shadow_stack",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_shadow_stack_base_store =
    M.getFunction("__softboundcets_store_base_shadow_stack");
  assert(m_shadow_stack_base_store &&
         "__softboundcets_store_base_shadow_stack NULL?");

  M.getOrInsertFunction("__softboundcets_store_bound_shadow_stack",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_shadow_stack_bound_store =
    M.getFunction("__softboundcets_store_bound_shadow_stack");
  assert(m_shadow_stack_bound_store &&
         "__softboundcets_store_bound_shadow_stack NULL?");

  args.clear();

  args.push_back(Type::getInt32Ty(M.getContext()));

  M.getOrInsertFunction("__softboundcets_load_base_shadow_stack",
                        FunctionType::get(m_void_ptr_type,
                        args, false));
  m_shadow_stack_base_load =
    M.getFunction("__softboundcets_load_base_shadow_stack");
  assert(m_shadow_stack_base_load &&
         "__softboundcets_load_base_shadow_stack NULL?");

  M.getOrInsertFunction("__softboundcets_load_bound_shadow_stack",
                        FunctionType::get(m_void_ptr_type,
                        args, false));
  m_shadow_stack_bound_load =
    M.getFunction("__softboundcets_load_bound_shadow_stack");
  assert(m_shadow_stack_bound_load &&
         "__softboundcets_load_bound_shadow_stack NULL?");

  M.getOrInsertFunction("__softboundcets_load_key_shadow_stack",
                        FunctionType::get(sizet_type,
                        args, false));
  m_shadow_stack_key_load =
    M.getFunction("__softboundcets_load_key_shadow_stack");
  assert(m_shadow_stack_key_load &&
         "__softboundcets_load_key_shadow_stack NULL?");

  M.getOrInsertFunction("__softboundcets_load_lock_shadow_stack",
                        FunctionType::get(m_void_ptr_type,
                        args, false));
  m_shadow_stack_lock_load =
    M.getFunction("__softboundcets_load_lock_shadow_stack");
  assert(m_shadow_stack_lock_load &&
         "__softboundcets_load_lock_shadow_stack NULL?");

  args.clear();

  args.push_back(sizet_type);
  args.push_back(Type::getInt32Ty(M.getContext()));

  M.getOrInsertFunction("__softboundcets_store_key_shadow_stack",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_shadow_stack_key_store =
    M.getFunction("__softboundcets_store_key_shadow_stack");
  assert(m_shadow_stack_key_store &&
         "__softboundcets_store_key_shadow_stack NULL?");

  args.clear();

  args.push_back(m_void_ptr_type);
  args.push_back(Type::getInt32Ty(M.getContext()));

  M.getOrInsertFunction("__softboundcets_store_lock_shadow_stack",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_shadow_stack_lock_store =
    M.getFunction("__softboundcets_store_lock_shadow_stack");
  assert(m_shadow_stack_lock_store &&
         "__softboundcets_store_lock_shadow_stack NULL?");

  args.clear();

  args.push_back(PointerType::getUnqual(m_void_ptr_type));
  args.push_back(sizet_ptr_ty);

  M.getOrInsertFunction("__softboundcets_stack_memory_allocation",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_temporal_stack_memory_allocation =
    M.getFunction("__softboundcets_stack_memory_allocation");
  assert(m_temporal_stack_memory_allocation &&
         "__softboundcets_stack_memory_allocation");

  args.clear();

  args.push_back(sizet_type);

  M.getOrInsertFunction("__softboundcets_stack_memory_deallocation",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_temporal_stack_memory_deallocation =
    M.getFunction("__softboundcets_stack_memory_deallocation");
  assert(m_temporal_stack_memory_deallocation &&
         "__softboundcets_stack_memory_deallocation not defined?");

  args.clear();

  args.push_back(m_void_ptr_type);

  M.getOrInsertFunction("__softboundcets_metadata_map",
                        FunctionType::get(m_void_ptr_type,
                        args, false));
  m_metadata_map_func = M.getFunction("__softboundcets_metadata_map");
  assert(m_metadata_map_func && "__softboundcets_metadata_map null?");

  args.clear();

  args.push_back(m_void_ptr_type);

  M.getOrInsertFunction("__softboundcets_metadata_load_base",
                        FunctionType::get(m_void_ptr_type,
                        args, false));
  m_metadata_load_base_func = M.getFunction("__softboundcets_metadata_load_base");
  assert(m_metadata_load_base_func && "__softboundcets_metadata_load_base null?");

  M.getOrInsertFunction("__softboundcets_metadata_load_bound",
                        FunctionType::get(m_void_ptr_type,
                        args, false));
  m_metadata_load_bound_func = M.getFunction("__softboundcets_metadata_load_bound");
  assert(m_metadata_load_bound_func && "__softboundcets_metadata_load_bound null?");

  M.getOrInsertFunction("__softboundcets_metadata_load_key",
                        FunctionType::get(sizet_type,
                        args, false));
  m_metadata_load_key_func = M.getFunction("__softboundcets_metadata_load_key");
  assert(m_metadata_load_key_func && "__softboundcets_metadata_load_key null");

  M.getOrInsertFunction("__softboundcets_metadata_load_lock",
                        FunctionType::get(m_void_ptr_type,
                        args, false));
  m_metadata_load_lock_func = M.getFunction("__softboundcets_metadata_load_lock");
  assert(m_metadata_load_lock_func && "__softboundcets_metadata_load_lock null?");

  args.clear();

  args.push_back(m_void_ptr_type);
  args.push_back(PointerType::getUnqual(m_void_ptr_type));
  args.push_back(PointerType::getUnqual(m_void_ptr_type));
  args.push_back(sizet_ptr_ty);
  args.push_back(PointerType::getUnqual(m_void_ptr_type));
  args.push_back(Type::getInt32Ty(M.getContext()));

  M.getOrInsertFunction("__softboundcets_metadata_load_vector",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_metadata_load_vector_func = M.getFunction("__softboundcets_metadata_load_vector");
  assert(m_metadata_load_vector_func && "__softboundcets_metadata_load_vector null?");

  args.clear();

  args.push_back(m_void_ptr_type);
  args.push_back(m_void_ptr_type);
  args.push_back(m_void_ptr_type);
  args.push_back(sizet_type);
  args.push_back(m_void_ptr_type);
  args.push_back(Type::getInt32Ty(M.getContext()));

  M.getOrInsertFunction("__softboundcets_metadata_store_vector",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_metadata_store_vector_func = M.getFunction("__softboundcets_metadata_store_vector");
  assert(m_metadata_store_vector_func && "__softboundcets_metadata_store_vector null?");

  args.clear();

  args.push_back(m_void_ptr_type);
  args.push_back(PointerType::getUnqual(m_void_ptr_type));
  args.push_back(PointerType::getUnqual(m_void_ptr_type));
  args.push_back(sizet_ptr_ty);
  args.push_back(PointerType::getUnqual(m_void_ptr_type));

  M.getOrInsertFunction("__softboundcets_metadata_load",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_load_base_bound_func = M.getFunction("__softboundcets_metadata_load");
  assert(m_load_base_bound_func && "__softboundcets_metadata_load null?");

  args.clear();

  args.push_back(m_void_ptr_type);
  args.push_back(m_void_ptr_type);
  args.push_back(m_void_ptr_type);
  args.push_back(sizet_type);
  args.push_back(m_void_ptr_type);

  M.getOrInsertFunction("__softboundcets_metadata_store",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_store_base_bound_func = M.getFunction("__softboundcets_metadata_store");
  assert(m_store_base_bound_func && "__softboundcets_metadata_store null?");

  args.clear();

  args.push_back(m_void_ptr_type);
  args.push_back(m_void_ptr_type);
  args.push_back(m_void_ptr_type);

  M.getOrInsertFunction("__softboundcets_spatial_call_dereference_check",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_call_dereference_func =
    M.getFunction("__softboundcets_spatial_call_dereference_check");
  assert(m_call_dereference_func &&
         "__softboundcets_spatial_call_dereference_check function null??");

  args.clear();

  args.push_back(m_void_ptr_type);
  args.push_back(m_void_ptr_type);
  args.push_back(sizet_type);
  args.push_back(m_void_ptr_type);
  args.push_back(m_void_ptr_type);
  args.push_back(m_void_ptr_type);
  args.push_back(m_void_ptr_type);
  args.push_back(sizet_type);
  args.push_back(m_void_ptr_type);
  args.push_back(sizet_type);
  args.push_back(m_void_ptr_type);

  M.getOrInsertFunction("__softboundcets_memcopy_check",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_memcopy_check =
    M.getFunction("__softboundcets_memcopy_check");
  assert(m_memcopy_check &&
         "__softboundcets_memcopy_check function null?");

  args.clear();

  args.push_back(m_void_ptr_type);
  args.push_back(sizet_type);
  args.push_back(m_void_ptr_type);
  args.push_back(m_void_ptr_type);
  args.push_back(sizet_type);
  args.push_back(m_void_ptr_type);

  M.getOrInsertFunction("__softboundcets_memset_check",
                        FunctionType::get(Type::getVoidTy(M.getContext()),
                        args, false));
  m_memset_check =
    M.getFunction("__softboundcets_memset_check");
  assert(m_memcopy_check &&
         "__softboundcets_memset_check function null?");

  markFunctionsToInstrument(M);
  markInitialGlobals(M);

#if defined(SOFTBOUNDCETS_INSTRUMENT_GLOBALS)
  addBaseBoundGlobals(M);
#endif
}

bool SoftBoundCETSImpl::sanitize(Function &F) {
  Function* func = &F;
  SOFTBOUNDCETS_ASSERT(func && "Not a function??");

  if (!isFunctionToInstrument(func)) {
    return false;
  }

  // We need to collect all the instructions in the original program
  // which create pointers. While doing this, we need to ignore instructions
  // that we ourselves have introduced, otherwise we'll end up
  // trying to recursively emit metadata checks for metadata checks

  for(Function::iterator bb_begin = func->begin(), bb_end = func->end();
    bb_begin != bb_end; ++bb_begin) {

    for(BasicBlock::iterator i_begin = bb_begin->begin(),
          i_end = bb_begin->end(); i_begin != i_end; ++i_begin){

      Value* insn = dyn_cast<Value>(i_begin);
      if (!m_present_in_original.count(insn)) {
        m_present_in_original[insn] = 1;
      }
      else {
        SOFTBOUNDCETS_ASSERT(0 && "present in original map already has the insn?");
      }

      if (isa<PointerType>(insn->getType())) {
        if (!m_is_pointer.count(insn)){
          m_is_pointer[insn] = 1;
        }
      }
    }
  }

  // Every function in the module needs a handle to the lock for globals

  Instruction* first_inst = &*(func->begin()->begin());
  Value* func_global_lock =
    introduceGlobalLockFunction(first_inst);
  m_func_global_lock[func->getName()] = func_global_lock;

  emitInstrumentationPhase1(func);
  emitInstrumentationPhase2(func);
  emitInstrumentationPhase3(func);

  return true;
}

void SoftBoundCETSImpl::finalize(Module &M) {
  renameFunctions(M);
}

class GenericSanitizerLegacyPass : public ModulePass {
private:
  SoftBoundCETSImpl impl;

public:
  // Pass identification, replacement for typeid.
  static char ID;

  explicit GenericSanitizerLegacyPass(bool Recover = false)
      : ModulePass(ID) {
    initializeGenericSanitizerLegacyPassPass(
        *PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override { return "GenericSanitizer"; }

  bool runOnModule(Module &M) override {
    impl.initialize(M);
    bool Modified = false;
    for (Function &F : M)
      Modified |= impl.sanitize(F);
    impl.finalize(M);
    return Modified;
  }

};

char GenericSanitizerLegacyPass::ID = 0;

INITIALIZE_PASS_BEGIN(
    GenericSanitizerLegacyPass, "gsan",
    "GenericSanitizer", false,
    false)
INITIALIZE_PASS_END(
    GenericSanitizerLegacyPass, "gsan",
    "GenericSanitizer", false,
    false)

ModulePass *llvm::createGenericSanitizerLegacyPassPass() {
  return new GenericSanitizerLegacyPass();
}

PreservedAnalyses GenericSanitizerPass::run(Module &M,
                                            ModuleAnalysisManager &MAM) {
  impl.initialize(M);
  bool Modified = false;
  for (Function &F : M)
    Modified |= impl.sanitize(F);
  impl.finalize(M);
  if (Modified)
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}
