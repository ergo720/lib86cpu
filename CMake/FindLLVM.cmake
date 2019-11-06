# This cmake file is borrowed from libcpu, Copyright (c) 2009-2010, the libcpu developers
#
# Detect LLVM and set various variable to link against the different component of LLVM
#
# NOTE: This is a modified version of the module originally found in the OpenGTL project
# at www.opengtl.org
#
# LLVM_BIN_DIR : directory with LLVM binaries
# LLVM_LIB_DIR : directory with LLVM library
# LLVM_INCLUDE_DIR : directory with LLVM include
#
# LLVM_COMPILE_FLAGS : compile flags needed to build a program using LLVM headers
# LLVM_LDFLAGS : ldflags needed to link
# LLVM_LIBS_CORE : ldflags needed to link against a LLVM core library
# LLVM_LIBS_JIT : ldflags needed to link against a LLVM JIT
# LLVM_LIBS_JIT_OBJECTS : objects you need to add to your source when using LLVM JIT

if (MSVC)
  set(LLVM_ROOT "C:/Program Files (x86)/LLVM")
  if (NOT IS_DIRECTORY ${LLVM_ROOT})
    message(FATAL_ERROR "Could NOT find LLVM")
  endif ()

  message(STATUS "Found LLVM: ${LLVM_ROOT}")
  set(LLVM_BIN_DIR ${LLVM_ROOT}/bin)
  set(LLVM_LIB_DIR ${LLVM_ROOT}/lib)
  set(LLVM_INCLUDE_DIR ${LLVM_ROOT}/include)

  set(LLVM_COMPILE_FLAGS "")
  set(LLVM_LDFLAGS "")

  set(LLVM_LIBS_CORE LLVMX86Disassembler.lib LLVMX86AsmParser.lib LLVMX86CodeGen.lib LLVMGlobalISel.lib LLVMSelectionDAG.lib LLVMAsmPrinter.lib LLVMCodeGen.lib LLVMTarget.lib
  LLVMScalarOpts.lib LLVMInstCombine.lib LLVMAggressiveInstCombine.lib LLVMTransformUtils.lib LLVMBitWriter.lib LLVMAnalysis.lib LLVMProfileData.lib LLVMX86Desc.lib LLVMObject.lib
  LLVMMCParser.lib LLVMBitReader.lib LLVMCore.lib LLVMMCDisassembler.lib LLVMX86Info.lib LLVMX86AsmPrinter.lib LLVMMC.lib LLVMDebugInfoCodeView.lib LLVMDebugInfoMSF.lib
  LLVMBinaryFormat.lib LLVMX86Utils.lib LLVMSupport.lib LLVMDemangle.lib LLVMMCJIT.lib LLVMOrcJIT.lib LLVMExecutionEngine.lib LLVMRuntimeDyld.lib LLVMipo.lib LLVMObjCARCOpts.lib
  LLVMInstrumentation.lib LLVMVectorize.lib LLVMIRReader.lib LLVMLinker.lib LLVMAsmParser.lib)
  set(LLVM_LIBS_JIT "")
  set(LLVM_LIBS_JIT_OBJECTS "")
else (MSVC)
  message(FATAL_ERROR "Only MSVC is supported for now")
endif (MSVC)
