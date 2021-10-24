# ergo720 Copyright (c) 2020

cmake_minimum_required(VERSION 3.4.3)
project(lib86cpu)

if(NOT DEFINED CMAKE_RUNTIME_OUTPUT_DIRECTORY)
 set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${lib86cpu_BINARY_DIR}/bin")
endif()

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)

set(LLVM_DIR ${PROJECT_SOURCE_DIR}/llvm/build/llvm)
if (NOT IS_DIRECTORY ${LLVM_DIR})
  message(FATAL_ERROR "Could NOT find LLVM")
endif ()
message(STATUS "Found LLVM: ${LLVM_DIR}")

message("Building lib86cpu")
include(BuildConfigH.cmake)
include_directories(${LLVM_DIR}/include ${PROJECT_SOURCE_DIR}/lib86cpu ${PROJECT_SOURCE_DIR}/lib86cpu/x86)
set(LLVM_LIBS LLVMX86Disassembler.lib LLVMX86AsmParser.lib LLVMX86CodeGen.lib LLVMGlobalISel.lib LLVMSelectionDAG.lib LLVMAsmPrinter.lib LLVMCodeGen.lib LLVMTarget.lib
LLVMScalarOpts.lib LLVMInstCombine.lib LLVMAggressiveInstCombine.lib LLVMTransformUtils.lib LLVMBitWriter.lib LLVMAnalysis.lib LLVMProfileData.lib LLVMX86Desc.lib LLVMObject.lib
LLVMMCParser.lib LLVMBitReader.lib LLVMCore.lib LLVMMCDisassembler.lib LLVMX86Info.lib LLVMX86AsmPrinter.lib LLVMMC.lib LLVMDebugInfoCodeView.lib LLVMDebugInfoMSF.lib
LLVMBinaryFormat.lib LLVMX86Utils.lib LLVMSupport.lib LLVMDemangle.lib LLVMMCJIT.lib LLVMOrcJIT.lib LLVMExecutionEngine.lib LLVMRuntimeDyld.lib LLVMipo.lib LLVMObjCARCOpts.lib
LLVMInstrumentation.lib LLVMVectorize.lib LLVMIRReader.lib LLVMLinker.lib LLVMAsmParser.lib)
link_directories(${LLVM_DIR}/lib)
add_definitions(-DLIB86CPU_BUILD_CORE)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("import/zydis")

if (MSVC)

set(CMAKE_CXX_FLAGS "/EHs")
include_directories(${PROJECT_SOURCE_DIR}/lib86cpu/x86/windows)
add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_WARNINGS -D_SCL_SECURE_NO_WARNINGS -D__STDC_FORMAT_MACROS -D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS)
add_definitions(-wd4146)
add_definitions(-wd4800)
add_definitions(-wd4355)

add_library(cpu SHARED
			lib86cpu/interface.cpp
			lib86cpu/support.cpp
			lib86cpu/x86/init.cpp
			lib86cpu/x86/decode.cpp
			lib86cpu/x86/translate.cpp
			lib86cpu/x86/frontend.cpp
			lib86cpu/x86/memory.cpp
			lib86cpu/x86/jit.cpp
			lib86cpu/x86/breakpoint.cpp
			lib86cpu/x86/windows/allocator.cpp
			lib86cpu/x86/windows/clock.cpp)
			
target_link_libraries(cpu PRIVATE ${LLVM_LIBS} Zydis)

else ()
message(FATAL_ERROR "Only Windows builds are supported for now")
endif()

if (${LIB86CPU_BUILD_TEST})
message("Building test")
add_subdirectory(${PROJECT_SOURCE_DIR}/test)
endif()