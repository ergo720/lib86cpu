# ergo720 Copyright (c) 2020

cmake_minimum_required(VERSION 3.4.3)
project(lib86cpu)

if(NOT DEFINED CMAKE_RUNTIME_OUTPUT_DIRECTORY)
 set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${lib86cpu_BINARY_DIR}/bin")
endif()

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)

set(LIB86CPU_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})
set(LLVM_DIR ${LIB86CPU_ROOT_DIR}/llvm)

message("Building lib86cpu")
include(BuildConfigH.cmake)
add_definitions(-DLIB86CPU_BUILD_CORE)
include_directories(${LIB86CPU_ROOT_DIR}/lib86cpu ${LIB86CPU_ROOT_DIR}/lib86cpu/x86)
set(LLVM_LIBS LLVMX86Disassembler.lib LLVMX86AsmParser.lib LLVMX86CodeGen.lib LLVMGlobalISel.lib LLVMSelectionDAG.lib LLVMAsmPrinter.lib LLVMCodeGen.lib LLVMTarget.lib
LLVMScalarOpts.lib LLVMInstCombine.lib LLVMAggressiveInstCombine.lib LLVMTransformUtils.lib LLVMBitWriter.lib LLVMAnalysis.lib LLVMProfileData.lib LLVMX86Desc.lib LLVMObject.lib
LLVMMCParser.lib LLVMBitReader.lib LLVMCore.lib LLVMMCDisassembler.lib LLVMX86Info.lib LLVMX86AsmPrinter.lib LLVMMC.lib LLVMDebugInfoCodeView.lib LLVMDebugInfoMSF.lib
LLVMBinaryFormat.lib LLVMX86Utils.lib LLVMSupport.lib LLVMDemangle.lib LLVMMCJIT.lib LLVMOrcJIT.lib LLVMExecutionEngine.lib LLVMRuntimeDyld.lib LLVMipo.lib LLVMObjCARCOpts.lib
LLVMInstrumentation.lib LLVMVectorize.lib LLVMIRReader.lib LLVMLinker.lib LLVMAsmParser.lib)
if (MSVC)
include_directories(${LLVM_DIR}/$(Configuration)/include)
link_directories(${LLVM_DIR}/$(Configuration)/lib)
add_compile_options(/external:I ${LLVM_DIR}/$(Configuration)/include /external:W0 /external:templates- /external:anglebrackets)
else ()
message(FATAL_ERROR "Only Windows builds are supported for now")
endif()

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("import/zydis")

file (GLOB HEADERS
 "${LIB86CPU_ROOT_DIR}/lib86cpu/config.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/interval_tree.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/lib86cpu.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/lib86cpu_priv.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/platform.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/support.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/types.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/breakpoint.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/decode.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/frontend.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/internal.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/jit.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/memory.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/registers.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/windows/allocator.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/windows/clock.h"
)

file (GLOB SOURCES
 "${LIB86CPU_ROOT_DIR}/lib86cpu/interface.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/support.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/breakpoint.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/decode.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/frontend.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/init.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/jit.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/memory.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/translate.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/windows/allocator.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/windows/clock.cpp"
)

source_group(TREE ${LIB86CPU_ROOT_DIR} PREFIX header FILES ${HEADERS})
source_group(TREE ${LIB86CPU_ROOT_DIR} PREFIX source FILES ${SOURCES})

if (MSVC)
set(CMAKE_CXX_FLAGS "/EHs")
include_directories(${LIB86CPU_ROOT_DIR}/lib86cpu/x86/windows)
add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_WARNINGS -D_SCL_SECURE_NO_WARNINGS -D__STDC_FORMAT_MACROS -D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS)
add_definitions(-wd4146)
add_definitions(-wd4800)
add_definitions(-wd4355)
else ()
message(FATAL_ERROR "Only Windows builds are supported for now")
endif()

add_library(cpu SHARED ${HEADERS} ${SOURCES})
target_link_libraries(cpu PRIVATE ${LLVM_LIBS} Zydis)

if (${LIB86CPU_BUILD_TEST})
message("Building test")
add_subdirectory(${LIB86CPU_ROOT_DIR}/test)
if (MSVC)
set_property(DIRECTORY "${LIB86CPU_ROOT_DIR}" PROPERTY VS_STARTUP_PROJECT test_run86)
endif()
endif()
