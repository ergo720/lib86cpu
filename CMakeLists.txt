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
include_directories(${LIB86CPU_ROOT_DIR}/lib86cpu ${LIB86CPU_ROOT_DIR}/lib86cpu/x86 ${LIB86CPU_ROOT_DIR}/import/glfw/include/GLFW ${LIB86CPU_ROOT_DIR}/import/imgui
 ${LIB86CPU_ROOT_DIR}/import/imgui/backends ${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/glad ${LIB86CPU_ROOT_DIR}/lib86cpu/dbg)
set(LLVM_LIBS LLVMLTO.lib LLVMExtensions.lib LLVMOrcJIT.lib LLVMPasses.lib LLVMObjCARCOpts.lib LLVMCoroutines.lib LLVMipo.lib LLVMVectorize.lib LLVMLinker.lib LLVMIRReader.lib LLVMAsmParser.lib LLVMFrontendOpenMP.lib
LLVMJITLink.lib LLVMExecutionEngine.lib LLVMRuntimeDyld.lib LLVMOrcTargetProcess.lib LLVMOrcShared.lib LLVMX86TargetMCA.lib LLVMMCA.lib LLVMX86Disassembler.lib LLVMX86AsmParser.lib LLVMX86CodeGen.lib LLVMCFGuard.lib
LLVMGlobalISel.lib LLVMX86Desc.lib LLVMX86Info.lib LLVMMCDisassembler.lib LLVMSelectionDAG.lib LLVMInstrumentation.lib LLVMAsmPrinter.lib LLVMDebugInfoMSF.lib LLVMCodeGen.lib LLVMTarget.lib LLVMScalarOpts.lib
LLVMInstCombine.lib LLVMAggressiveInstCombine.lib LLVMTransformUtils.lib LLVMBitWriter.lib LLVMAnalysis.lib LLVMProfileData.lib LLVMDebugInfoDWARF.lib LLVMObject.lib LLVMTextAPI.lib LLVMMCParser.lib LLVMMC.lib
LLVMDebugInfoCodeView.lib LLVMBitReader.lib LLVMCore.lib LLVMRemarks.lib LLVMBitstreamReader.lib LLVMBinaryFormat.lib LLVMSupport.lib LLVMDemangle.lib)
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

option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(GLFW_BUILD_EXAMPLES "Build the GLFW example programs" OFF)
option(GLFW_BUILD_TESTS "Build the GLFW test programs" OFF)
option(GLFW_BUILD_DOCS "Build the GLFW documentation" OFF)
option(GLFW_INSTALL "Generate installation target" OFF)
option(GLFW_VULKAN_STATIC "Assume the Vulkan loader is linked with the application" OFF)
add_subdirectory("import/glfw")

add_subdirectory("projects/imgui")

file (GLOB HEADERS
 "${LIB86CPU_ROOT_DIR}/lib86cpu/config.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/interval_tree.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/lib86cpu.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/lib86cpu_priv.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/platform.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/support.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/types.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/debugger.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/imgui_memory_editor.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/imgui_wnd.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/main_wnd.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/glad/glad/glad.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/glad/KHR/khrplatform.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/breakpoint.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/decode.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/frontend.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/helpers.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/instructions.h"
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
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/debugger.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/imgui_wnd.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/main_wnd.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/glad/glad.c"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/breakpoint.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/decode.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/frontend.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/helpers.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/init.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/x86/instructions.cpp"
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
add_definitions(-wd4624)
else ()
message(FATAL_ERROR "Only Windows builds are supported for now")
endif()

add_library(cpu SHARED ${HEADERS} ${SOURCES})
target_link_libraries(cpu PRIVATE ${LLVM_LIBS} Zydis glfw imgui)

if (${LIB86CPU_BUILD_TEST})
message("Building test")
add_subdirectory(${LIB86CPU_ROOT_DIR}/test)
if (MSVC)
set_property(DIRECTORY "${LIB86CPU_ROOT_DIR}" PROPERTY VS_STARTUP_PROJECT test_run86)
endif()
endif()
