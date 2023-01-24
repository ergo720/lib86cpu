# ergo720 Copyright (c) 2020

cmake_minimum_required(VERSION 3.4.3)
project(lib86cpu)

if(NOT DEFINED CMAKE_RUNTIME_OUTPUT_DIRECTORY)
 set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${lib86cpu_BINARY_DIR}/bin")
endif()

set(LIB86CPU_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)

option(LIB86CPU_BUILD_SHARED_LIB
    "Build shared library"
    OFF)

if (WIN32 AND MSVC)
message("Building for Windows")
include_directories(${LIB86CPU_ROOT_DIR}/lib86cpu/core/windows)
set(PLATFORM_HEADERS
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/windows/allocator.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/windows/clock.h"
)
set(PLATFORM_SRC
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/windows/allocator.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/windows/clock.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/windows/x64_exceptions.cpp"
)
else ()
message(FATAL_ERROR "Only Windows builds with msvc are supported for now")
endif()

if (${LIB86CPU_X64_EMITTER})
 add_definitions(-DLIB86CPU_X64_EMITTER)
 set(LIB86CPU_EMITTER "X64")
else ()
 set(LIB86CPU_X64_EMITTER FALSE)
 set(LIB86CPU_EMITTER "Autodetect")
endif()

message("** Lib86cpu Summary **")
message("   LIB86CPU_EMITTER=${LIB86CPU_EMITTER}")
message("   LIB86CPU_X64_EMITTER=${LIB86CPU_X64_EMITTER}")
message("   LIB86CPU_BUILD_TEST=${LIB86CPU_BUILD_TEST}")

message("Building lib86cpu")
include(BuildConfigH.cmake)
add_definitions(-DASMJIT_STATIC)
include_directories(${LIB86CPU_ROOT_DIR}/include ${LIB86CPU_ROOT_DIR}/lib86cpu ${LIB86CPU_ROOT_DIR}/lib86cpu/core ${LIB86CPU_ROOT_DIR}/lib86cpu/core/emitter ${LIB86CPU_ROOT_DIR}/import/glfw/include/GLFW
 ${LIB86CPU_ROOT_DIR}/import/imgui ${LIB86CPU_ROOT_DIR}/import/imgui/backends ${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/glad ${LIB86CPU_ROOT_DIR}/lib86cpu/dbg
 ${LIB86CPU_ROOT_DIR}/import/asmjit/src)

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

option(ASMJIT_STATIC "" ON)
if (NOT ${LIB86CPU_X64_EMITTER})
 option(ASMJIT_NO_FOREIGN "" ON)
endif()
add_subdirectory("import/asmjit")

set(HEADERS
 "${LIB86CPU_ROOT_DIR}/include/config.h"
 "${LIB86CPU_ROOT_DIR}/include/lib86cpu.h"
 "${LIB86CPU_ROOT_DIR}/include/platform.h"
 "${LIB86CPU_ROOT_DIR}/include/types.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/as.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/endianness.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/lib86cpu_priv.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/support.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/debugger.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/imgui_memory_editor.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/imgui_wnd.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/main_wnd.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/glad/glad/glad.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/glad/KHR/khrplatform.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/breakpoint.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/decode.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/helpers.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/instructions.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/internal.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/memory.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/registers.h"

 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/emitter/emitter_common.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/emitter/x64/jit.h"

  ${PLATFORM_HEADERS}
)

set(SOURCES
 "${LIB86CPU_ROOT_DIR}/lib86cpu/interface.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/support.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/debugger.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/imgui_wnd.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/main_wnd.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/glad/glad.c"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/breakpoint.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/decode.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/fpu.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/helpers.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/instructions.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/memory.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/translate.cpp"
 
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/emitter/emitter_common.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/emitter/x64/jit.cpp"
 
  ${PLATFORM_SRC}
)

source_group(TREE ${LIB86CPU_ROOT_DIR} PREFIX header FILES ${HEADERS})
source_group(TREE ${LIB86CPU_ROOT_DIR} PREFIX source FILES ${SOURCES})

if (MSVC)
set(CMAKE_CXX_FLAGS "/EHs /fp:strict")
add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_WARNINGS -D_SCL_SECURE_NO_WARNINGS -D__STDC_FORMAT_MACROS -D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS)
add_definitions(-wd4146)
add_definitions(-wd4800)
add_definitions(-wd4355)
add_definitions(-wd4624)
endif()

if (${LIB86CPU_BUILD_SHARED_LIB})
 add_definitions(-DLIB86CPU_BUILD_SHARED_LIB -DLIB86CPU_BUILD_CORE)
 add_library(cpu SHARED ${HEADERS} ${SOURCES})
else ()
 add_library(cpu STATIC ${HEADERS} ${SOURCES})
endif()

target_link_libraries(cpu PRIVATE asmjit Zydis glfw imgui)

if (${LIB86CPU_BUILD_TEST})
message("Building test")
add_subdirectory(${LIB86CPU_ROOT_DIR}/test)
if (MSVC)
set_property(DIRECTORY "${LIB86CPU_ROOT_DIR}" PROPERTY VS_STARTUP_PROJECT test_run86)
endif()
endif()
