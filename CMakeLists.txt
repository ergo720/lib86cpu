# ergo720 Copyright (c) 2020

cmake_minimum_required(VERSION 3.4.3)
project(lib86cpu)

if(NOT DEFINED CMAKE_RUNTIME_OUTPUT_DIRECTORY)
 set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${lib86cpu_BINARY_DIR}/bin")
endif()

set(LIB86CPU_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(LIB86CPU_BUILD_SHARED_LIB
    "Build shared library"
    OFF)

if (CMAKE_HOST_SYSTEM_NAME MATCHES "Windows")
 set(OS_IS_WIN TRUE)
elseif (CMAKE_HOST_SYSTEM_NAME MATCHES "Linux")
 set(OS_IS_LINUX TRUE)
else ()
message(FATAL_ERROR "Unsupported OS")
endif()

if (CMAKE_GENERATOR MATCHES "Visual Studio")
 set(GENERATOR_IS_VS TRUE)
elseif (CMAKE_GENERATOR MATCHES "Unix Makefiles")
 set(GENERATOR_IS_UMAKE TRUE)
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
 set(COMPILER_IS_MSVC TRUE)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
 set(COMPILER_IS_GNU TRUE)
else ()
message(FATAL_ERROR "Unsupported compiler")
endif()

if (${GENERATOR_IS_UMAKE})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/Debug")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/Release")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE}")
endif()

if (${OS_IS_WIN})
message("Building for Windows")
include_directories(${LIB86CPU_ROOT_DIR}/lib86cpu/core/windows)
set(PLATFORM_HEADERS
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/windows/clock.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/windows/os_exceptions.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/windows/os_mem.h"
)
set(PLATFORM_SRC
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/windows/clock.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/windows/os_exceptions.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/windows/os_mem.cpp"
)
elseif (${OS_IS_LINUX})
message("Building for Linux")
include_directories(${LIB86CPU_ROOT_DIR}/lib86cpu/core/linux)
set(PLATFORM_HEADERS
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/linux/clock.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/linux/os_exceptions.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/linux/os_mem.h"
)
set(PLATFORM_SRC
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/linux/clock.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/linux/os_exceptions.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/linux/os_mem.cpp"
)
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
include_directories(${LIB86CPU_ROOT_DIR}/include ${LIB86CPU_ROOT_DIR}/lib86cpu ${LIB86CPU_ROOT_DIR}/lib86cpu/core ${LIB86CPU_ROOT_DIR}/lib86cpu/core/emitter
 ${LIB86CPU_ROOT_DIR}/import/glfw/include/GLFW ${LIB86CPU_ROOT_DIR}/import/imgui ${LIB86CPU_ROOT_DIR}/import/imgui/backends ${LIB86CPU_ROOT_DIR}/lib86cpu/dbg/glad
 ${LIB86CPU_ROOT_DIR}/lib86cpu/dbg ${LIB86CPU_ROOT_DIR}/import/asmjit/src)

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
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/allocator.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/breakpoint.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/decode.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/helpers.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/instructions.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/internal.h"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/memory_management.h"
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
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/allocator.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/breakpoint.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/decode.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/fpu.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/fpu_instructions.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/helpers.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/instructions.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/memory_management.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/translate.cpp"
 
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/emitter/emitter_common.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/emitter/x64/jit.cpp"
 "${LIB86CPU_ROOT_DIR}/lib86cpu/core/emitter/x64/support.cpp"
 
  ${PLATFORM_SRC}
)

source_group(TREE ${LIB86CPU_ROOT_DIR} PREFIX header FILES ${HEADERS})
source_group(TREE ${LIB86CPU_ROOT_DIR} PREFIX source FILES ${SOURCES})

if (${COMPILER_IS_MSVC})
set(CMAKE_CXX_FLAGS "/EHs /fp:strict /Zc:preprocessor")
add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_WARNINGS -D_SCL_SECURE_NO_WARNINGS -D__STDC_FORMAT_MACROS -D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS)
add_definitions(-wd4146)
add_definitions(-wd4800)
add_definitions(-wd4355)
add_definitions(-wd4624)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} \
 /Ob2 \
 /Oi \
 /GS- \
 /Gy \
 /Qpar \
 "
)
elseif (${COMPILER_IS_GNU})
set(CMAKE_CXX_FLAGS "-m64 -msse2 -fexceptions -funwind-tables")
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
if (${GENERATOR_IS_VS})
set_property(DIRECTORY "${LIB86CPU_ROOT_DIR}" PROPERTY VS_STARTUP_PROJECT test_run86)
endif()
endif()
