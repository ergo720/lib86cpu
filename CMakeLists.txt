# This cmake file is borrowed from libcpu, Copyright (c) 2009-2010, the libcpu developers

PROJECT(lib86cpu)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

INCLUDE(FindThreads)

#
#
#
SET(CMAKE_BUILD_TYPE "Debug")

# Add compiler flags.
IF(MSVC)
SET(CMAKE_CXX_FLAGS "/std:c++17 /EHs")
ELSE(MSVC)
SET(CMAKE_CXX_FLAGS "-std=c++17")
ENDIF(MSVC)

#
# Find LLVM, we need it.
#
SET(LLVM_FIND_REQUIRED TRUE)
INCLUDE(CMake/FindLLVM.cmake)

INCLUDE(CMake/BuildConfigH.cmake)
IF(MSVC)
	add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_WARNINGS -D_SCL_SECURE_NO_WARNINGS -D__STDC_FORMAT_MACROS -D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS)
	# disable warnings for LLVM
	add_definitions(-wd4146) # unary minus operator applied to unsigned type, result still unsigned
	add_definitions(-wd4800) # forcing value to bool 'true' or 'false' (performance warning)
	add_definitions(-wd4355) # 'this' : used in base member initializer list
ENDIF()

SET(LIB86CPU_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib86cpu)

#
#
#
if (WIN32)
include_directories(${LLVM_INCLUDE_DIR} ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/lib86cpu ${PROJECT_SOURCE_DIR}/x86/windows)
else (WIN32)
message(FATAL_ERROR "Only Windows builds are supported for now")
endif(WIN32)
LINK_DIRECTORIES(${LLVM_LIB_DIR})

MACRO(TARGET_LINK_LLVM TARGET)
  TARGET_LINK_LIBRARIES(${TARGET} ${LLVM_LDFLAGS} ${LLVM_LIBS_CORE} ${LLVM_LIBS_JIT} ${LLVM_LIBS_JIT_OBJECTS})
ENDMACRO(TARGET_LINK_LLVM)

#
# Build lib86cpu
#
SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG_LOG")
MESSAGE("** Building lib86cpu")
ADD_SUBDIRECTORY(${PROJECT_SOURCE_DIR}/x86)
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/x86)
MESSAGE("** Building Test")
ADD_SUBDIRECTORY(${PROJECT_SOURCE_DIR}/test)

ADD_SUBDIRECTORY(lib86cpu)
