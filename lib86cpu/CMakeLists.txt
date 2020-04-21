# This cmake file is borrowed from libcpu, Copyright (c) 2009-2010, the libcpu developers

PROJECT(lib86cpu)

if (WIN32)
include_directories(${PROJECT_SOURCE_DIR}/x86/windows)
ADD_LIBRARY(cpu SHARED
			interface.cpp
			x86/arch.cpp
			x86/decode.cpp
			x86/disasm.cpp
			x86/disasm_att.cpp
			x86/disasm_intel.cpp
			x86/translate.cpp
			x86/frontend.cpp
			x86/memory.cpp
			x86/jit.cpp
			x86/windows/allocator.cpp)
else (WIN32)
message(FATAL_ERROR "Only Windows builds are supported for now")
endif(WIN32)

ADD_DEFINITIONS(-DLIB86CPU_BUILD_CORE)

IF(HAVE_LIBREADLINE)
	ADD_DEFINITIONS(-DUSE_READLINE)
	TARGET_LINK_LIBRARIES(cpu readline)
ENDIF()
IF(HAVE_LIBRT)
	TARGET_LINK_LIBRARIES(cpu rt)
ENDIF()
TARGET_LINK_LLVM(cpu)
