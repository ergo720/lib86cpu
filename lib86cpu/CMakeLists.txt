# This cmake file is borrowed from libcpu, Copyright (c) 2009-2010, the libcpu developers

PROJECT(lib86cpu)

ADD_LIBRARY(cpu SHARED
			interface.cpp
			osfunc.cpp)

ADD_DEFINITIONS(-DLIB86CPU_BUILD_CORE)

TARGET_LINK_LIBRARIES(cpu x86)
IF(HAVE_LIBREADLINE)
	ADD_DEFINITIONS(-DUSE_READLINE)
	TARGET_LINK_LIBRARIES(cpu readline)
ENDIF()
IF(HAVE_LIBRT)
	TARGET_LINK_LIBRARIES(cpu rt)
ENDIF()
TARGET_LINK_LLVM(cpu)
