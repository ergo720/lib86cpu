# This cmake file is borrowed from libcpu, Copyright (c) 2009-2010, the libcpu developers

PROJECT(test_run86)

SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${LIB86CPU_RUNTIME_OUTPUT_DIRECTORY})
ADD_EXECUTABLE(test_run86 run.cpp)
TARGET_LINK_LIBRARIES(test_run86 cpu)
