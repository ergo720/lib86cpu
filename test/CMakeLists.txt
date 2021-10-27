# This cmake file is borrowed from libcpu, Copyright (c) 2009-2010, the libcpu developers

project(test_run86)

add_executable(test_run86
			run.cpp
			test386.cpp
			hook.cpp
			debug.cpp)

target_link_libraries(test_run86 cpu)
