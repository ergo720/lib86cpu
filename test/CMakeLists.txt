# ergo720 Copyright (c) 2022

project(test_run86)

set(TEST_RUN86_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})

file (GLOB HEADERS
 "${TEST_RUN86_ROOT_DIR}/run.h"
)

file (GLOB SOURCES
 "${TEST_RUN86_ROOT_DIR}/debug.cpp"
 "${TEST_RUN86_ROOT_DIR}/hook.cpp"
 "${TEST_RUN86_ROOT_DIR}/kernel.cpp"
 "${TEST_RUN86_ROOT_DIR}/run.cpp"
 "${TEST_RUN86_ROOT_DIR}/test386.cpp"
 "${TEST_RUN86_ROOT_DIR}/test80186.cpp"
)

source_group(TREE ${TEST_RUN86_ROOT_DIR} PREFIX header FILES ${HEADERS})
source_group(TREE ${TEST_RUN86_ROOT_DIR} PREFIX source FILES ${SOURCES})

add_executable(test_run86 ${HEADERS} ${SOURCES})

target_link_libraries(test_run86 cpu)
