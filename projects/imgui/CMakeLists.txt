# ergo720 Copyright (c) 2020

cmake_minimum_required (VERSION 3.4.3)
project(imgui)

if (MSVC)
add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_DEPRECATE)
endif()

add_definitions(-DIMGUI_DISABLE_WIN32_DEFAULT_CLIPBOARD_FUNCTIONS -DIMGUI_DISABLE_WIN32_DEFAULT_IME_FUNCTIONS)

file (GLOB HEADERS
 "${LIB86CPU_ROOT_DIR}/import/imgui/imconfig.h"
 "${LIB86CPU_ROOT_DIR}/import/imgui/imgui.h"
 "${LIB86CPU_ROOT_DIR}/import/imgui/imgui_internal.h"
 "${LIB86CPU_ROOT_DIR}/import/imgui/imstb_rectpack.h"
 "${LIB86CPU_ROOT_DIR}/import/imgui/imstb_textedit.h"
 "${LIB86CPU_ROOT_DIR}/import/imgui/imstb_truetype.h"
 "${LIB86CPU_ROOT_DIR}/import/imgui/backends/imgui_impl_glfw.h"
 "${LIB86CPU_ROOT_DIR}/import/imgui/backends/imgui_impl_opengl3.h"
)

file (GLOB SOURCES
 "${LIB86CPU_ROOT_DIR}/import/imgui/imgui.cpp"
 "${LIB86CPU_ROOT_DIR}/import/imgui/imgui_draw.cpp"
 "${LIB86CPU_ROOT_DIR}/import/imgui/imgui_tables.cpp"
 "${LIB86CPU_ROOT_DIR}/import/imgui/imgui_widgets.cpp"
 "${LIB86CPU_ROOT_DIR}/import/imgui/backends/imgui_impl_glfw.cpp"
 "${LIB86CPU_ROOT_DIR}/import/imgui/backends/imgui_impl_opengl3.cpp"
)

source_group(TREE ${LIB86CPU_ROOT_DIR}/import/imgui PREFIX header FILES ${HEADERS})
source_group(TREE ${LIB86CPU_ROOT_DIR}/import/imgui PREFIX source FILES ${SOURCES})

include_directories(${LIB86CPU_ROOT_DIR}/import/imgui ${LIB86CPU_ROOT_DIR}/import/glfw/include)
add_library(imgui STATIC ${HEADERS} ${SOURCES})
