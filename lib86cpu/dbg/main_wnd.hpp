/*
 * ergo720                Copyright (c) 2022
 */

#pragma once

#include <future>


void dbg_main_wnd(cpu_t *cpu, std::promise<bool> &promise);
void dbg_should_close();
