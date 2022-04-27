#pragma once

#include "lib86cpu.h"


inline cpu_t *cpu = nullptr;

bool gen_test386asm_test(const std::string &executable);
bool gen_hook_test();
bool gen_dbg_test();
bool gen_cxbxrkrnl_test(const std::string &executable);
