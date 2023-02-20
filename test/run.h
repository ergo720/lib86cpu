#pragma once

#include "lib86cpu.h"
#include <cstring>
#include <memory>


inline cpu_t *cpu = nullptr;

bool gen_test386asm_test(const std::string &executable);
bool gen_hook_test();
bool gen_dbg_test();
bool gen_cxbxrkrnl_test(const std::string &executable);
void gen_test80186_test(const std::string &path, int intel_syntax, int use_dbg);
