#pragma once

#include "lib86cpu.h"


inline cpu_t *cpu = nullptr;
inline uint8_t *ram = nullptr;
bool create_cpu(const std::string &executable, uint8_t *ram, size_t ramsize, addr_t code_start);

bool gen_test386asm_test(const std::string &executable);
bool gen_hook_test();
