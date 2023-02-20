/*
 * cpu clock
 *
 * ergo720                Copyright (c) 2023
 */

#pragma once

#include "lib86cpu_priv.h"


void tsc_init(cpu_t *cpu);
void cpu_timer_set_now(cpu_t *cpu);
uint32_t JIT_API cpu_timer_helper(cpu_ctx_t *cpu_ctx);
