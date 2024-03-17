/*
 * cpu clock
 *
 * ergo720                Copyright (c) 2023
 */

#pragma once

#include "lib86cpu_priv.h"


uint64_t get_current_time();
void tsc_init(cpu_t *cpu);
void cpu_timer_set_now(cpu_t *cpu);
JIT_API uint32_t cpu_timer_helper(cpu_ctx_t *cpu_ctx);
