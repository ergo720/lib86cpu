/*
 * cpu clock
 *
 * ergo720                Copyright (c) 2021
 */

#pragma once

#include "lib86cpu_priv.h"


void tsc_init(cpu_t *cpu);
void cpu_timer_set_now(cpu_t *cpu);
template<bool check_int>
uint32_t cpu_timer_helper(cpu_ctx_t *cpu_ctx);
