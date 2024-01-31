/*
 * ergo720                Copyright (c) 2024
 */

#pragma once

#include "lib86cpu_priv.h"


enum class fpu_instr_t : int {
	integer8 = 0,
	integer16,
	integer32,
	integer64,
	float_,
	bcd,
};

void fpu_init(cpu_t *cpu);
void JIT_API fpu_update_tag(cpu_ctx_t *cpu_ctx, uint32_t idx);
template<bool is_push, fpu_instr_t instr_type>
uint32_t JIT_API fpu_stack_check(cpu_ctx_t *cpu_ctx, uint32_t *sw, uint80_t *inv_val);
