/*
 * ergo720                Copyright (c) 2024
 */

#pragma once

#include "lib86cpu_priv.h"


enum class fpu_instr_t : uint32_t {
	integer8 = 0,
	integer16,
	integer32,
	integer64,
	float_,
	bcd,
};

void fpu_init(cpu_t *cpu);
template<bool is_push>
JIT_API void fpu_update_tag(cpu_ctx_t *cpu_ctx, uint32_t idx);
template<bool is_push, fpu_instr_t instr_type>
JIT_API uint32_t fpu_stack_check(cpu_ctx_t *cpu_ctx, uint32_t *sw, uint80_t *inv_val);
template<bool is_push>
JIT_API uint32_t fpu_stack_check(cpu_ctx_t *cpu_ctx, uint32_t *sw, uint80_t *inv_val, fpu_instr_t instr_type);
