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
JIT_API void fpu_update_tag(cpu_ctx_t *cpu_ctx, uint32_t st_num);
JIT_API uint32_t fpu_is_tag_empty(cpu_ctx_t *cpu_ctx, uint32_t st_num);
JIT_API void fpu_stack_overflow(cpu_ctx_t *cpu_ctx);
JIT_API void fpu_stack_underflow(cpu_ctx_t *cpu_ctx, uint32_t st_num, uint32_t should_pop);
JIT_API void fpu_stack_fault(cpu_ctx_t *cpu_ctx, uint32_t exception);
JIT_API void fpu_update_ptr(cpu_ctx_t *cpu_ctx, uint64_t instr_info);
