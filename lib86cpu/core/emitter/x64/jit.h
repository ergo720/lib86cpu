/*
 * x86-64 emitter class
 *
 * ergo720                Copyright (c) 2020
 */

#pragma once

#include <asmjit/asmjit.h>
#include "lib86cpu_priv.h"
#include "allocator.h"
#include "../common.h"

#ifdef LIB86CPU_X64_EMITTER

#define RAISEin(addr, code, idx, eip) cpu->jit->raise_exp_inline_emit(addr, code, idx, eip)
#define RAISEin0(idx) cpu->jit->raise_exp_inline_emit(0, 0, idx, cpu->instr_eip)


using namespace asmjit;


class lc86_jit : public Target {
public:
	lc86_jit(cpu_t *cpu);
	void start_new_session();
	void gen_code_block(translated_code_t *tc);
	void gen_prologue_main();
	void raise_exp_inline_emit(uint32_t fault_addr, uint16_t code, uint16_t idx, uint32_t eip);
	void free_code_block(void *addr) { m_mem.release_sys_mem(addr); }
	void destroy_all_code() { m_mem.destroy_all_blocks(); }

#if defined(_WIN64)
	uint8_t *gen_exception_info(uint8_t *code_ptr, size_t code_size);

private:
	void create_unwind_info();

	uint8_t m_unwind_info[4 + 12];
#endif

private:
	void gen_int_fn();

	cpu_t *m_cpu;
	CodeHolder m_code;
	x86::Assembler m_a;
	size_t m_prolog_patch_offset;
	size_t m_stack_args_size;
	size_t m_local_vars_size;
	bool m_update_guest_eip;
	mem_manager m_mem;
};

#endif
