/*
 * x86-64 emitter class
 *
 * ergo720                Copyright (c) 2020
 */

#pragma once

#include <asmjit/asmjit.h>
#include "lib86cpu_priv.h"
#include "allocator.h"
#include "../emitter_common.h"

#ifdef LIB86CPU_X64_EMITTER


using namespace asmjit;


// val: value of immediate or offset of referenced register, bits: size in bits of val
struct op_info {
	size_t val;
	size_t bits;
	op_info() : val(0U), bits(0U) {}
	op_info(size_t val_, size_t bits_) : val(val_), bits(bits_) {}
};

// all x64 regs that can actually be used in the main jitted function
enum class x64 : uint32_t {
	rax = 0,
	rcx,
	rdx,
	rdi,
	r8,
	r9,
	r10,
	r11,
	max = r11,
};

class lc86_jit : public Target {
public:
	lc86_jit(cpu_t *cpu);
	void gen_code_block(translated_code_t *tc);
	void gen_tc_prologue() { start_new_session(); gen_prologue_main(); }
	void gen_tc_epilogue();
	void raise_exp_inline_emit(uint32_t fault_addr, uint16_t code, uint16_t idx, uint32_t eip);
	void free_code_block(void *addr) { m_mem.release_sys_mem(addr); }
	void destroy_all_code() { m_mem.destroy_all_blocks(); }

	void cli(ZydisDecodedInstruction *instr);
	void jmp(ZydisDecodedInstruction *instr);
	void mov(ZydisDecodedInstruction *instr);
	void out(ZydisDecodedInstruction *instr);
	void xor_(ZydisDecodedInstruction *instr);

#if defined(_WIN64)
	uint8_t *gen_exception_info(uint8_t *code_ptr, size_t code_size);

private:
	void create_unwind_info();

	uint8_t m_unwind_info[4 + 12];
#endif

private:
	void start_new_session();
	void gen_prologue_main();
	void gen_epilogue_main();
	void gen_tail_call(x86::Gp addr);
	void gen_int_fn();
	void check_int_emit();
	bool check_rf_single_step_emit();
	template<typename T>
	void link_direct_emit(addr_t dst_pc, addr_t *next_pc, T target_addr);
	void link_dst_only_emit();
	void link_indirect_emit();
	template<bool terminates, typename T1, typename T2, typename T3, typename T4>
	void raise_exp_inline_emit(T1 fault_addr, T2 code, T3 idx, T4 eip);
	template<bool terminates>
	void raise_exp_inline_emit();
	op_info get_operand(ZydisDecodedInstruction *instr, const unsigned opnum);
	op_info get_register_op(ZydisDecodedInstruction *instr, const unsigned opnum);
	uint32_t get_immediate_op(ZydisDecodedInstruction *instr, const unsigned opnum);
	template<unsigned opnum, typename T, typename U>
	auto get_rm(ZydisDecodedInstruction *instr, T &&reg, U &&mem);
	template<x64 res_32reg, typename T1, typename T2>
	void set_flags(T1 res, T2 aux, size_t size);
	void load_reg(x86::Gp dst, size_t reg_offset, size_t size);
	void store_reg(size_t size, size_t offset);
	void store_reg(size_t size, size_t offset, uint32_t val);
	op_info load_mem(uint8_t size_mode, uint8_t is_priv);
	void store_mem(uint8_t size_mode, uint8_t is_priv);
	void store_mem(uint8_t size_mode, uint32_t val, uint8_t is_priv);
	void store_io(uint8_t size_mode);
	template<typename T>
	void check_io_priv_emit(T port);

	cpu_t *m_cpu;
	CodeHolder m_code;
	x86::Assembler m_a;
	size_t m_prolog_patch_offset;
	bool m_needs_epilogue;
	mem_manager m_mem;
};

#endif
