/*
 * x86-64 emitter class
 *
 * ergo720                Copyright (c) 2022
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

class lc86_jit : public Target {
public:
	lc86_jit(cpu_t *cpu);
	void gen_code_block();
	void gen_tc_prologue() { start_new_session(); gen_prologue_main(); }
	void gen_tc_epilogue();
	void gen_aux_funcs();
	void gen_hook(void *hook_addr);
	void gen_raise_exp_inline(uint32_t fault_addr, uint16_t code, uint16_t idx, uint32_t eip);
	void free_code_block(void *addr) { m_mem.release_sys_mem(addr); }
	void destroy_all_code() { m_mem.destroy_all_blocks(); }

	void aaa(ZydisDecodedInstruction *instr);
	void aad(ZydisDecodedInstruction *instr);
	void aam(ZydisDecodedInstruction *instr);
	void aas(ZydisDecodedInstruction *instr);
	void adc(ZydisDecodedInstruction *instr);
	void add(ZydisDecodedInstruction *instr);
	void and_(ZydisDecodedInstruction *instr);
	void arpl(ZydisDecodedInstruction *instr);
	void bound(ZydisDecodedInstruction *instr);
	void bsf(ZydisDecodedInstruction *instr);
	void bsr(ZydisDecodedInstruction *instr);
	void bswap(ZydisDecodedInstruction *instr);
	void bt(ZydisDecodedInstruction *instr);
	void btc(ZydisDecodedInstruction *instr);
	void btr(ZydisDecodedInstruction *instr);
	void bts(ZydisDecodedInstruction *instr);
	void call(ZydisDecodedInstruction *instr);
	void clc(ZydisDecodedInstruction *instr);
	void cbw(ZydisDecodedInstruction *instr);
	void cdq(ZydisDecodedInstruction *instr);
	void cld(ZydisDecodedInstruction *instr);
	void cli(ZydisDecodedInstruction *instr);
	void cmc(ZydisDecodedInstruction *instr);
	void cmovcc(ZydisDecodedInstruction *instr);
	void cmp(ZydisDecodedInstruction *instr);
	void cmps(ZydisDecodedInstruction *instr);
	void cmpxchg(ZydisDecodedInstruction *instr);
	void cmpxchg8b(ZydisDecodedInstruction *instr);
	void cpuid(ZydisDecodedInstruction *instr);
	void cwd(ZydisDecodedInstruction *instr);
	void cwde(ZydisDecodedInstruction *instr);
	void daa(ZydisDecodedInstruction *instr);
	void das(ZydisDecodedInstruction *instr);
	void dec(ZydisDecodedInstruction *instr);
	void div(ZydisDecodedInstruction *instr);
	void enter(ZydisDecodedInstruction *instr);
	void fninit(ZydisDecodedInstruction *instr);
	void fnstsw(ZydisDecodedInstruction *instr);
	void hlt(ZydisDecodedInstruction *instr);
	void idiv(ZydisDecodedInstruction *instr);
	void imul(ZydisDecodedInstruction *instr);
	void in(ZydisDecodedInstruction *instr);
	void inc(ZydisDecodedInstruction *instr);
	void ins(ZydisDecodedInstruction *instr);
	void int3(ZydisDecodedInstruction *instr);
	void intn(ZydisDecodedInstruction *instr);
	void into(ZydisDecodedInstruction *instr);
	void invlpg(ZydisDecodedInstruction *instr);
	void iret(ZydisDecodedInstruction *instr);
	void jcc(ZydisDecodedInstruction *instr);
	void jmp(ZydisDecodedInstruction *instr);
	void lahf(ZydisDecodedInstruction *instr);
	void lea(ZydisDecodedInstruction *instr);
	void leave(ZydisDecodedInstruction *instr);
	void lgdt(ZydisDecodedInstruction *instr);
	void lidt(ZydisDecodedInstruction *instr);
	void lldt(ZydisDecodedInstruction *instr);
	void lods(ZydisDecodedInstruction *instr);
	void loop(ZydisDecodedInstruction *instr);
	void lds(ZydisDecodedInstruction *instr);
	void les(ZydisDecodedInstruction *instr);
	void lfs(ZydisDecodedInstruction *instr);
	void lgs(ZydisDecodedInstruction *instr);
	void lss(ZydisDecodedInstruction *instr);
	void ltr(ZydisDecodedInstruction *instr);
	void mov(ZydisDecodedInstruction *instr);
	void movs(ZydisDecodedInstruction *instr);
	void movsx(ZydisDecodedInstruction *instr);
	void movzx(ZydisDecodedInstruction *instr);
	void mul(ZydisDecodedInstruction *instr);
	void neg(ZydisDecodedInstruction *instr);
	void not_(ZydisDecodedInstruction *instr);
	void or_(ZydisDecodedInstruction *instr);
	void out(ZydisDecodedInstruction *instr);
	void outs(ZydisDecodedInstruction *instr);
	void pop(ZydisDecodedInstruction *instr);
	void popa(ZydisDecodedInstruction *instr);
	void popf(ZydisDecodedInstruction *instr);
	void push(ZydisDecodedInstruction *instr);
	void pusha(ZydisDecodedInstruction *instr);
	void pushf(ZydisDecodedInstruction *instr);
	void rcl(ZydisDecodedInstruction *instr);
	void rcr(ZydisDecodedInstruction *instr);
	void rdmsr(ZydisDecodedInstruction *instr);
	void rdtsc(ZydisDecodedInstruction *instr);
	void ret(ZydisDecodedInstruction *instr);
	void rol(ZydisDecodedInstruction *instr);
	void ror(ZydisDecodedInstruction *instr);
	void sahf(ZydisDecodedInstruction *instr);
	void sar(ZydisDecodedInstruction *instr);
	void sbb(ZydisDecodedInstruction *instr);
	void scas(ZydisDecodedInstruction *instr);
	void setcc(ZydisDecodedInstruction *instr);
	void sgdt(ZydisDecodedInstruction *instr);
	void shl(ZydisDecodedInstruction *instr);
	void shld(ZydisDecodedInstruction *instr);
	void shr(ZydisDecodedInstruction *instr);
	void shrd(ZydisDecodedInstruction *instr);
	void sidt(ZydisDecodedInstruction *instr);
	void sldt(ZydisDecodedInstruction *instr);
	void stc(ZydisDecodedInstruction *instr);
	void std(ZydisDecodedInstruction *instr);
	void sti(ZydisDecodedInstruction *instr);
	void stos(ZydisDecodedInstruction *instr);
	void str(ZydisDecodedInstruction *instr);
	void sub(ZydisDecodedInstruction *instr);
	void test(ZydisDecodedInstruction *instr);
	void verr(ZydisDecodedInstruction *instr);
	void verw(ZydisDecodedInstruction *instr);
	void wbinvd(ZydisDecodedInstruction *instr);
	void wrmsr(ZydisDecodedInstruction *instr);
	void xadd(ZydisDecodedInstruction *instr);
	void xchg(ZydisDecodedInstruction *instr);
	void xlat(ZydisDecodedInstruction *instr);
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
	template<bool set_ret = true>
	void gen_epilogue_main();
	void gen_tail_call(x86::Gp addr);
	void gen_block_end_checks();
	void gen_no_link_checks();
	bool gen_check_rf_single_step();
	template<typename T>
	void gen_link_direct(addr_t dst_pc, addr_t *next_pc, T target_addr);
	void gen_link_dst_only();
	void gen_link_indirect();
	void gen_link_ret();
	template<bool terminates, typename T1, typename T2, typename T3, typename T4>
	void gen_raise_exp_inline(T1 fault_addr, T2 code, T3 idx, T4 eip);
	template<bool terminates>
	void gen_raise_exp_inline();
	template<bool add_seg_base = true>
	op_info get_operand(ZydisDecodedInstruction *instr, const unsigned opnum);
	op_info get_register_op(ZydisDecodedInstruction *instr, const unsigned opnum);
	uint32_t get_immediate_op(ZydisDecodedInstruction *instr, const unsigned opnum);
	template<unsigned opnum, typename T1, typename T2>
	auto get_rm(ZydisDecodedInstruction *instr, T1 &&reg, T2 &&mem);
	template<bool write_dst = true, typename T>
	void r_to_rm(ZydisDecodedInstruction *instr, T &&lambda);
	template<bool is_sum, bool write_dst = true, typename T>
	void r_to_rm_flags(ZydisDecodedInstruction *instr, T &&lambda);
	template<bool write_dst = true, typename T>
	void rm_to_r(ZydisDecodedInstruction *instr, T &&lambda);
	template<bool is_sum, bool write_dst = true, typename T>
	void rm_to_r_flags(ZydisDecodedInstruction *instr, T &&lambda);
	template<bool write_dst = true, typename T>
	void imm_to_eax(ZydisDecodedInstruction *instr, T &&lambda);
	template<bool is_sum, bool write_dst = true, typename T>
	void imm_to_eax_flags(ZydisDecodedInstruction *instr, T &&lambda);
	template<typename Imm, bool write_dst = true, typename T>
	void imm_to_rm(ZydisDecodedInstruction *instr, Imm src_imm, T &&lambda);
	template<bool is_sum, typename Imm, bool write_dst = true, typename T>
	void imm_to_rm_flags(ZydisDecodedInstruction *instr, Imm src_imm, T &&lambda);
	template<unsigned size, typename T>
	void gen_sum_vec16_8(T b, x86::Gp sum);
	template<typename T>
	void gen_sum_vec32(T b);
	template<unsigned size, typename T>
	void gen_sub_vec16_8(T b, x86::Gp sum);
	template<typename T>
	void gen_sub_vec32(T b);
	template<typename T>
	void set_flags_sum(x86::Gp a, T b, x86::Gp sum);
	template<typename T1, typename T2>
	void set_flags_sub(T1 a, T2 b, x86::Gp sub);
	template<typename T1, typename T2>
	void set_flags(T1 res, T2 aux, size_t res_size);
	void ld_of(x86::Gp dst, x86::Gp aux);
	void ld_sf(x86::Gp res_dst, x86::Gp aux);
	void ld_pf(x86::Gp dst, x86::Gp res, x86::Gp aux);
	void load_reg(x86::Gp dst, size_t reg_offset, size_t size);
	template<typename T>
	void store_reg(T val, size_t reg_offset, size_t size);
	void load_mem(uint8_t size, uint8_t is_priv);
	template<typename T, bool dont_write = false>
	void store_mem(T val, uint8_t size, uint8_t is_priv);
	void load_io(uint8_t size_mode);
	void store_io(uint8_t size_mode);
	template<typename T>
	bool gen_check_io_priv(T port);
	Label rep_start(Label end);
	template<unsigned rep_prfx>
	void rep(Label start, Label end);
	template<bool use_esp = true, typename... Args>
	void gen_stack_push(Args... pushed_args);
	void gen_virtual_stack_push();
	template<unsigned num, unsigned store_at = 0, bool write_esp = true>
	void gen_stack_pop();
	template<unsigned idx>
	void shift(ZydisDecodedInstruction *instr);
	template<unsigned idx>
	void double_shift(ZydisDecodedInstruction *instr);
	template<unsigned idx>
	void rotate(ZydisDecodedInstruction *instr);
	template<unsigned idx>
	void load_sys_seg_reg(ZydisDecodedInstruction *instr);
	template<unsigned idx>
	void store_sys_seg_reg(ZydisDecodedInstruction *instr);
	template<bool is_verr>
	void verx(ZydisDecodedInstruction *instr);
	template<unsigned idx>
	void lxs(ZydisDecodedInstruction *instr);
	template<unsigned idx>
	void bit(ZydisDecodedInstruction *instr);
	template<unsigned idx>
	void int_(ZydisDecodedInstruction *instr);

	cpu_t *m_cpu;
	CodeHolder m_code;
	x86::Assembler m_a;
	bool m_needs_epilogue;
	mem_manager m_mem;
};

#endif
