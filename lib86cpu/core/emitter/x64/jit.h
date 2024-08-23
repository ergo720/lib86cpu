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
	void gen_tc_prologue() { start_new_session(); gen_exit_func(); gen_prologue_main(); }
	void gen_tc_epilogue();
	void gen_hook(hook_t hook_addr);
	void gen_raise_exp_inline(uint32_t fault_addr, uint16_t code, uint16_t idx);
	template<bool update_eip>
	void gen_interrupt_check();
	void free_code_block(void *addr) { m_mem.release_sys_mem(addr); }
	void destroy_all_code() { m_mem.destroy_all_blocks(); }

	void aaa(decoded_instr *instr);
	void aad(decoded_instr *instr);
	void aam(decoded_instr *instr);
	void aas(decoded_instr *instr);
	void adc(decoded_instr *instr);
	void add(decoded_instr *instr);
	void and_(decoded_instr *instr);
	void arpl(decoded_instr *instr);
	void bound(decoded_instr *instr);
	void bsf(decoded_instr *instr);
	void bsr(decoded_instr *instr);
	void bswap(decoded_instr *instr);
	void bt(decoded_instr *instr);
	void btc(decoded_instr *instr);
	void btr(decoded_instr *instr);
	void bts(decoded_instr *instr);
	void call(decoded_instr *instr);
	void clc(decoded_instr *instr);
	void cbw(decoded_instr *instr);
	void cdq(decoded_instr *instr);
	void cld(decoded_instr *instr);
	void cli(decoded_instr *instr);
	void clts(decoded_instr* instr);
	void cmc(decoded_instr *instr);
	void cmovcc(decoded_instr *instr);
	void cmp(decoded_instr *instr);
	void cmps(decoded_instr *instr);
	void cmpxchg(decoded_instr *instr);
	void cmpxchg8b(decoded_instr *instr);
	void cpuid(decoded_instr *instr);
	void cwd(decoded_instr *instr);
	void cwde(decoded_instr *instr);
	void daa(decoded_instr *instr);
	void das(decoded_instr *instr);
	void dec(decoded_instr *instr);
	void div(decoded_instr *instr);
	void enter(decoded_instr *instr);
	void fild(decoded_instr *instr);
	void fistp(decoded_instr *instr);
	void fld(decoded_instr *instr);
	void fld1(decoded_instr *instr);
	void fldcw(decoded_instr *instr);
	void fldl2e(decoded_instr *instr);
	void fldl2t(decoded_instr *instr);
	void fldlg2(decoded_instr *instr);
	void fldln2(decoded_instr *instr);
	void fldpi(decoded_instr *instr);
	void fldz(decoded_instr *instr);
	void fnclex(decoded_instr *instr);
	void fninit(decoded_instr *instr);
	void fnstcw(decoded_instr *instr);
	void fnstsw(decoded_instr *instr);
	void fstp(decoded_instr *instr);
	void fwait(decoded_instr *instr);
	void fxrstor(decoded_instr *instr);
	void fxsave(decoded_instr *instr);
	void hlt(decoded_instr *instr);
	void idiv(decoded_instr *instr);
	void imul(decoded_instr *instr);
	void in(decoded_instr *instr);
	void inc(decoded_instr *instr);
	void ins(decoded_instr *instr);
	void int3(decoded_instr *instr);
	void intn(decoded_instr *instr);
	void into(decoded_instr *instr);
	void invlpg(decoded_instr *instr);
	void iret(decoded_instr *instr);
	void jcc(decoded_instr *instr);
	void jmp(decoded_instr *instr);
	void lahf(decoded_instr *instr);
	void lea(decoded_instr *instr);
	void leave(decoded_instr *instr);
	void lgdt(decoded_instr *instr);
	void lidt(decoded_instr *instr);
	void lldt(decoded_instr *instr);
	void lmsw(decoded_instr* instr);
	void lods(decoded_instr *instr);
	void loop(decoded_instr *instr);
	void lds(decoded_instr *instr);
	void les(decoded_instr *instr);
	void lfs(decoded_instr *instr);
	void lgs(decoded_instr *instr);
	void lss(decoded_instr *instr);
	void ltr(decoded_instr *instr);
	void mov(decoded_instr *instr);
	void movaps(decoded_instr *instr);
	void movntps(decoded_instr *instr);
	void movs(decoded_instr *instr);
	void movsx(decoded_instr *instr);
	void movzx(decoded_instr *instr);
	void mul(decoded_instr *instr);
	void neg(decoded_instr *instr);
	void not_(decoded_instr *instr);
	void or_(decoded_instr *instr);
	void out(decoded_instr *instr);
	void outs(decoded_instr *instr);
	void pop(decoded_instr *instr);
	void popa(decoded_instr *instr);
	void popf(decoded_instr *instr);
	void push(decoded_instr *instr);
	void pusha(decoded_instr *instr);
	void pushf(decoded_instr *instr);
	void rcl(decoded_instr *instr);
	void rcr(decoded_instr *instr);
	void rdmsr(decoded_instr *instr);
	void rdtsc(decoded_instr *instr);
	void ret(decoded_instr *instr);
	void rol(decoded_instr *instr);
	void ror(decoded_instr *instr);
	void sahf(decoded_instr *instr);
	void sar(decoded_instr *instr);
	void sbb(decoded_instr *instr);
	void scas(decoded_instr *instr);
	void setcc(decoded_instr *instr);
	void sgdt(decoded_instr *instr);
	void shl(decoded_instr *instr);
	void shld(decoded_instr *instr);
	void shr(decoded_instr *instr);
	void shrd(decoded_instr *instr);
	void sidt(decoded_instr *instr);
	void sldt(decoded_instr *instr);
	void stc(decoded_instr *instr);
	void std(decoded_instr *instr);
	void sti(decoded_instr *instr);
	void stos(decoded_instr *instr);
	void str(decoded_instr *instr);
	void sub(decoded_instr *instr);
	void test(decoded_instr *instr);
	void verr(decoded_instr *instr);
	void verw(decoded_instr *instr);
	void wbinvd(decoded_instr *instr);
	void wrmsr(decoded_instr *instr);
	void xadd(decoded_instr *instr);
	void xchg(decoded_instr *instr);
	void xlat(decoded_instr *instr);
	void xor_(decoded_instr *instr);
	void xorps(decoded_instr *instr);

#if defined(_WIN64) || defined (__linux__)
	void gen_exception_info(uint8_t *code_ptr, size_t code_size);
#endif

private:
	void start_new_session();
	void gen_prologue_main();
	template<bool set_ret = true>
	void gen_epilogue_main();
	void gen_tail_call(x86::Gp addr);
	void gen_exit_func();
	void gen_aux_funcs();
	void gen_no_link_checks();
	void gen_timeout_check();
	bool gen_check_rf_single_step();
	template<typename T>
	void gen_link_direct(addr_t dst_pc, addr_t *next_pc, T target_addr);
	void gen_link_dst_only();
	void gen_link_indirect();
	void gen_link_ret();
	template<typename T>
	void gen_link_dst_cond(T &&lambda);
	template<bool terminates, typename T1, typename T2, typename T3>
	void gen_raise_exp_inline(T1 fault_addr, T2 code, T3 idx);
	template<bool terminates>
	void gen_raise_exp_inline();
	template<bool add_seg_base = true>
	op_info get_operand(decoded_instr *instr, const unsigned opnum);
	op_info get_register_op(decoded_instr *instr, const unsigned opnum);
	uint32_t get_immediate_op(decoded_instr *instr, const unsigned opnum);
	template<unsigned opnum, typename T1, typename T2>
	auto get_rm(decoded_instr *instr, T1 &&reg, T2 &&mem);
	template<bool write_dst = true, typename T>
	void r_to_rm(decoded_instr *instr, T &&lambda);
	template<bool is_sum, bool write_dst = true, typename T>
	void r_to_rm_flags(decoded_instr *instr, T &&lambda);
	template<bool write_dst = true, typename T>
	void rm_to_r(decoded_instr *instr, T &&lambda);
	template<bool is_sum, bool write_dst = true, typename T>
	void rm_to_r_flags(decoded_instr *instr, T &&lambda);
	template<bool write_dst = true, typename T>
	void imm_to_eax(decoded_instr *instr, T &&lambda);
	template<bool is_sum, bool write_dst = true, typename T>
	void imm_to_eax_flags(decoded_instr *instr, T &&lambda);
	template<typename Imm, bool write_dst = true, typename T>
	void imm_to_rm(decoded_instr *instr, Imm src_imm, T &&lambda);
	template<bool is_sum, typename Imm, bool write_dst = true, typename T>
	void imm_to_rm_flags(decoded_instr *instr, Imm src_imm, T &&lambda);
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
	void gen_simd_mem_align_check();
	void gen_fpu_exp_post_check();
	void gen_set_host_fpu_ctx();
	template<bool update_fdp>
	void gen_update_fpu_ptr(decoded_instr *instr);
	template<bool is_push>
	void gen_fpu_stack_fault_check(bool should_set_ftop_in_ebx, fpu_instr_t fpu_instr);
	template<unsigned idx>
	void shift(decoded_instr *instr);
	template<unsigned idx>
	void double_shift(decoded_instr *instr);
	template<unsigned idx>
	void rotate(decoded_instr *instr);
	template<unsigned idx>
	void load_sys_seg_reg(decoded_instr *instr);
	template<unsigned idx>
	void store_sys_seg_reg(decoded_instr *instr);
	template<bool is_verr>
	void verx(decoded_instr *instr);
	template<unsigned idx>
	void lxs(decoded_instr *instr);
	template<unsigned idx>
	void bit(decoded_instr *instr);
	template<unsigned idx>
	void int_(decoded_instr *instr);
	template<unsigned idx>
	void float_load_constant(decoded_instr *instr);
	template<bool is_push, typename T>
	void gen_fpu_stack_prologue(bool should_set_ftop_in_ebx, fpu_instr_t fpu_instr, T &&action_when_no_fault);

	cpu_t *m_cpu;
	CodeHolder m_code;
	x86::Assembler m_a;
	mem_manager m_mem;
	Label m_exit_int, m_next_instr;
};

#endif
