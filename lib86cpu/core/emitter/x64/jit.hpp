/*
 * x86-64 emitter class
 *
 * ergo720                Copyright (c) 2022
 */

#pragma once

#include <asmjit/asmjit.h>
#include "lib86cpu_priv.hpp"
#include "allocator.hpp"
#include "../emitter_common.hpp"

#ifdef LIB86CPU_X64_EMITTER


using namespace asmjit;


// val: value of immediate or offset of referenced register, bits: size in bits of val or, for moffset only, whether or not the segment base was added to it
struct op_info {
	uint64_t val;
	uint64_t bits;
	op_info() : val(0U), bits(0U) {}
	op_info(size_t val_, size_t bits_) : val(val_), bits(bits_) {}
};


class lc86_jit {
public:
	enum class ret_tc_t {
	zero,
	dont_set,
	};

	lc86_jit(cpu_t *cpu);
	void gen_code_block();
	void gen_tc_prologue() { start_new_session(); gen_exit_func(); gen_prologue_main(); }
	void gen_tc_epilogue();
	void gen_hook(hook_t hook_addr);
	void gen_raise_exp_inline(uint32_t fault_addr, uint16_t code, uint16_t idx);
	void update_eip();
	void gen_interrupt_check();
	void free_code_block(void *addr) { m_mem.release_sys_mem(addr); }
	void destroy_all_code() { m_mem.destroy_all_blocks(); }

	void unimplemented(decoded_instr *instr);
	void AAA(decoded_instr *instr);
	void AAD(decoded_instr *instr);
	void AAM(decoded_instr *instr);
	void AAS(decoded_instr *instr);
	void ADC(decoded_instr *instr);
	void ADD_(decoded_instr *instr);
	void ADDSS_(decoded_instr *instr);
	void ADDPS_(decoded_instr *instr);
	void AND_(decoded_instr *instr);
	void ARPL(decoded_instr *instr);
	void BOUND(decoded_instr *instr);
	void BSF_(decoded_instr *instr);
	void BSR_(decoded_instr *instr);
	void BSWAP_(decoded_instr *instr);
	void BT_(decoded_instr *instr);
	void BTC_(decoded_instr *instr);
	void BTR_(decoded_instr *instr);
	void BTS_(decoded_instr *instr);
	void CALL_(decoded_instr *instr);
	void CLC_(decoded_instr *instr);
	void CBW(decoded_instr *instr);
	void CDQ(decoded_instr *instr);
	void CLD(decoded_instr *instr);
	void CLI(decoded_instr *instr);
	void CLTS(decoded_instr* instr);
	void CMC(decoded_instr *instr);
	void CMOVB(decoded_instr *instr);
	void CMOVBE(decoded_instr *instr);
	void CMOVL(decoded_instr *instr);
	void CMOVLE(decoded_instr *instr);
	void CMOVNB(decoded_instr *instr);
	void CMOVNBE(decoded_instr *instr);
	void CMOVNL(decoded_instr *instr);
	void CMOVNLE(decoded_instr *instr);
	void CMOVNO(decoded_instr *instr);
	void CMOVNP(decoded_instr *instr);
	void CMOVNS(decoded_instr *instr);
	void CMOVNZ(decoded_instr *instr);
	void CMOVO(decoded_instr *instr);
	void CMOVP(decoded_instr *instr);
	void CMOVS(decoded_instr *instr);
	void CMOVZ(decoded_instr *instr);
	void CMP_(decoded_instr *instr);
	void CMPSB(decoded_instr *instr);
	void CMPSW(decoded_instr *instr);
	void CMPSD(decoded_instr *instr);
	void CMPXCHG(decoded_instr *instr);
	void CMPXCHG8B(decoded_instr *instr);
	void CPUID(decoded_instr *instr);
	void CVTTSS2SI_(decoded_instr *instr);
	void CWD(decoded_instr *instr);
	void CWDE(decoded_instr *instr);
	void DAA(decoded_instr *instr);
	void DAS(decoded_instr *instr);
	void DEC_(decoded_instr *instr);
	void DIV_(decoded_instr *instr);
	void EMMS_(decoded_instr *instr);
	void ENTER(decoded_instr *instr);
	void FADD_(decoded_instr *instr);
	void FADDP_(decoded_instr *instr);
	void FIADD_(decoded_instr *instr);
	void FCHS_(decoded_instr *instr);
	void FCOM(decoded_instr *instr);
	void FCOMP_(decoded_instr *instr);
	void FCOMPP_(decoded_instr *instr);
	void FCOS_(decoded_instr *instr);
	void FDIV_(decoded_instr *instr);
	void FDIVP_(decoded_instr *instr);
	void FIDIV_(decoded_instr *instr);
	void FDIVR_(decoded_instr *instr);
	void FDIVRP_(decoded_instr *instr);
	void FIDIVR_(decoded_instr *instr);
	void FILD_(decoded_instr *instr);
	void FIST(decoded_instr *instr);
	void FISTP_(decoded_instr *instr);
	void FLD_(decoded_instr *instr);
	void FLD1_(decoded_instr *instr);
	void FLDCW_(decoded_instr *instr);
	void FLDL2E_(decoded_instr *instr);
	void FLDL2T_(decoded_instr *instr);
	void FLDLG2_(decoded_instr *instr);
	void FLDLN2_(decoded_instr *instr);
	void FLDPI_(decoded_instr *instr);
	void FLDZ_(decoded_instr *instr);
	void FMUL_(decoded_instr *instr);
	void FMULP(decoded_instr *instr);
	void FIMUL_(decoded_instr *instr);
	void FNCLEX_(decoded_instr *instr);
	void FNINIT(decoded_instr *instr);
	void FNSTCW_(decoded_instr *instr);
	void FNSTSW_(decoded_instr *instr);
	void FPATAN_(decoded_instr *instr);
	void FSIN_(decoded_instr *instr);
	void FSINCOS_(decoded_instr *instr);
	void FSQRT_(decoded_instr *instr);
	void FSTP_(decoded_instr *instr);
	void FSUB_(decoded_instr *instr);
	void FSUBP(decoded_instr *instr);
	void FISUB_(decoded_instr *instr);
	void FSUBR_(decoded_instr *instr);
	void FSUBRP(decoded_instr *instr);
	void FISUBR_(decoded_instr *instr);
	void FWAIT(decoded_instr *instr);
	void FXCH_(decoded_instr *instr);
	void FXRSTOR(decoded_instr *instr);
	void FXSAVE(decoded_instr *instr);
	void HLT(decoded_instr *instr);
	void IDIV_(decoded_instr *instr);
	void IMUL(decoded_instr *instr);
	void IN(decoded_instr *instr);
	void INC_(decoded_instr *instr);
	void INSB(decoded_instr *instr);
	void INSW(decoded_instr *instr);
	void INSD(decoded_instr *instr);
	void INT3_(decoded_instr *instr);
	void INTN(decoded_instr *instr);
	void INTO(decoded_instr *instr);
	void INVLPG(decoded_instr *instr);
	void IRET(decoded_instr *instr);
	void IRETD(decoded_instr *instr);
	void JCXZ(decoded_instr *instr);
	void JECXZ(decoded_instr *instr);
	void JO(decoded_instr *instr);
	void JNO(decoded_instr *instr);
	void JB(decoded_instr *instr);
	void JNB(decoded_instr *instr);
	void JZ(decoded_instr *instr);
	void JNZ(decoded_instr *instr);
	void JBE(decoded_instr *instr);
	void JNBE(decoded_instr *instr);
	void JS(decoded_instr *instr);
	void JNS(decoded_instr *instr);
	void JP(decoded_instr *instr);
	void JNP(decoded_instr *instr);
	void JL(decoded_instr *instr);
	void JNL(decoded_instr *instr);
	void JLE(decoded_instr *instr);
	void JNLE(decoded_instr *instr);
	void JMP(decoded_instr *instr);
	void LAHF(decoded_instr *instr);
	void LEA_(decoded_instr *instr);
	void LEAVE(decoded_instr *instr);
	void LGDT(decoded_instr *instr);
	void LIDT(decoded_instr *instr);
	void LLDT(decoded_instr *instr);
	void LMSW(decoded_instr* instr);
	void LODSB(decoded_instr *instr);
	void LODSW(decoded_instr *instr);
	void LODSD(decoded_instr *instr);
	void LOOP(decoded_instr *instr);
	void LOOPE(decoded_instr *instr);
	void LOOPNE(decoded_instr *instr);
	void LDS(decoded_instr *instr);
	void LES(decoded_instr *instr);
	void LFS(decoded_instr *instr);
	void LGS(decoded_instr *instr);
	void LSS(decoded_instr *instr);
	void LTR(decoded_instr *instr);
	void MOV_(decoded_instr *instr);
	void MOVAPS_(decoded_instr *instr);
	void MOVLPS(decoded_instr *instr);
	void MOVHPS(decoded_instr *instr);
	void MOVNTPS(decoded_instr *instr);
	void MOVNTQ(decoded_instr *instr);
	void MOVQ(decoded_instr *instr);
	void MOVSD(decoded_instr *instr);
	void MOVSW(decoded_instr *instr);
	void MOVSB(decoded_instr *instr);
	void MOVSS_(decoded_instr *instr);
	void MOVSX_(decoded_instr *instr);
	void MOVZX_(decoded_instr *instr);
	void MUL_(decoded_instr *instr);
	void MULSS_(decoded_instr *instr);
	void MULPS_(decoded_instr *instr);
	void NEG_(decoded_instr *instr);
	void NOP(decoded_instr *instr);
	void NOT_(decoded_instr *instr);
	void OR_(decoded_instr *instr);
	void OUT(decoded_instr *instr);
	void OUTSD(decoded_instr *instr);
	void OUTSW(decoded_instr *instr);
	void OUTSB(decoded_instr *instr);
	void PAUSE(decoded_instr *instr);
	void POP_(decoded_instr *instr);
	void POPA(decoded_instr *instr);
	void POPAD(decoded_instr *instr);
	void POPF(decoded_instr *instr);
	void POPFD(decoded_instr *instr);
	void PREFETCHNTA(decoded_instr *instr);
	void PREFETCHT0(decoded_instr *instr);
	void PREFETCHT1(decoded_instr *instr);
	void PREFETCHT2(decoded_instr *instr);
	void PUSH_(decoded_instr *instr);
	void PUSHA(decoded_instr *instr);
	void PUSHAD(decoded_instr *instr);
	void PUSHF(decoded_instr *instr);
	void PUSHFD(decoded_instr *instr);
	void RCL_(decoded_instr *instr);
	void RCPPS_(decoded_instr *instr);
	void RCPSS_(decoded_instr *instr);
	void RCR_(decoded_instr *instr);
	void RDMSR(decoded_instr *instr);
	void RDTSC(decoded_instr *instr);
	void RET_(decoded_instr *instr);
	void ROL_(decoded_instr *instr);
	void ROR_(decoded_instr *instr);
	void RSQRTPS_(decoded_instr *instr);
	void RSQRTSS_(decoded_instr *instr);
	void SAHF(decoded_instr *instr);
	void SAR_(decoded_instr *instr);
	void SBB(decoded_instr *instr);
	void SCASD(decoded_instr *instr);
	void SCASW(decoded_instr *instr);
	void SCASB(decoded_instr *instr);
	void SETB(decoded_instr *instr);
	void SETBE(decoded_instr *instr);
	void SETL(decoded_instr *instr);
	void SETLE(decoded_instr *instr);
	void SETNB(decoded_instr *instr);
	void SETNBE(decoded_instr *instr);
	void SETNL(decoded_instr *instr);
	void SETNLE(decoded_instr *instr);
	void SETNO(decoded_instr *instr);
	void SETNP(decoded_instr *instr);
	void SETNS(decoded_instr *instr);
	void SETNZ_(decoded_instr *instr);
	void SETO_(decoded_instr *instr);
	void SETP(decoded_instr *instr);
	void SETS(decoded_instr *instr);
	void SETZ(decoded_instr *instr);
	void SFENCE(decoded_instr *instr);
	void SGDT(decoded_instr *instr);
	void SHL_(decoded_instr *instr);
	void SHLD_(decoded_instr *instr);
	void SHR_(decoded_instr *instr);
	void SHRD_(decoded_instr *instr);
	void SHUFPS_(decoded_instr *instr);
	void SIDT(decoded_instr *instr);
	void SLDT(decoded_instr *instr);
	void STC_(decoded_instr *instr);
	void STD(decoded_instr *instr);
	void STI(decoded_instr *instr);
	void STOSD(decoded_instr *instr);
	void STOSW(decoded_instr *instr);
	void STOSB(decoded_instr *instr);
	void STR(decoded_instr *instr);
	void SUB_(decoded_instr *instr);
	void SUBPS_(decoded_instr *instr);
	void SUBSS_(decoded_instr *instr);
	void TEST_(decoded_instr *instr);
	void UNPCKHPS_(decoded_instr *instr);
	void UNPCKLPS_(decoded_instr *instr);
	void VERR(decoded_instr *instr);
	void VERW(decoded_instr *instr);
	void WBINVD(decoded_instr *instr);
	void WRMSR(decoded_instr *instr);
	void XADD(decoded_instr *instr);
	void XCHG_(decoded_instr *instr);
	void XLAT(decoded_instr *instr);
	void XOR_(decoded_instr *instr);
	void XORPS_(decoded_instr *instr);

#if defined(_WIN64) || defined (__linux__)
	void gen_exception_info(uint8_t *code_ptr, uint64_t code_size);
#endif

private:
	void CMOVCC(decoded_instr *instr);
	std::array<addr_t, 2> JCC_start(decoded_instr *instr);
	void JCC_end(decoded_instr *instr, std::array<addr_t, 2> arr);
	void SETCC(decoded_instr *instr);

	void start_new_session();
	void gen_prologue_main();
	template<ret_tc_t set_ret>
	void gen_epilogue_main();
	void gen_tail_call(x86::Gp addr);
	void gen_exit_func();
	void gen_aux_funcs();
	bool gen_no_link_checks();
	void gen_timeout_check();
	bool gen_check_rf_single_step();
	template<typename T, bool emit_checks = true>
	void gen_tc_linking_jmp(T target_addr);
	void gen_rsb_push();
	void gen_rsb_pop();
	void gen_tc_linking_ret();
	template<bool terminates, typename T1, typename T2, typename T3>
	void gen_raise_exp_inline(T1 fault_addr, T2 code, T3 idx);
	template<bool terminates>
	void gen_raise_exp_inline();
	template<bool add_seg_base = true>
	op_info get_operand(decoded_instr *instr, const unsigned opnum);
	op_info get_register_op(decoded_instr *instr, const unsigned opnum);
	uint64_t get_immediate_op(decoded_instr *instr, const unsigned opnum);
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
	void load_mem(uint64_t size);
	template<bool dont_write = false>
	void store_mem(uint64_t size);
#ifdef XBOX_CPU
	void load_ipt(uint64_t size);
	void load_moffset(uint64_t size, op_info info);
	void store_ipt(uint64_t size);
	void store_moffset(uint64_t size, op_info info);
#endif
	void load_io(uint64_t size_mode);
	void store_io(uint64_t size_mode);
	template<typename T>
	bool gen_check_io_priv(T port);
	Label rep_start(Label end);
	template<unsigned rep_prfx>
	void rep(Label start, Label end);
	template<bool use_esp = true, typename T>
	void gen_stack_push(T rgs);
	void gen_virtual_stack_push();
	template<unsigned num, unsigned store_at = 0, bool write_esp = true>
	void gen_stack_pop();
	void gen_simd_mem_align_check();
	void gen_set_host_simd_ctx();
	void gen_simd_exp_post_check();
	template<bool write_fstatus, typename T>
	void gen_fpu_exp_post_check(uint32_t exception, T &&unmasked);
	void gen_set_host_fpu_ctx();
	void gen_update_fpu_ptr(decoded_instr *instr);
	template<unsigned idx>
	void simd_arithmetic(decoded_instr *instr, bool is_packed);
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
	void fpu_load_constant(decoded_instr *instr);
	template<unsigned idx>
	void fpu_arithmetic(decoded_instr *instr);
	template<unsigned idx>
	void fpu_store(decoded_instr *instr);
	template<unsigned idx>
	void fpu_load(decoded_instr *instr);
	void gen_fpu_check_stack_overflow();
	void gen_fpu_check_stack_underflow(uint32_t st_num_src, uint32_t st_mun_dst, uint32_t should_pop);
	void gen_fpu_check_stack_fault_fpatan();
	void gen_fpu_check_stack_fault_fsincos();
	void gen_fpu_check_stack_fault_fxch(uint32_t st_num);
	void gen_fpu_check_stack_fault_fcom1(uint32_t st_num1, uint32_t pops_num);
	void gen_fpu_check_stack_fault_fcom2(uint32_t st_num1, uint32_t st_num2, uint32_t pops_num);
	template<typename T, T qnan>
	void gen_fpu_check_stack_underflow(uint32_t st_num_src, uint32_t should_pop);
	void gen_check_fpu_unmasked_exp();
	void gen_fpu_load_stx(uint32_t st_num);
	void gen_fpu_store_stx(uint32_t st_num);
	void gen_vzeroupper();
	void gen_fpu2mmx_transition();

	cpu_t *m_cpu;
	CodeHolder m_code;
	x86::Assembler m_a;
	Environment m_environment;
	mem_manager m_mem;
	Label m_exit_int, m_rsb_push_pop;
	std::size_t m_instr_after_call_byte_align;
};

using instr_func = void(lc86_jit::*)(decoded_instr *);

#endif
