/*
 * x86 translation code
 *
 * ergo720                Copyright (c) 2019
 */

#include "internal.hpp"
#include "memory_management.hpp"
#include "main_wnd.hpp"
#include "debugger.hpp"
#include "helpers.hpp"
#include "clock.hpp"

#ifdef LIB86CPU_X64_EMITTER
#include "x64/jit.hpp"
#endif

#ifdef XBOX_CPU
#include "ipt.hpp"
#endif

// Make sure we can safely use memset on the register structs
static_assert(std::is_trivially_copyable_v<regs_t>);
static_assert(std::is_trivially_copyable_v<msr_t>);


// NOTE: msvc has a hard limit of 128 nesting levels while compiling code, which will be reached if putting all instruction cases
// in a single function. To avoid that, we split the if/else statements in multiple functions after 100 instructions

#define INSTR_BEGIN(func, ...) if (instr == ZydisMnemonic::ZYDIS_MNEMONIC_ ## func) {\
return std::pair<uint16_t, instr_func>{1, &lc86_jit::func ## __VA_ARGS__};\
}
#define INSTR_CASE(func, ...) else if (instr == ZydisMnemonic::ZYDIS_MNEMONIC_ ## func) {\
return std::pair<uint16_t, instr_func>{1, &lc86_jit::func ## __VA_ARGS__};\
}
#define INSTR_END() \
return std::pair<uint16_t, instr_func>{0, &lc86_jit::unimplemented}

#define INSTR_CALL(func) \
return func(instr)

constexpr auto dispatch_func3(int instr)
{
	INSTR_BEGIN(RCL, _)
		INSTR_CASE(RCPPS, _)
		INSTR_CASE(RCPSS, _)
		INSTR_CASE(RCR, _)
		INSTR_CASE(RDMSR)
		INSTR_CASE(RDTSC)
		INSTR_CASE(RET, _)
		INSTR_CASE(ROL, _)
		INSTR_CASE(ROR, _)
		INSTR_CASE(RSQRTPS, _)
		INSTR_CASE(RSQRTSS, _)
		INSTR_CASE(SAHF)
		INSTR_CASE(SAR, _)
		INSTR_CASE(SBB)
		INSTR_CASE(SCASB)
		INSTR_CASE(SCASD)
		INSTR_CASE(SCASW)
		INSTR_CASE(SETB)
		INSTR_CASE(SETBE)
		INSTR_CASE(SETL)
		INSTR_CASE(SETLE)
		INSTR_CASE(SETNB)
		INSTR_CASE(SETNBE)
		INSTR_CASE(SETNL)
		INSTR_CASE(SETNLE)
		INSTR_CASE(SETNO)
		INSTR_CASE(SETNP)
		INSTR_CASE(SETNS)
		INSTR_CASE(SETNZ, _)
		INSTR_CASE(SETO, _)
		INSTR_CASE(SETP)
		INSTR_CASE(SETS)
		INSTR_CASE(SETZ)
		INSTR_CASE(SFENCE)
		INSTR_CASE(SGDT)
		INSTR_CASE(SHL, _)
		INSTR_CASE(SHLD, _)
		INSTR_CASE(SHR, _)
		INSTR_CASE(SHRD, _)
		INSTR_CASE(SHUFPS, _)
		INSTR_CASE(SIDT)
		INSTR_CASE(SLDT)
		INSTR_CASE(STC, _)
		INSTR_CASE(STD)
		INSTR_CASE(STI)
		INSTR_CASE(STOSB)
		INSTR_CASE(STOSD)
		INSTR_CASE(STOSW)
		INSTR_CASE(STR)
		INSTR_CASE(SUB, _)
		INSTR_CASE(SUBPS, _)
		INSTR_CASE(SUBSS, _)
		INSTR_CASE(TEST, _)
		INSTR_CASE(UNPCKHPS, _)
		INSTR_CASE(UNPCKLPS, _)
		INSTR_CASE(VERR)
		INSTR_CASE(VERW)
		INSTR_CASE(WBINVD)
		INSTR_CASE(WRMSR)
		INSTR_CASE(XADD)
		INSTR_CASE(XCHG, _)
		INSTR_CASE(XLAT)
		INSTR_CASE(XOR, _)
		INSTR_CASE(XORPS, _)
	INSTR_END();
}

constexpr auto dispatch_func2(int instr)
{
	INSTR_BEGIN(FISUB, _)
		INSTR_CASE(FSUBR, _)
		INSTR_CASE(FSUBRP)
		INSTR_CASE(FISUBR, _)
		INSTR_CASE(FWAIT)
		INSTR_CASE(FXCH, _)
		INSTR_CASE(FXRSTOR)
		INSTR_CASE(FXSAVE)
		INSTR_CASE(HLT)
		INSTR_CASE(IDIV, _)
		INSTR_CASE(IMUL)
		INSTR_CASE(IN)
		INSTR_CASE(INC, _)
		INSTR_CASE(INSB)
		INSTR_CASE(INSD)
		INSTR_CASE(INSW)
		INSTR_CASE(INT3, _)
		INSTR_CASE(INT, N)
		INSTR_CASE(INTO)
		INSTR_CASE(INVLPG)
		INSTR_CASE(IRET)
		INSTR_CASE(IRETD)
		INSTR_CASE(JCXZ)
		INSTR_CASE(JECXZ)
		INSTR_CASE(JO)
		INSTR_CASE(JNO)
		INSTR_CASE(JB)
		INSTR_CASE(JNB)
		INSTR_CASE(JZ)
		INSTR_CASE(JNZ)
		INSTR_CASE(JBE)
		INSTR_CASE(JNBE)
		INSTR_CASE(JS)
		INSTR_CASE(JNS)
		INSTR_CASE(JP)
		INSTR_CASE(JNP)
		INSTR_CASE(JL)
		INSTR_CASE(JNL)
		INSTR_CASE(JLE)
		INSTR_CASE(JNLE)
		INSTR_CASE(JMP)
		INSTR_CASE(LAHF)
		INSTR_CASE(LDS)
		INSTR_CASE(LEA, _)
		INSTR_CASE(LEAVE)
		INSTR_CASE(LES)
		INSTR_CASE(LFS)
		INSTR_CASE(LGDT)
		INSTR_CASE(LGS)
		INSTR_CASE(LIDT)
		INSTR_CASE(LLDT)
		INSTR_CASE(LMSW)
		INSTR_CASE(LODSB)
		INSTR_CASE(LODSD)
		INSTR_CASE(LODSW)
		INSTR_CASE(LOOP)
		INSTR_CASE(LOOPE)
		INSTR_CASE(LOOPNE)
		INSTR_CASE(LSS)
		INSTR_CASE(LTR)
		INSTR_CASE(MOV, _)
		INSTR_CASE(MOVAPS, _)
		INSTR_CASE(MOVLPS)
		INSTR_CASE(MOVHPS)
		INSTR_CASE(MOVNTPS)
		INSTR_CASE(MOVNTQ)
		INSTR_CASE(MOVQ)
		INSTR_CASE(MOVSB)
		INSTR_CASE(MOVSD)
		INSTR_CASE(MOVSW)
		INSTR_CASE(MOVSS, _)
		INSTR_CASE(MOVSX, _)
		INSTR_CASE(MOVZX, _)
		INSTR_CASE(MUL, _)
		INSTR_CASE(MULSS, _)
		INSTR_CASE(MULPS, _)
		INSTR_CASE(NEG, _)
		INSTR_CASE(NOP)
		INSTR_CASE(NOT, _)
		INSTR_CASE(OR, _)
		INSTR_CASE(OUT)
		INSTR_CASE(OUTSB)
		INSTR_CASE(OUTSD)
		INSTR_CASE(OUTSW)
		INSTR_CASE(PAUSE)
		INSTR_CASE(POP, _)
		INSTR_CASE(POPA)
		INSTR_CASE(POPAD)
		INSTR_CASE(POPF)
		INSTR_CASE(POPFD)
		INSTR_CASE(PREFETCHNTA)
		INSTR_CASE(PREFETCHT0)
		INSTR_CASE(PREFETCHT1)
		INSTR_CASE(PREFETCHT2)
		INSTR_CASE(PUSH, _)
		INSTR_CASE(PUSHA)
		INSTR_CASE(PUSHAD)
		INSTR_CASE(PUSHF)
		INSTR_CASE(PUSHFD)
	INSTR_CALL(dispatch_func3);
}

constexpr auto dispatch_func1(int instr)
{
	INSTR_BEGIN(AAA)
		INSTR_CASE(AAD)
		INSTR_CASE(AAM)
		INSTR_CASE(AAS)
		INSTR_CASE(ADC)
		INSTR_CASE(ADD, _)
		INSTR_CASE(ADDSS, _)
		INSTR_CASE(ADDPS, _)
		INSTR_CASE(AND, _)
		INSTR_CASE(ARPL)
		INSTR_CASE(BOUND)
		INSTR_CASE(BSF, _)
		INSTR_CASE(BSR, _)
		INSTR_CASE(BSWAP, _)
		INSTR_CASE(BT, _)
		INSTR_CASE(BTC, _)
		INSTR_CASE(BTR, _)
		INSTR_CASE(BTS, _)
		INSTR_CASE(CALL, _)
		INSTR_CASE(CBW)
		INSTR_CASE(CDQ)
		INSTR_CASE(CLC, _)
		INSTR_CASE(CLD)
		INSTR_CASE(CLI)
		INSTR_CASE(CLTS)
		INSTR_CASE(CMC)
		INSTR_CASE(CMOVB)
		INSTR_CASE(CMOVBE)
		INSTR_CASE(CMOVL)
		INSTR_CASE(CMOVLE)
		INSTR_CASE(CMOVNB)
		INSTR_CASE(CMOVNBE)
		INSTR_CASE(CMOVNL)
		INSTR_CASE(CMOVNLE)
		INSTR_CASE(CMOVNO)
		INSTR_CASE(CMOVNP)
		INSTR_CASE(CMOVNS)
		INSTR_CASE(CMOVNZ)
		INSTR_CASE(CMOVO)
		INSTR_CASE(CMOVP)
		INSTR_CASE(CMOVS)
		INSTR_CASE(CMOVZ)
		INSTR_CASE(CMP, _)
		INSTR_CASE(CMPSB)
		INSTR_CASE(CMPSW)
		INSTR_CASE(CMPSD)
		INSTR_CASE(CMPXCHG)
		INSTR_CASE(CMPXCHG8B)
		INSTR_CASE(CPUID)
		INSTR_CASE(CVTTSS2SI, _)
		INSTR_CASE(CWD)
		INSTR_CASE(CWDE)
		INSTR_CASE(DAA)
		INSTR_CASE(DAS)
		INSTR_CASE(DEC, _)
		INSTR_CASE(DIV, _)
		INSTR_CASE(EMMS, _)
		INSTR_CASE(ENTER)
		INSTR_CASE(FADD, _)
		INSTR_CASE(FADDP, _)
		INSTR_CASE(FIADD, _)
		INSTR_CASE(FCHS, _)
		INSTR_CASE(FCOM)
		INSTR_CASE(FCOMP, _)
		INSTR_CASE(FCOMPP, _)
		INSTR_CASE(FCOS, _)
		INSTR_CASE(FDIV, _)
		INSTR_CASE(FDIVP, _)
		INSTR_CASE(FIDIV, _)
		INSTR_CASE(FDIVR, _)
		INSTR_CASE(FDIVRP, _)
		INSTR_CASE(FIDIVR, _)
		INSTR_CASE(FILD, _)
		INSTR_CASE(FIST)
		INSTR_CASE(FISTP, _)
		INSTR_CASE(FLD, _)
		INSTR_CASE(FLD1, _)
		INSTR_CASE(FLDCW, _)
		INSTR_CASE(FLDL2E, _)
		INSTR_CASE(FLDL2T, _)
		INSTR_CASE(FLDLG2, _)
		INSTR_CASE(FLDLN2, _)
		INSTR_CASE(FLDPI, _)
		INSTR_CASE(FLDZ, _)
		INSTR_CASE(FMUL, _)
		INSTR_CASE(FMULP)
		INSTR_CASE(FIMUL, _)
		INSTR_CASE(FNCLEX, _)
		INSTR_CASE(FNINIT)
		INSTR_CASE(FNSTCW, _)
		INSTR_CASE(FNSTSW, _)
		INSTR_CASE(FPATAN, _)
		INSTR_CASE(FSIN, _)
		INSTR_CASE(FSINCOS, _)
		INSTR_CASE(FSQRT, _)
		INSTR_CASE(FST, P_)
		INSTR_CASE(FSTP, _)
		INSTR_CASE(FSUB, _)
		INSTR_CASE(FSUBP)
	INSTR_CALL(dispatch_func2);
}

template<std::size_t Length, unsigned Action, typename Generator, std::size_t... Indexes>
constexpr auto gen_func_table_impl(Generator&& f, std::index_sequence<Indexes...>)
{
	if constexpr (Action == 0) {
		std::array<uint16_t, Length> arr {{ f(Indexes).first... }}; // sets to 1 all positions with implemented instructions
		int idx = 0;
		for (auto &val : arr) {
			if (val) {
				val = ++idx; // converts all 1's to increasing index values
			}
		}
		return arr;
	}
	else if constexpr (Action == 1) {
		std::array<uint16_t, Length> arr {{ f(Indexes).first... }};
		std::size_t num = 0;
		for (auto val : arr) {
			if (val) {
				++num; // sums all 1's
			}
		}
		return num;
	}
	else {
		throw std::logic_error("Unknown action requested");
	}
}

template<std::size_t Length, unsigned Action, typename Generator>
constexpr auto gen_func_table(Generator&& f)
{
	return gen_func_table_impl<Length, Action>(std::forward<Generator>(f), std::make_index_sequence<Length>{});
}

template<std::size_t Length, std::array<uint16_t, ZYDIS_MNEMONIC_MAX_VALUE + 1> arr, typename Generator>
constexpr auto gen_func_table(Generator &&f)
{
	std::array<instr_func, Length> local_arr {};
	local_arr[0] = &lc86_jit::unimplemented;
	int j = 1;
	for (int i = 0; i < arr.size(); ++i) {
		if (arr[i]) {
			local_arr[j] = f(i).second;
			++j;
		}
	}
	return local_arr;
}

constexpr static std::array<uint16_t, ZYDIS_MNEMONIC_MAX_VALUE + 1> s_zydis2idx_table = gen_func_table<ZYDIS_MNEMONIC_MAX_VALUE + 1, 0>(dispatch_func1);
constexpr static std::size_t instr_table_size = 1 + gen_func_table<ZYDIS_MNEMONIC_MAX_VALUE + 1, 1>(dispatch_func1);
constexpr static std::array<instr_func, instr_table_size> s_instr_table = gen_func_table<instr_table_size, s_zydis2idx_table>(dispatch_func1);

#undef INSTR_BEGIN
#undef INSTR_CASE
#undef INSTR_END
#undef INSTR_CALL

#ifdef XBOX_CPU
template<typename T>
void memory_region_t<T>::cpu_rom_deinit(uint8_t *rom_ptr, uint8_t *rom_alias_ptr, addr_t start)
{
	if constexpr (std::is_same_v<T, addr_t>) {
		ipt_rom_deinit(rom_ptr, rom_alias_ptr, start);
	}
}

template void memory_region_t<addr_t>::cpu_rom_deinit(uint8_t *rom_ptr, uint8_t *rom_alias_ptr, addr_t start);
template void memory_region_t<port_t>::cpu_rom_deinit(uint8_t *rom_ptr, uint8_t *rom_alias_ptr, addr_t start);
#endif

void
cpu_reset(cpu_t *cpu)
{
	std::memset(&cpu->cpu_ctx.regs, 0, sizeof(regs_t));
	std::memset(&cpu->msr, 0, sizeof(msr_t));
	cpu->cpu_ctx.regs.eip = 0x0000FFF0;
	cpu->cpu_ctx.regs.edx = 0x0000068A;
	cpu->cpu_ctx.regs.cs = 0xF000;
	cpu->cpu_ctx.regs.cs_hidden.base = 0xFFFF0000;
	cpu->cpu_ctx.regs.es_hidden.limit = cpu->cpu_ctx.regs.cs_hidden.limit = cpu->cpu_ctx.regs.ss_hidden.limit =
	cpu->cpu_ctx.regs.ds_hidden.limit = cpu->cpu_ctx.regs.fs_hidden.limit = cpu->cpu_ctx.regs.gs_hidden.limit = 0xFFFF;
	cpu->cpu_ctx.regs.cs_hidden.flags = ((1 << 15) | (1 << 12) | (1 << 11) | (1 << 9) | (1 << 8)); // present, code, readable, accessed
	cpu->cpu_ctx.regs.es_hidden.flags = cpu->cpu_ctx.regs.ss_hidden.flags = cpu->cpu_ctx.regs.ds_hidden.flags =
	cpu->cpu_ctx.regs.fs_hidden.flags = cpu->cpu_ctx.regs.gs_hidden.flags = ((1 << 15) | (1 << 12) | (1 << 9) | (1 << 8)); // present, data, writable, accessed
	cpu->cpu_ctx.regs.eflags = 0x2;
	cpu->cpu_ctx.regs.cr0 = 0x60000010;
	cpu->cpu_ctx.regs.dr[6] = DR6_RES_MASK;
	cpu->cpu_ctx.regs.dr[7] = DR7_RES_MASK;
	cpu->cpu_ctx.regs.idtr_hidden.limit = cpu->cpu_ctx.regs.gdtr_hidden.limit = cpu->cpu_ctx.regs.ldtr_hidden.limit =
	cpu->cpu_ctx.regs.tr_hidden.limit = 0xFFFF;
	cpu->cpu_ctx.regs.ldtr_hidden.flags = ((1 << 15) | (2 << 8)); // present, ldt
	cpu->cpu_ctx.regs.tr_hidden.flags = ((1 << 15) | (11 << 8)); // present, 32bit tss busy
	cpu->cpu_ctx.regs.mxcsr = 0x1F80;
	cpu->cpu_ctx.shadow_mxcsr = cpu->cpu_ctx.regs.mxcsr;
	cpu->cpu_ctx.lazy_eflags.result = 0x100; // make zf=0
	cpu->a20_mask = 0xFFFFFFFF; // gate closed
	cpu->cpu_ctx.exp_info.old_exp = EXP_INVALID;
	cpu->msr.ebl_cr_poweron = 0xC5040000; // system bus frequency = 133 MHz, clock frequency ratio = 5.5, low power mode enabled
	cpu->msr.mcg_cap = (MCG_NUM_BANKS | MCG_CTL_P | MCG_SER_P);
	cpu->msr.mcg_ctl = MCG_CTL_ENABLE;
	for (unsigned i = 0; i < MCG_NUM_BANKS; ++i) {
		cpu->msr.mca_banks[i][MCi_CTL] = MCi_CTL_ENABLE;
	}
	rsb_flush(cpu);
	tsc_init(cpu);
	fpu_init(cpu);
	tlb_flush_g(cpu);
	tc_cache_purge(cpu);
}

static std::string
exp_idx_to_str(unsigned idx)
{
	switch (idx)
	{
	case EXP_DE:
		return "DE";

	case EXP_DB:
		return "DB";

	case EXP_NMI:
		return "NMI";

	case EXP_BP:
		return "BP";

	case EXP_OF:
		return "OF";

	case EXP_BR:
		return "BR";

	case EXP_UD:
		return "UD";

	case EXP_NM:
		return "NM";

	case EXP_DF:
		return "DF";

	case EXP_TS:
		return "TS";

	case EXP_NP:
		return "NP";

	case EXP_SS:
		return "SS";

	case EXP_GP:
		return "GP";

	case EXP_PF:
		return "PF";

	case EXP_MF:
		return "MF";

	case EXP_AC:
		return "AC";

	case EXP_MC:
		return "MC";

	case EXP_XF:
		return "XF";

	case EXP_INVALID:
		return "NOTHING";

	default:
		return std::to_string(idx);
	}
}

static void
check_dbl_exp(cpu_ctx_t *cpu_ctx)
{
	uint16_t idx = cpu_ctx->exp_info.exp_data.idx;
	bool old_contributory = cpu_ctx->exp_info.old_exp == 0 || (cpu_ctx->exp_info.old_exp >= 10 && cpu_ctx->exp_info.old_exp <= 13);
	bool curr_contributory = idx == 0 || (idx >= 10 && idx <= 13);

	LOG(log_level::info, "Exception thrown -> old: %s new %s", exp_idx_to_str(cpu_ctx->exp_info.old_exp).c_str(), exp_idx_to_str(idx).c_str());

	if (cpu_ctx->exp_info.old_exp == EXP_DF) {
		throw lc86_exp_abort("The guest has triple faulted, cannot continue", lc86_status::success);
	}

	if ((old_contributory && curr_contributory) || (cpu_ctx->exp_info.old_exp == EXP_PF && (curr_contributory || (idx == EXP_PF)))) {
		cpu_ctx->exp_info.exp_data.code = 0;
		idx = EXP_DF;
	}

	if (curr_contributory || (idx == EXP_PF) || (idx == EXP_DF)) {
		cpu_ctx->exp_info.old_exp = idx;
	}

	cpu_ctx->exp_info.exp_data.idx = idx;
}

template<unsigned is_intn, bool is_hw_int>
translated_code_t *cpu_raise_exception(cpu_ctx_t *cpu_ctx)
{
	// If lib86dbg is present, we will forward to it all debug and breakpoint exceptions and let it handle them
	if (cpu_ctx->cpu->cpu_flags & CPU_DBG_PRESENT) [[unlikely]] {
		uint32_t idx = cpu_ctx->exp_info.exp_data.idx;
		if ((idx == EXP_DB) || (idx == EXP_BP)) {
			dbg_exp_handler(cpu_ctx);
			return nullptr;
		}
	}

	// is_intn -> not a int instruction(0), int3(1), intn(2), into(3), is_hw_int -> hardware interrupt
	if constexpr (!(is_intn) && !(is_hw_int)) {
		check_dbl_exp(cpu_ctx);
	}

	cpu_t *cpu = cpu_ctx->cpu;
	uint32_t fault_addr = cpu_ctx->exp_info.exp_data.fault_addr;
	uint16_t code = cpu_ctx->exp_info.exp_data.code;
	uint32_t idx = cpu_ctx->exp_info.exp_data.idx;
	uint32_t eip = cpu_ctx->regs.eip;
	uint32_t cs_base = cpu_ctx->regs.cs_hidden.base;
	uint32_t old_eflags = read_eflags(cpu);

	if (cpu_ctx->hflags & HFLG_PE_MODE) {
		// protected mode

		constexpr uint16_t ext_flg = is_intn ? 0 : 1; // EXT flag clear for INT instructions, set otherwise

		uint32_t iopl = (cpu_ctx->regs.eflags & IOPL_MASK) >> 12;
		if ((is_intn == 2) && (((cpu_ctx->regs.eflags & VM_MASK) | (cpu_ctx->hflags & HFLG_CR4_VME)) == VM_MASK) &&
			(((cpu_ctx->regs.eflags & IOPL_MASK) >> 12) < 3)) {
			cpu_ctx->exp_info.exp_data.code = 0;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		if ((is_intn == 2) && (((cpu_ctx->regs.eflags & VM_MASK) | (cpu_ctx->hflags & HFLG_CR4_VME)) == (VM_MASK | HFLG_CR4_VME))) {
			uint16_t offset = mem_read_helper<uint16_t>(cpu_ctx, cpu_ctx->regs.tr_hidden.base + 102, 0);
			uint8_t io_int_table_byte = mem_read_helper<uint8_t>(cpu_ctx, cpu_ctx->regs.tr_hidden.base + offset - 32 + idx / 8, 0);
			if ((io_int_table_byte & (1 << (idx % 8))) == 0) {
				if (iopl < 3) {
					old_eflags = ((old_eflags & VIF_MASK) >> 10) | (old_eflags & ~(IF_MASK | IOPL_MASK)) | IOPL_MASK;
				}
				uint32_t esp = cpu_ctx->regs.esp;
				uint32_t stack_mask = cpu_ctx->hflags & HFLG_SS32 ? 0xFFFFFFFF : 0xFFFF;
				uint32_t stack_base = cpu_ctx->regs.ss_hidden.base;
				esp -= 2;
				mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), old_eflags, 0);
				esp -= 2;
				mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, 0);
				esp -= 2;
				mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), eip, 0);
				uint32_t vec_entry = mem_read_helper<uint32_t>(cpu_ctx, idx * 4, 0);
				uint32_t eflags_mask = TF_MASK;
				cpu_ctx->regs.esp = (cpu_ctx->regs.esp & ~stack_mask) | (esp & stack_mask);
				cpu_ctx->regs.cs = vec_entry >> 16;
				cpu_ctx->regs.cs_hidden.base = cpu_ctx->regs.cs << 4;
				cpu_ctx->regs.eip = vec_entry & 0xFFFF;
				if (iopl == 3) {
					eflags_mask |= (IF_MASK | VIF_MASK);
				}
				cpu_ctx->regs.eflags &= ~eflags_mask;
				cpu_ctx->exp_info.old_exp = EXP_INVALID;
				if (idx == EXP_PF) {
					cpu_ctx->regs.cr2 = fault_addr;
				}
				if (idx == EXP_DB) {
					cpu_ctx->regs.dr[7] &= ~DR7_GD_MASK;
				}

				return nullptr;
			}
			else {
				if (iopl != 3) {
					cpu_ctx->exp_info.exp_data.code = 0;
					cpu_ctx->exp_info.exp_data.idx = EXP_GP;
					return cpu_raise_exception(cpu_ctx);
				}
			}
		}

		if (idx * 8 + 7 > cpu_ctx->regs.idtr_hidden.limit) {
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2 + ext_flg;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		uint64_t desc = mem_read_helper<uint64_t>(cpu_ctx, cpu_ctx->regs.idtr_hidden.base + idx * 8, 2);
		uint16_t type = (desc >> 40) & 0x1F;
		uint32_t new_eip, eflags;
		switch (type)
		{
		case 5:  // task gate
			// we don't support task gates yet, so just abort
			LIB86CPU_ABORT_msg("Task gates are not supported yet while delivering an exception");

		case 6:  // interrupt gate, 16 bit
		case 14: // interrupt gate, 32 bit
			eflags = cpu_ctx->regs.eflags & ~IF_MASK;
			new_eip = ((desc & 0xFFFF000000000000) >> 32) | (desc & 0xFFFF);
			break;

		case 7:  // trap gate, 16 bit
		case 15: // trap gate, 32 bit
			eflags = cpu_ctx->regs.eflags;
			new_eip = ((desc & 0xFFFF000000000000) >> 32) | (desc & 0xFFFF);
			break;

		default:
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2 + ext_flg;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		uint32_t dpl = (desc & SEG_DESC_DPL) >> 45;
		uint32_t cpl = cpu_ctx->hflags & HFLG_CPL;
		if (is_intn && (dpl < cpl)) { // only INT instructions check the dpl of the gate in the idt
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		if ((desc & SEG_DESC_P) == 0) {
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2 + ext_flg;
			cpu_ctx->exp_info.exp_data.idx = EXP_NP;
			return cpu_raise_exception(cpu_ctx);
		}

		uint16_t sel = (desc & 0xFFFF0000) >> 16;
		if ((sel >> 2) == 0) {
			cpu_ctx->exp_info.exp_data.code = ext_flg;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		addr_t code_desc_addr;
		uint64_t code_desc;
		if (read_seg_desc_helper(cpu, sel, code_desc_addr, code_desc)) {
			cpu_ctx->exp_info.exp_data.code += ext_flg;
			return cpu_raise_exception(cpu_ctx);
		}

		dpl = (code_desc & SEG_DESC_DPL) >> 45;
		if (dpl > cpl) {
			cpu_ctx->exp_info.exp_data.code = (sel & 0xFFFC) + ext_flg;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		if ((code_desc & SEG_DESC_P) == 0) {
			cpu_ctx->exp_info.exp_data.code = (sel & 0xFFFC) + ext_flg;
			cpu_ctx->exp_info.exp_data.idx = EXP_NP;
			return cpu_raise_exception(cpu_ctx);
		}

		if (code_desc & SEG_DESC_C) {
			dpl = cpl;
		}

		set_access_flg_seg_desc_helper(cpu, code_desc, code_desc_addr);

		const auto &exp_has_code = [idx]() -> uint8_t
		{
			if constexpr (is_intn || is_hw_int) {
				// INT instructions and hw interrupts don't push error codes
				return 0;
			}
			else {
				switch (idx)
				{
				case EXP_DF:
				case EXP_TS:
				case EXP_NP:
				case EXP_SS:
				case EXP_GP:
				case EXP_PF:
				case EXP_AC:
					return 1;
				}

				return 0;
			}
		};

		uint32_t seg_base = read_seg_desc_base_helper(cpu, code_desc);
		uint32_t seg_limit = read_seg_desc_limit_helper(cpu, code_desc);
		uint32_t seg_flags = read_seg_desc_flags_helper(cpu, code_desc);
		uint32_t stack_switch, stack_mask, stack_base, esp;
		uint32_t new_esp;
		uint16_t new_ss;
		uint64_t ss_desc;

		if (dpl < cpl) {
			// more privileged

			const auto &check_ss_desc = [eip, cpu]<bool is_vm86>(cpu_ctx_t *cpu_ctx, uint32_t dpl, uint32_t &new_esp, uint16_t &new_ss, uint64_t &ss_desc)
			{
				addr_t ss_desc_addr;

				if (read_stack_ptr_from_tss_helper(cpu, dpl, new_esp, new_ss, is_vm86 ? 2 : 0)) {
					cpu_ctx->exp_info.exp_data.code += ext_flg;
					return true;
				}

				if ((new_ss >> 2) == 0) {
					cpu_ctx->exp_info.exp_data.code = ext_flg;
					cpu_ctx->exp_info.exp_data.idx = EXP_TS;
					return true;
				}

				if (read_seg_desc_helper(cpu, new_ss, ss_desc_addr, ss_desc)) {
					cpu_ctx->exp_info.exp_data.code += ext_flg;
					cpu_ctx->exp_info.exp_data.idx = EXP_TS;
					return true;
				}

				uint32_t p = (ss_desc & SEG_DESC_P) >> 40;
				uint32_t s = (ss_desc & SEG_DESC_S) >> 44;
				uint32_t d = (ss_desc & SEG_DESC_DC) >> 42;
				uint32_t w = (ss_desc & SEG_DESC_W) >> 39;
				uint32_t ss_dpl = (ss_desc & SEG_DESC_DPL) >> 42;
				uint32_t ss_rpl = (new_ss & 3) << 5;
				uint32_t dpl_compare = is_vm86 ? 0 : dpl;
				if ((s | d | w | ss_dpl | ss_rpl | p) ^ ((0x85 | (dpl_compare << 3)) | (dpl_compare << 5))) {
					cpu_ctx->exp_info.exp_data.code = (new_ss & 0xFFFC) + ext_flg;
					cpu_ctx->exp_info.exp_data.idx = EXP_TS;
					return true;
				}

				set_access_flg_seg_desc_helper(cpu, ss_desc, ss_desc_addr);

				return false;
			};

			if (cpu_ctx->regs.eflags & VM_MASK) {
				if (dpl) {
					cpu_ctx->exp_info.exp_data.code = (sel & 0xFFFC) + ext_flg;
					cpu_ctx->exp_info.exp_data.idx = EXP_GP;
					return cpu_raise_exception(cpu_ctx);
				}

				if (check_ss_desc.template operator()<true>(cpu_ctx, dpl, new_esp, new_ss, ss_desc)) {
					return cpu_raise_exception(cpu_ctx);
				}

				uint32_t esp = new_esp;
				uint32_t stack_mask = ss_desc & SEG_DESC_DB ? 0xFFFFFFFF : 0xFFFF;
				uint32_t stack_base = read_seg_desc_base_helper(cpu, ss_desc);

				const auto &push_regs = [old_eflags, eip, exp_has_code, code]<bool is_idt32>(cpu_ctx_t *cpu_ctx, uint32_t &esp, uint32_t stack_mask, uint32_t stack_base)
				{
					using T = std::conditional_t<is_idt32, uint32_t, uint16_t>;
					constexpr uint32_t push_size = sizeof(T);

					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.gs, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.fs, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.ds, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.es, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.ss, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.esp, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), old_eflags, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), eip, 2);
					if (exp_has_code()) {
						esp -= push_size;
						mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), code, 2);
					}
				};

				if ((type == 14) || (type == 15)) {
					push_regs.template operator()<true>(cpu_ctx, esp, stack_mask, stack_base);
				}
				else {
					push_regs.template operator()<false>(cpu_ctx, esp, stack_mask, stack_base);
					new_eip &= 0xFFFF;
				}

				cpu_ctx->regs.gs = cpu_ctx->regs.fs = cpu_ctx->regs.ds = cpu_ctx->regs.es = 0;
				cpu_ctx->regs.gs_hidden.base = cpu_ctx->regs.fs_hidden.base = cpu_ctx->regs.ds_hidden.base = cpu_ctx->regs.es_hidden.base = 0;
				cpu_ctx->regs.gs_hidden.limit = cpu_ctx->regs.fs_hidden.limit = cpu_ctx->regs.ds_hidden.limit = cpu_ctx->regs.es_hidden.limit = 0;
				cpu_ctx->regs.gs_hidden.flags = cpu_ctx->regs.fs_hidden.flags = cpu_ctx->regs.ds_hidden.flags = cpu_ctx->regs.es_hidden.flags = 0;
				cpu_ctx->regs.cs = sel & 0xFFC;
				cpu_ctx->regs.cs_hidden.base = seg_base;
				cpu_ctx->regs.cs_hidden.limit = seg_limit;
				cpu_ctx->regs.cs_hidden.flags = seg_flags;
				cpu_ctx->hflags = ((cpu_ctx->regs.cs_hidden.flags & SEG_HIDDEN_DB) >> 20) | (cpu_ctx->hflags & ~(HFLG_CS32 | HFLG_CPL));
				cpu_ctx->regs.ss = new_ss;
				cpu_ctx->regs.ss_hidden.base = stack_base;
				cpu_ctx->regs.ss_hidden.limit = read_seg_desc_limit_helper(cpu, ss_desc);
				cpu_ctx->regs.ss_hidden.flags = read_seg_desc_flags_helper(cpu, ss_desc);
				cpu_ctx->hflags = ((cpu_ctx->regs.ss_hidden.flags & SEG_HIDDEN_DB) >> 19) | (cpu_ctx->hflags & ~HFLG_SS32);
				cpu_ctx->regs.eflags = (eflags & ~(VM_MASK | RF_MASK | NT_MASK | TF_MASK));
				cpu_ctx->regs.esp = (cpu_ctx->regs.esp & ~stack_mask) | (esp & stack_mask);
				cpu_ctx->regs.eip = new_eip;
				cpu_ctx->exp_info.old_exp = EXP_INVALID;
				if (idx == EXP_PF) {
					cpu_ctx->regs.cr2 = fault_addr;
				}
				if (idx == EXP_DB) {
					cpu_ctx->regs.dr[7] &= ~DR7_GD_MASK;
				}

				return nullptr;
			}

			if (check_ss_desc.template operator()<false>(cpu_ctx, dpl, new_esp, new_ss, ss_desc)) {
				return cpu_raise_exception(cpu_ctx);
			}

			stack_switch = 1;
			stack_mask = ss_desc & SEG_DESC_DB ? 0xFFFFFFFF : 0xFFFF;
			stack_base = read_seg_desc_base_helper(cpu, ss_desc);
			esp = new_esp;
		}
		else {
			if (cpu_ctx->regs.eflags & VM_MASK) {
				cpu_ctx->exp_info.exp_data.code = (sel & 0xFFFC) + ext_flg;
				cpu_ctx->exp_info.exp_data.idx = EXP_GP;
				return cpu_raise_exception(cpu_ctx);
			}
			else if (dpl == cpl) {
				// same privilege

				stack_switch = 0;
				stack_mask = cpu_ctx->hflags & HFLG_SS32 ? 0xFFFFFFFF : 0xFFFF;
				stack_base = cpu_ctx->regs.ss_hidden.base;
				esp = cpu_ctx->regs.esp;
			}
			else {
				cpu_ctx->exp_info.exp_data.code = (sel & 0xFFFC) + ext_flg;
				cpu_ctx->exp_info.exp_data.idx = EXP_GP;
				return cpu_raise_exception(cpu_ctx);
			}
		}

		uint8_t has_code = exp_has_code();

		const auto &push_regs = [old_eflags, eip, has_code, code]<bool is_push32, bool stack_switch>(cpu_ctx_t *cpu_ctx, uint32_t &esp, uint32_t stack_mask,
			uint32_t stack_base, uint8_t is_priv)
		{
			using T = std::conditional_t<is_push32, uint32_t, uint16_t>;
			constexpr uint32_t push_size = sizeof(T);

			if constexpr (stack_switch) {
				esp -= push_size;
				mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.ss, is_priv);
				esp -= push_size;
				mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.esp, is_priv);
			}
			esp -= push_size;
			mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), old_eflags, is_priv);
			esp -= push_size;
			mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, is_priv);
			esp -= push_size;
			mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), eip, is_priv);
			if (has_code) {
				esp -= push_size;
				mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), code, is_priv);
			}
		};

		type >>= 3;
		if (stack_switch) {
			if (type) { // push 32, priv
				push_regs.template operator()<true, true>(cpu_ctx, esp, stack_mask, stack_base, 2);
			}
			else { // push 16, priv
				push_regs.template operator()<false, true>(cpu_ctx, esp, stack_mask, stack_base, 2);
			}

			uint32_t ss_is_zero = stack_base ? 0 : HFLG_SS_IS_ZERO;
			uint32_t ss_flags = read_seg_desc_flags_helper(cpu, ss_desc);
			cpu_ctx->regs.ss = (new_ss & ~3) | dpl;
			cpu_ctx->regs.ss_hidden.base = stack_base;
			cpu_ctx->regs.ss_hidden.limit = read_seg_desc_limit_helper(cpu, ss_desc);
			cpu_ctx->regs.ss_hidden.flags = ss_flags;
			cpu_ctx->hflags = (((ss_flags & SEG_HIDDEN_DB) >> 19) | ss_is_zero) | (cpu_ctx->hflags & ~(HFLG_SS32 | HFLG_SS_IS_ZERO));
		}
		else {
			if (type) { // push 32, not priv
				push_regs.template operator()<true, false>(cpu_ctx, esp, stack_mask, stack_base, 0);
			}
			else { // push 16, not priv
				push_regs.template operator()<false, false>(cpu_ctx, esp, stack_mask, stack_base, 0);
			}
		}

		uint32_t cs_is_zero = seg_base ? 0 : HFLG_CS_IS_ZERO;
		cpu_ctx->regs.eflags = (eflags & ~(VM_MASK | RF_MASK | NT_MASK | TF_MASK));
		cpu_ctx->regs.esp = (cpu_ctx->regs.esp & ~stack_mask) | (esp & stack_mask);
		cpu_ctx->regs.cs = (sel & ~3) | dpl;
		cpu_ctx->regs.cs_hidden.base = seg_base;
		cpu_ctx->regs.cs_hidden.limit = seg_limit;
		cpu_ctx->regs.cs_hidden.flags = seg_flags;
		cpu_ctx->hflags = (((seg_flags & SEG_HIDDEN_DB) >> 20) | dpl | cs_is_zero) | (cpu_ctx->hflags & ~(HFLG_CS32 | HFLG_CPL | HFLG_CS_IS_ZERO));
		cpu_ctx->regs.eip = new_eip;
		if (idx == EXP_PF) {
			cpu_ctx->regs.cr2 = fault_addr;
		}
	}
	else {
		// real mode

		if (idx * 4 + 3 > cpu_ctx->regs.idtr_hidden.limit) {
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		uint32_t vec_entry = mem_read_helper<uint32_t>(cpu_ctx, cpu_ctx->regs.idtr_hidden.base + idx * 4, 0);
		uint32_t stack_mask = 0xFFFF;
		uint32_t stack_base = cpu_ctx->regs.ss_hidden.base;
		uint32_t esp = cpu_ctx->regs.esp;
		esp -= 2;
		mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), old_eflags, 0);
		esp -= 2;
		mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, 0);
		esp -= 2;
		mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), eip, 0);

		cpu_ctx->regs.eflags &= ~(AC_MASK | RF_MASK | IF_MASK | TF_MASK);
		cpu_ctx->regs.esp = (cpu_ctx->regs.esp & ~stack_mask) | (esp & stack_mask);
		cpu_ctx->regs.cs = vec_entry >> 16;
		cpu_ctx->regs.cs_hidden.base = cpu_ctx->regs.cs << 4;
		cpu_ctx->regs.eip = vec_entry & 0xFFFF;
		uint32_t cs_is_zero = cpu_ctx->regs.cs_hidden.base ? 0 : HFLG_CS_IS_ZERO;
		cpu_ctx->hflags = cs_is_zero | (cpu_ctx->hflags & ~HFLG_CS_IS_ZERO);
	}

	cpu_ctx->exp_info.old_exp = EXP_INVALID;
	if (idx == EXP_DB) {
		cpu_ctx->regs.dr[7] &= ~DR7_GD_MASK;
	}

	// Need to push a valid entry to the rsb, to avoid a misprediction at every exception
	rsb_push(cpu_ctx, nullptr, 0, cs_base + eip);

	return nullptr;
}

addr_t
get_pc(cpu_ctx_t *cpu_ctx)
{
	return cpu_ctx->regs.cs_hidden.base + cpu_ctx->regs.eip;
}

translated_code_t::translated_code_t() noexcept
{
	cs_base = 0,
	pc = 0,
	virt_pc = 0;
	guest_flags = 0;
	ptr_exit = nullptr;
	flags = 0;
	size = 0;
}

static inline uint32_t
tc_hash(addr_t pc)
{
	return pc & (CODE_CACHE_MAX_SIZE - 1);
}

void
tc_unlink(cpu_t *cpu, addr_t virt_pc)
{
	if (auto it_map = cpu->jmp_page_map.find(virt_pc >> PAGE_SHIFT); it_map != cpu->jmp_page_map.end()) {
		if (auto it_set = it_map->second.find(virt_pc); it_set != it_map->second.end()) {
			it_map->second.erase(it_set);
			if (it_map->second.empty()) {
				cpu->jmp_page_map.erase(it_map);
			}
			uint32_t idx = virt_pc & JMP_TABLE_MASK;
			cpu->cpu_ctx.jmp_table[idx].guest_flags = HFLG_INVALID;
		}
	}
	rsb_flush(cpu, virt_pc);
}

void
tc_unlink_page(cpu_t *cpu, addr_t virt_pc)
{
	if (auto it_map = cpu->jmp_page_map.find(virt_pc >> PAGE_SHIFT); it_map != cpu->jmp_page_map.end()) {
		for (auto addr : it_map->second) {
			uint32_t idx = addr & JMP_TABLE_MASK;
			cpu->cpu_ctx.jmp_table[idx].guest_flags = HFLG_INVALID;
		}
		cpu->jmp_page_map.erase(it_map);
	}
	rsb_flush(cpu, virt_pc);
}

void
tc_unlink_all(cpu_t *cpu)
{
	cpu->jmp_page_map.clear();
	for (unsigned i = 0; i < JMP_TABLE_NUM_ELEMENTS; ++i) {
		cpu->cpu_ctx.jmp_table[i].guest_flags = HFLG_INVALID;
	}
	rsb_flush(cpu);
}

template<bool remove_hook>
void tc_invalidate(cpu_ctx_t *cpu_ctx, addr_t phys_addr, [[maybe_unused]] uint64_t size)
{
	bool halt_tc = false;

	// find all tc in the page phys_addr belongs to
	auto it_map = cpu_ctx->cpu->tc_page_map.find(phys_addr >> PAGE_SHIFT);
	if (it_map != cpu_ctx->cpu->tc_page_map.end()) {
		auto it_set = it_map->second.begin();
		uint32_t flags = (cpu_ctx->hflags & HFLG_CONST) | (cpu_ctx->regs.eflags & EFLAGS_CONST);
		std::vector<std::unordered_set<translated_code_t *>::iterator> tc_to_delete;
		// iterate over all tc's found in the page
		while (it_set != it_map->second.end()) {
			translated_code_t *tc_in_page = *it_set;
			// only invalidate the tc if phys_addr is included in the translated address range of the tc
			// hook tc have a zero guest code size, so they are unaffected by guest writes and do not need to be considered by tc_invalidate
			bool remove_tc;
			if constexpr (remove_hook) {
				remove_tc = !tc_in_page->size && (tc_in_page->pc == phys_addr);
			}
			else {
				remove_tc = tc_in_page->size && !(std::min(phys_addr + size - 1, tc_in_page->pc + tc_in_page->size - 1) < std::max(phys_addr, tc_in_page->pc));
			}

			if (remove_tc) {
				// unlink this tc from the others
				tc_unlink(cpu_ctx->cpu, tc_in_page->virt_pc);

				// delete the found tc from the code cache
				uint32_t idx = tc_hash(tc_in_page->pc);
				auto it = cpu_ctx->cpu->code_cache[idx].begin();
				while (it != cpu_ctx->cpu->code_cache[idx].end()) {
					if (it->get() == tc_in_page) {
						try {
							if (it->get()->cs_base == cpu_ctx->regs.cs_hidden.base &&
								it->get()->pc == get_code_addr(cpu_ctx->cpu, get_pc(cpu_ctx)) &&
								it->get()->guest_flags == flags) {
								// worst case: the write overlaps with the tc we are currently executing
								halt_tc = true;
							}
						}
						catch (host_exp_t) {
							// the current tc cannot fault
							LIB86CPU_ABORT_msg("%s: unexpected page fault while touching address 0x%08X", __func__, get_pc(cpu_ctx));
						}
						cpu_ctx->cpu->code_cache[idx].erase(it);
						break;
					}
					++it;
				}

				// we can't delete the tc in tc_page_map right now because it would invalidate its iterator, which is still needed below
				tc_to_delete.push_back(it_set);

				if constexpr (remove_hook) {
					break;
				}
			}
			++it_set;
		}

		// delete the found tc from tc_page_map
		for (auto &it : tc_to_delete) {
			it_map->second.erase(it);
		}

		// if the tc_page_map for phys_addr is now empty, also clear the corresponding smc bit and its key in the map
		if (it_map->second.empty()) {
			cpu_ctx->cpu->smc.reset(phys_addr >> PAGE_SHIFT);
			cpu_ctx->cpu->tc_page_map.erase(it_map);
		}
	}

	if (halt_tc) {
		cpu_ctx->cpu->raise_int_fn(cpu_ctx, CPU_HALT_TC_INT);
	}
}

template void tc_invalidate<true>(cpu_ctx_t *cpu_ctx, addr_t phys_addr, [[maybe_unused]] uint64_t size);
template void tc_invalidate<false>(cpu_ctx_t *cpu_ctx, addr_t phys_addr, [[maybe_unused]] uint64_t size);

static translated_code_t *
tc_cache_search(cpu_t *cpu, addr_t pc)
{
	uint32_t flags = (cpu->cpu_ctx.hflags & HFLG_CONST) | (cpu->cpu_ctx.regs.eflags & EFLAGS_CONST);
	uint32_t idx = tc_hash(pc);
	auto it = cpu->code_cache[idx].begin();
	while (it != cpu->code_cache[idx].end()) {
		translated_code_t *tc = it->get();
		if (tc->cs_base == cpu->cpu_ctx.regs.cs_hidden.base &&
			tc->pc == pc &&
			tc->guest_flags == flags) {
			return tc;
		}
		it++;
	}

	return nullptr;
}

static void
tc_cache_insert(cpu_t *cpu, addr_t pc, std::unique_ptr<translated_code_t> &&tc)
{
	cpu->num_tc++;
	cpu->tc_page_map[pc >> PAGE_SHIFT].insert(tc.get());
	cpu->code_cache[tc_hash(pc)].push_front(std::move(tc));
}

void
tc_clear_cache_and_tlb(cpu_t *cpu)
{
	tc_cache_clear(cpu);
	tlb_flush_g(cpu);
}

void
tc_cache_clear(cpu_t *cpu)
{
	// Use this when you want to destroy all tc's but without affecting the actual code allocated. E.g: on x86-64, you'll want to keep the .pdata sections
	// when this is called from a function called from the JITed code, and the current function can potentially throw an exception
	cpu->tc_page_map.clear();
	cpu->smc.reset();
	for (auto &bucket : cpu->code_cache) {
		bucket.clear();
	}

	// Because all tc have been invalidated, we must unlink them all
	tc_unlink_all(cpu);
}

void
tc_cache_purge(cpu_t *cpu)
{
	// This is like tc_cache_clear, but it also frees all code allocated. E.g: on x86-64, the jit also emits .pdata sections that hold the exception tables
	// necessary to unwind the stack of the JITed functions
	tc_cache_clear(cpu);
	cpu->jit->destroy_all_code();
	cpu->num_tc = 0;
}

static void
tc_link_jmp(cpu_t *cpu, translated_code_t *ptr_tc)
{
	uint32_t idx = ptr_tc->virt_pc & JMP_TABLE_MASK;
	jmp_table_elem *elem = &cpu->cpu_ctx.jmp_table[idx];

	// If there is an existing entry in the table, we must flush it first before inserting the new entry
	if (!(elem->guest_flags & HFLG_INVALID)) {
		auto it_map = cpu->jmp_page_map.find(elem->virt_pc >> PAGE_SHIFT);
		assert(it_map != cpu->jmp_page_map.end());
		auto it_set = it_map->second.find(elem->virt_pc);
		assert(it_set != it_map->second.end());
		it_map->second.erase(it_set);
		if (it_map->second.empty()) {
			cpu->jmp_page_map.erase(it_map);
		}
	}

	elem->virt_pc = ptr_tc->virt_pc;
	elem->cs_base = ptr_tc->cs_base;
	elem->guest_flags = ptr_tc->guest_flags;
	elem->ptr_code = GET_PTR_CODE(ptr_tc->ptr_exit);
	cpu->jmp_page_map[ptr_tc->virt_pc >> PAGE_SHIFT].insert(ptr_tc->virt_pc);
}

static void
tc_link_prev(cpu_t *cpu, translated_code_t *prev_tc, translated_code_t *ptr_tc)
{
	// see if we can link the previous tc with the current one
	if (prev_tc) {
		switch (prev_tc->flags)
		{
		case TC_FLG_CALL: // this happens when a CALL is the very last instruction on a page boundary (that is, when DISAS_FLG_PAGE_CROSS_NEXT_INSTR is set). Alternatively, it can
			// also happen if block terminated with an instruction that never links to other blocks (INT3, HLT or MOV drN, reg)
		case TC_FLG_JMP: // standard case with a terminating jumping instruction
		case TC_FLG_CALL | TC_FLG_RET: // this happens when the terminating instruction after a CALL is a RET. Note that, if we are at the last RET and the rsb mispredicted, then
			// tc_link_jmp will cache an unnecessary ptr_tc->virt_pc in the jmp table, because rsb_pop was supposed to have handled it instead
		case TC_FLG_CALL | TC_FLG_JMP: // this happens when the terminating instruction after a CALL is any jumping instruction
			// link the current with the preceding block
			tc_link_jmp(cpu, ptr_tc);
			break;

		case TC_FLG_RET: // already handled by rsb_pop
			// don't link the blocks
			break;

		case 0: // same as TC_FLG_CALL, but without a CALL in the block. Note that this should never happen because in all cases, prev_tc is always set to nullptr
		default:
			LIB86CPU_ABORT_msg("prev_tc->flags was 0x%08" PRIx32, prev_tc->flags);
		}
	}
}

static void
cpu_translate(cpu_t *cpu)
{
	disas_ctx_t *disas_ctx = &cpu->disas_ctx;
	cpu->translate_next = 1;
	cpu->virt_pc = disas_ctx->virt_pc;

	decoded_instr instr;
	ZydisDecoder decoder;
	ZyanStatus status;

	init_instr_decoder(disas_ctx, &decoder);

	do {
		cpu->instr_eip = cpu->virt_pc - cpu->cpu_ctx.regs.cs_hidden.base;

		try {
			status = decode_instr(cpu, disas_ctx, &decoder, &instr);
		}
		catch ([[maybe_unused]] host_exp_t type) {
			// this happens on instr breakpoints (not int3)
			assert(type == host_exp_t::db_exp);
			cpu->jit->gen_raise_exp_inline(0, 0, EXP_DB);
			// Don't insert this code block in the cache, since it unconditionally invokes the exception handler for the breakpoint. Also, note that only
			// gen_tc_linking_jmp can set CPU_FORCE_INSERT, which we are not calling here, so we can be sure this block is never inserted
			cpu->disas_ctx.flags |= DISAS_INSTR_BREAKPOINT;
			return;
		}

		if (ZYAN_SUCCESS(status)) {
			// successfully decoded

			// NOTE: the second OR for disas_ctx->flags is to handle the edge case where the last byte of the current instructions ends exactly at a page boundary. In this case,
			// the current block can be added to the code cache (so DISAS_FLG_PAGE_CROSS should not be set), but the translation of this block must terminate now (so
			// DISAS_FLG_PAGE_CROSS_NEXT_INSTR should be set)
			cpu->instr_bytes = instr.i.length;
			disas_ctx->flags |= ((disas_ctx->virt_pc & ~PAGE_MASK) != ((disas_ctx->virt_pc + cpu->instr_bytes - 1) & ~PAGE_MASK)) << 2; // checks last byte of curr instr, DISAS_FLG_PAGE_CROSS
			disas_ctx->flags |= ((disas_ctx->virt_pc & ~PAGE_MASK) != ((disas_ctx->virt_pc + cpu->instr_bytes) & ~PAGE_MASK)) << 5; // check 1st byte of next instr, DISAS_FLG_PAGE_CROSS_NEXT_INSTR
			disas_ctx->pc += cpu->instr_bytes;
			disas_ctx->virt_pc += cpu->instr_bytes;

			// att syntax uses percentage symbols to designate the operands, which will cause an error/crash if we (or the client)
			// attempts to interpret them as conversion specifiers, so we pass the formatted instruction as an argument
			LOG(log_level::debug, "0x%08X  %s", disas_ctx->virt_pc - cpu->instr_bytes, instr_logfn(disas_ctx->virt_pc - cpu->instr_bytes, &instr).c_str());
		}
		else {
			// NOTE: if rf is set, then it means we are translating the instr that caused a breakpoint. However, the exp handler always clears rf on itw own,
			// which means we do not need to do it again here in the case the original instr raises another kind of exp
			switch (status)
			{
			case ZYDIS_STATUS_BAD_REGISTER:
			case ZYDIS_STATUS_ILLEGAL_LOCK:
			case ZYDIS_STATUS_DECODING_ERROR:
				// illegal and/or undefined instruction, or lock prefix used on an instruction which does not accept it or used as source operand,
				// or the instruction encodes a register that cannot be used (e.g. mov cs, edx)
				cpu->jit->gen_raise_exp_inline(0, 0, EXP_UD);
				return;

			case ZYDIS_STATUS_NO_MORE_DATA:
				// buffer < 15 bytes
				cpu->cpu_flags &= ~CPU_DISAS_ONE;
				if (disas_ctx->exp_data.idx == EXP_PF) {
					// buffer size reduced because of page fault on second page
					disas_ctx->flags |= DISAS_FLG_FETCH_FAULT;
					cpu->jit->gen_raise_exp_inline(disas_ctx->exp_data.fault_addr, disas_ctx->exp_data.code, disas_ctx->exp_data.idx);
					return;
				}
				else {
					// buffer size reduced because ram/rom region ended
					LIB86CPU_ABORT_msg("Attempted to execute code outside of ram/rom!");
				}

			case ZYDIS_STATUS_INSTRUCTION_TOO_LONG: {
				// instruction length > 15 bytes
				cpu->cpu_flags &= ~CPU_DISAS_ONE;
				volatile addr_t addr = get_code_addr<true>(cpu, disas_ctx->virt_pc + X86_MAX_INSTR_LENGTH, &disas_ctx->exp_data);
				if (disas_ctx->exp_data.idx == EXP_PF) {
					disas_ctx->flags |= DISAS_FLG_FETCH_FAULT;
					cpu->jit->gen_raise_exp_inline(disas_ctx->exp_data.fault_addr, disas_ctx->exp_data.code, disas_ctx->exp_data.idx);
				}
				else {
					cpu->jit->gen_raise_exp_inline(0, 0, EXP_GP);
				}
				return;
			}

			default:
				LIB86CPU_ABORT_msg("Unhandled zydis decode return status");
			}
		}


		if ((disas_ctx->flags & DISAS_FLG_CS32) ^ ((instr.i.attributes & ZYDIS_ATTRIB_HAS_OPERANDSIZE) >> 43)) {
			cpu->size_mode = SIZE32;
		}
		else {
			cpu->size_mode = SIZE16;
		}

		if ((disas_ctx->flags & DISAS_FLG_CS32) ^ ((instr.i.attributes & ZYDIS_ATTRIB_HAS_ADDRESSSIZE) >> 44)) {
			cpu->addr_mode = ADDR32;
		}
		else {
			cpu->addr_mode = ADDR16;
		}

		uint16_t idx = s_zydis2idx_table[instr.i.mnemonic];
		ASSUME(idx < instr_table_size);
		instr_func func = s_instr_table[idx];
		ASSUME(func);
		(cpu->jit.get()->*func)(&instr);

		cpu->virt_pc += cpu->instr_bytes;
		cpu->tc->size += cpu->instr_bytes;

		// Only generate an interrupt check if the current instruction didn't terminate this tc. Terminating instructions already check for interrupts
		if ((cpu->translate_next == 1) && (func != &lc86_jit::CALL_)) {
			cpu->jit->update_eip();
			if ((disas_ctx->flags & (DISAS_FLG_PAGE_CROSS | DISAS_FLG_ONE_INSTR | DISAS_FLG_PAGE_CROSS_NEXT_INSTR)) == 0) {
				cpu->jit->gen_interrupt_check();
			}
		}

	} while ((cpu->translate_next | (disas_ctx->flags & (DISAS_FLG_PAGE_CROSS | DISAS_FLG_ONE_INSTR | DISAS_FLG_PAGE_CROSS_NEXT_INSTR))) == 1);
}

uint32_t
cpu_do_int(cpu_ctx_t *cpu_ctx, uint32_t int_flg)
{
	if (int_flg & CPU_ABORT_INT) {
		// this also happens when the user closes the debugger window
		cpu_ctx->cpu->clear_int_fn(cpu_ctx, CPU_ABORT_INT);
		throw lc86_exp_abort("Received abort signal, terminating the emulation", lc86_status::success);
	}

	if (int_flg & CPU_NON_HW_INT) {
		cpu_t *cpu = cpu_ctx->cpu;
		uint32_t int_clear_flg = CPU_MASKED_INT | CPU_HALT_TC_INT;
		if (int_flg & CPU_DBG_TRAP_INT) {
			int_clear_flg |= CPU_DBG_TRAP_INT;
			if (cpu_ctx->exp_info.exp_data.idx != EXP_DB) {
				// This happens when another exception is generated by the instruction after a debug trap exception was detected by a memory handler. In this case, the debug exception
				// is dismissed and only the other exception is delivered. Tested on xbox
				LOG(log_level::debug, "Dismissing debug trap exception");
			}
			else {
				cpu_raise_exception<false, false>(cpu_ctx);
			}
		}

		if (int_flg & CPU_HANDLER_INT) {
			int_clear_flg |= CPU_HANDLER_INT;
			std::for_each(cpu->regions_updated.begin(), cpu->regions_updated.end(), [cpu](const auto &data) {
				if (data.io_space) {
					auto io = const_cast<memory_region_t<port_t> *>(cpu->io_space_tree->search(data.start));
					if (io->type == mem_type::pmio) {
						io->handlers = data.handlers;
						io->opaque = data.opaque;
					}
				}
				else {
					auto mmio = const_cast<memory_region_t<addr_t> *>(cpu->memory_space_tree->search(data.start));
					if (mmio->type == mem_type::mmio) {
						mmio->handlers = data.handlers;
						mmio->opaque = data.opaque;
					}
				}
				});
			cpu->regions_updated.clear();
		}

		if (int_flg & CPU_A20_INT) {
			int_clear_flg |= CPU_A20_INT;
			cpu->a20_mask = cpu->new_a20;
			tc_clear_cache_and_tlb(cpu);
			if (int_flg & CPU_REGION_INT) {
				// the a20 interrupt has already flushed the tlb and the code cache, so just update the as object
				int_clear_flg |= CPU_REGION_INT;
				std::for_each(cpu->regions_changed.begin(), cpu->regions_changed.end(), [cpu](auto &pair) {
					if (pair.first) {
						cpu->memory_space_tree->insert(std::move(pair.second));
					}
					else {
						cpu->memory_space_tree->erase(pair.second->start, pair.second->end);
					}
					});
				cpu->regions_changed.clear();
			}
		}
		else if (int_flg & CPU_REGION_INT) {
			int_clear_flg |= CPU_REGION_INT;
			std::for_each(cpu->regions_changed.begin(), cpu->regions_changed.end(), [cpu](auto &pair) {
				addr_t start = pair.second->start, end = pair.second->end;
				if (pair.first) {
					cpu->memory_space_tree->insert(std::move(pair.second));
				}
				else {
					cpu->memory_space_tree->erase(start, end);
				}
			});
			tc_clear_cache_and_tlb(cpu);
			cpu->regions_changed.clear();
		}

		if (int_flg & CPU_SUSPEND_INT) {
			int_clear_flg |= CPU_SUSPEND_INT;
			cpu_ctx->cpu->is_suspended.test_and_set();
			if (cpu_ctx->cpu->suspend_should_throw.load() && cpu_ctx->cpu->suspend_flg.test()) {
				cpu_ctx->cpu->clear_int_fn(cpu_ctx, int_clear_flg);
				throw lc86_exp_abort("Received pause signal, suspending the emulation", lc86_status::paused);
			}
			else {
				cpu_ctx->cpu->suspend_flg.wait(true);
			}
			cpu_ctx->cpu->is_suspended.clear();
			if (cpu_ctx->cpu->state_loaded) {
				cpu_ctx->cpu->state_loaded = false;
			}
		}

		cpu_ctx->cpu->clear_int_fn(cpu_ctx, int_clear_flg);
		return CPU_NON_HW_INT;
	}

	if (((int_flg & CPU_HW_INT) | (cpu_ctx->regs.eflags & IF_MASK)) == (IF_MASK | CPU_HW_INT)) {
		cpu_ctx->exp_info.exp_data.fault_addr = 0;
		cpu_ctx->exp_info.exp_data.code = 0;
		cpu_ctx->exp_info.exp_data.idx = cpu_ctx->cpu->int_data.first(cpu_ctx->cpu->int_data.second);
		cpu_raise_exception<false, true>(cpu_ctx);
		return CPU_HW_INT;
	}

	return CPU_NO_INT;
}

// forward declare for cpu_main_loop
translated_code_t *tc_run_code(cpu_ctx_t *cpu_ctx, translated_code_t *tc);

template<bool is_tramp>
void cpu_suppress_trampolines(cpu_t *cpu)
{
	if constexpr (is_tramp) {
		// we need to remove the HFLG_TRAMP after we have searched the tc cache, but before executing the guest code, so that successive tc's
		// can still call hooks, if the trampolined function happens to make calls to other hooked functions internally
		cpu->cpu_ctx.hflags &= ~HFLG_TRAMP;
	}
}

template<bool is_tramp, typename T>
void cpu_main_loop(cpu_t *cpu, T &&lambda)
{
	translated_code_t *prev_tc = nullptr, *ptr_tc = nullptr;
	addr_t virt_pc, pc;

	// main cpu loop
	while (lambda()) {

		retry:
		try {
			virt_pc = get_pc(&cpu->cpu_ctx);
			cpu_check_data_watchpoints(cpu, virt_pc, 1, DR7_TYPE_INSTR);
			pc = get_code_addr(cpu, virt_pc);
		}
		catch ([[maybe_unused]] host_exp_t type) {
			assert((type == host_exp_t::pf_exp) || (type == host_exp_t::db_exp));
			cpu_suppress_trampolines<is_tramp>(cpu);

			// this is either a page fault or a debug exception. In both cases, we have to call the exception handler
			retry_exp:
			try {
				// the exception handler always returns nullptr
				prev_tc = cpu_raise_exception(&cpu->cpu_ctx);
			}
			catch ([[maybe_unused]] host_exp_t type) {
				assert((type == host_exp_t::pf_exp) || (type == host_exp_t::db_exp));

				// page fault or debug exception while delivering another exception
				goto retry_exp;
			}

			goto retry;
		}

		ptr_tc = tc_cache_search(cpu, pc);

		if (ptr_tc == nullptr) {

			// code block for this pc not present, we need to translate new code
			std::unique_ptr<translated_code_t> tc(new translated_code_t());

			cpu->tc = tc.get();
			cpu->jit->gen_tc_prologue();

			// prepare the disas ctx
			cpu->disas_ctx.flags = ((cpu->cpu_ctx.hflags & HFLG_CS32) >> CS32_SHIFT) |
				((cpu->cpu_ctx.hflags & HFLG_SS32) >> (SS32_SHIFT - 1)) |
				(cpu->cpu_ctx.hflags & HFLG_PE_MODE) |
				(cpu->cpu_flags & CPU_DISAS_ONE) |
				((cpu->cpu_flags & CPU_SINGLE_STEP) >> 3) |
				((cpu->cpu_ctx.regs.eflags & RF_MASK) >> 9) | // if rf is set, we need to clear it after the first instr executed
				((cpu->cpu_ctx.regs.eflags & TF_MASK) >> 1); // if tf is set, we need to raise a DB exp after every instruction
			cpu->disas_ctx.virt_pc = virt_pc;
			cpu->disas_ctx.pc = pc;

			cpu->tc->pc = pc;
			cpu->tc->virt_pc = virt_pc;
			cpu->tc->cs_base = cpu->cpu_ctx.regs.cs_hidden.base;
			cpu->tc->guest_flags = (cpu->cpu_ctx.hflags & HFLG_CONST) | (cpu->cpu_ctx.regs.eflags & EFLAGS_CONST);
			ptr_tc = cpu->tc;

			const auto it = cpu->hook_map.find(cpu->disas_ctx.virt_pc);
			bool take_hook;
			if constexpr (is_tramp) {
				take_hook = (it != cpu->hook_map.end()) && !(cpu->cpu_ctx.hflags & HFLG_TRAMP);
			}
			else {
				take_hook = it != cpu->hook_map.end();
			}

			if (take_hook) {
				cpu->jit->gen_hook(it->second);
			}
			else {
				// start guest code translation
				cpu_translate(cpu);
			}

			cpu->jit->gen_tc_epilogue();

			if (cpu->num_tc == CODE_CACHE_MAX_SIZE) {
				tc_cache_purge(cpu);
				prev_tc = nullptr;
			}
			cpu->jit->gen_code_block();

			if (cpu->disas_ctx.flags & (DISAS_FLG_PAGE_CROSS | DISAS_FLG_ONE_INSTR)) {
				cpu_suppress_trampolines<is_tramp>(cpu);
				cpu->cpu_flags &= ~CPU_DISAS_ONE;
				tc_run_code(&cpu->cpu_ctx, ptr_tc);
				if (ptr_tc->flags & TC_FLG_CALL) {
					// the rsb might have cached the return value that would point to this tc that we are going to delete now, so flush it out
					rsb_flush(cpu, ptr_tc->virt_pc);
				}
				cpu->jit->free_code_block(reinterpret_cast<void *>(ptr_tc->ptr_exit));
				prev_tc = nullptr;
				continue;
			}
			else {
				tc_cache_insert(cpu, pc, std::move(tc));
			}
		}

		cpu_suppress_trampolines<is_tramp>(cpu);

		// see if we can link the previous tc with the current one
		tc_link_prev(cpu, prev_tc, ptr_tc);

		prev_tc = tc_run_code(&cpu->cpu_ctx, ptr_tc);
	}
}

translated_code_t *
tc_run_code(cpu_ctx_t *cpu_ctx, translated_code_t *tc)
{
	try {
		// run the translated code
#ifdef XBOX_CPU
		return ipt_run_guarded_code(cpu_ctx, tc);
#else
		return GET_PTR_CODE(tc->ptr_exit)(cpu_ctx);
#endif
	}
	catch (host_exp_t type) {
		switch (type)
		{
		case host_exp_t::pf_exp: {
			// page fault while executing the translated code
			retry_exp:
			try {
				// the exception handler always returns nullptr
				return cpu_raise_exception(cpu_ctx);
			}
			catch ([[maybe_unused]] host_exp_t type) {
				assert(type == host_exp_t::pf_exp);

				// page fault exception while delivering another exception
				goto retry_exp;
			}
		}
		break;

		case host_exp_t::db_exp:
			// because debug trap exceptions are handled at runtime with the debug interrupt, this cannot happen, so it must be a bug
			LIB86CPU_ABORT_msg("Unexpected debug trap exception while running code");
			break;

		default:
			LIB86CPU_ABORT_msg("Unknown host exception in %s", __func__);
		}
	}

	LIB86CPU_ABORT();
}

template<bool run_forever>
lc86_status cpu_start(cpu_t *cpu)
{
	if ((cpu->cpu_flags & (CPU_DBG_PRESENT | CPU_TIMEOUT)) == CPU_DBG_PRESENT) [[unlikely]] {
		// This check is necessary because the debugger will show disassembled instructions when first run, and HLT is translated differently depending on CPU_TIMEOUT
		if constexpr (run_forever == false) {
			cpu->cpu_flags |= CPU_TIMEOUT;
		}
		std::promise<bool> promise;
		std::future<bool> fut = promise.get_future();
		std::thread(dbg_main_wnd, cpu, std::ref(promise)).detach();
		bool has_err = fut.get();
		if (has_err) {
			return set_last_error(lc86_status::internal_error);
		}
		// wait until the debugger continues execution, so that users have a chance to set breakpoints and/or inspect the guest code
		g_guest_running.wait(false);
		dbg_apply_sw_breakpoints(cpu);
		dbg_apply_watchpoints(cpu);
	}

	if constexpr (run_forever == false) {
		cpu->cpu_flags |= CPU_TIMEOUT;
	}

	if (cpu->is_suspended.test()) {
		if (cpu->suspend_flg.test()) {
			return set_last_error(lc86_status::paused);
		}

		// suspend_flg was cleared by cpu_resume, so we can clear is_suspended too
		cpu->is_suspended.clear();
	}

	// NOTE: doesn't place this in cpu_main_loop to prevent the thread id from being overwritten when a trampoline is called
	cpu->cpu_thr_id = std::this_thread::get_id();

	try {
		if constexpr (run_forever) {
			cpu_main_loop<false>(cpu, []() { return true; });
		}
		else {
			cpu_timer_set_now(cpu);
			cpu->exit_requested = false;
			if (cpu->is_halted) {
				// if the cpu was previously halted, then we must keep waiting until the next hw int
				hlt_helper<true>(&cpu->cpu_ctx);
				if (cpu->is_halted) {
					// if it is still halted, then it must be a timeout
					return set_last_error(lc86_status::timeout);
				}
			}
			cpu_main_loop<false>(cpu, [cpu]() { return !cpu->exit_requested; });
			cpu->cpu_thr_id = std::thread::id();
			return set_last_error(lc86_status::timeout);
		}
	}
	catch (lc86_exp_abort &exp) {
		if (cpu->cpu_flags & CPU_DBG_PRESENT) {
			dbg_should_close();
		}

		cpu->cpu_thr_id = std::thread::id();
		last_error = exp.what();
		return exp.get_code();
	}

	assert(0);

	return set_last_error(lc86_status::internal_error);
}

void
cpu_exec_trampoline(cpu_t *cpu, const uint32_t ret_eip)
{
	// set the trampoline flag, so that we can call the trampoline tc instead of the hook tc
	cpu->cpu_ctx.hflags |= HFLG_TRAMP;
	cpu_main_loop<true>(cpu, [cpu, ret_eip]() { return cpu->cpu_ctx.regs.eip != ret_eip; });
}

void
dbg_exec_original_instr(cpu_t *cpu)
{
	cpu->cpu_flags |= CPU_DISAS_ONE;
	// run the main loop only once, since we only execute the original instr that was replaced by int3
	int i = 0;
	cpu_main_loop<false>(cpu, [&i]() { return i++ == 0; });
}

template JIT_API translated_code_t *cpu_raise_exception<0, true>(cpu_ctx_t *cpu_ctx);
template JIT_API translated_code_t *cpu_raise_exception<1, true>(cpu_ctx_t *cpu_ctx);
template JIT_API translated_code_t *cpu_raise_exception<2, true>(cpu_ctx_t *cpu_ctx);
template JIT_API translated_code_t *cpu_raise_exception<3, true>(cpu_ctx_t *cpu_ctx);
template JIT_API translated_code_t *cpu_raise_exception<0, false>(cpu_ctx_t *cpu_ctx);
template JIT_API translated_code_t *cpu_raise_exception<1, false>(cpu_ctx_t *cpu_ctx);
template JIT_API translated_code_t *cpu_raise_exception<2, false>(cpu_ctx_t *cpu_ctx);
template JIT_API translated_code_t *cpu_raise_exception<3, false>(cpu_ctx_t *cpu_ctx);
template lc86_status cpu_start<true>(cpu_t *cpu);
template lc86_status cpu_start<false>(cpu_t *cpu);
