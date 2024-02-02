/*
 * x86-64 emitter
 *
 * ergo720                Copyright (c) 2022
 */

#include "jit.h"
#include "support.h"
#include "instructions.h"
#include "debugger.h"
#include "clock.h"
#include <assert.h>
#include <optional>

#ifdef LIB86CPU_X64_EMITTER

// The emitted code assumes that host pointers are 8 bytes
static_assert(sizeof(uint8_t *) == 8, "Pointers must be 8 bytes");
// This is assumed in mov dr/reg, reg/dr
static_assert(ZYDIS_REGISTER_DR0 - ZYDIS_REGISTER_DR0 == 0);
static_assert(ZYDIS_REGISTER_DR1 - ZYDIS_REGISTER_DR0 == 1);
static_assert(ZYDIS_REGISTER_DR2 - ZYDIS_REGISTER_DR0 == 2);
static_assert(ZYDIS_REGISTER_DR3 - ZYDIS_REGISTER_DR0 == 3);
static_assert(ZYDIS_REGISTER_DR4 - ZYDIS_REGISTER_DR0 == 4);
static_assert(ZYDIS_REGISTER_DR5 - ZYDIS_REGISTER_DR0 == 5);
static_assert(ZYDIS_REGISTER_DR6 - ZYDIS_REGISTER_DR0 == 6);
static_assert(ZYDIS_REGISTER_DR7 - ZYDIS_REGISTER_DR0 == 7);

// all regs available on x64
#define AH x86::ah
#define CH x86::ch
#define DH x86::dh
#define BH x86::bh
#define AL x86::al
#define CL x86::cl
#define DL x86::dl
#define BL x86::bl
#define AX x86::ax
#define CX x86::cx
#define DX x86::dx
#define BX x86::bx
#define SP x86::sp
#define BP x86::bp
#define SI x86::si
#define DI x86::di
#define EAX x86::eax
#define ECX x86::ecx
#define EDX x86::edx
#define EBX x86::ebx
#define ESP x86::esp
#define EBP x86::ebp
#define ESI x86::esi
#define EDI x86::edi
#define RAX x86::rax
#define RCX x86::rcx
#define RDX x86::rdx
#define RBX x86::rbx
#define RSP x86::rsp
#define RBP x86::rbp
#define RSI x86::rsi
#define RDI x86::rdi
#define R8B  x86::r8b
#define R9B  x86::r9b
#define R10B x86::r10b
#define R11B x86::r11b
#define R12B x86::r12b
#define R13B x86::r13b
#define R14B x86::r14b
#define R15B x86::r15b
#define R8W  x86::r8w
#define R9W  x86::r9w
#define R10W x86::r10w
#define R11W x86::r11w
#define R12W x86::r12w
#define R13W x86::r13w
#define R14W x86::r14w
#define R15W x86::r15w
#define R8D  x86::r8d
#define R9D  x86::r9d
#define R10D x86::r10d
#define R11D x86::r11d
#define R12D x86::r12d
#define R13D x86::r13d
#define R14D x86::r14d
#define R15D x86::r15d
#define R8  x86::r8
#define R9  x86::r9
#define R10 x86::r10
#define R11 x86::r11
#define R12 x86::r12
#define R13 x86::r13
#define R14 x86::r14
#define R15 x86::r15
#define XMM0 x86::xmm0
#define XMM1 x86::xmm1
#define XMM2 x86::xmm2
#define XMM3 x86::xmm3
#define XMM4 x86::xmm4
#define XMM5 x86::xmm5
#define XMM6 x86::xmm6
#define XMM7 x86::xmm7

#define RCX_HOME_off 8  // skip ret rip that was pushed on the stack by the caller
#define RDX_HOME_off 16
#define R8_HOME_off  24
#define R9_HOME_off  32

#define JIT_LOCAL_VARS_STACK_SIZE  0x30 // must be a multiple of 16
#define JIT_REG_ARGS_STACK_SIZE    0x20

// all x64 regs that can actually be used in the main jitted function
enum class x64 : uint32_t {
	rax = 0,
	rbx,
	rcx,
	rdx,
	r8,
	r9,
	r10,
	r11,
	max = r11,
};

constexpr x64
operator|(x64 reg, uint32_t size)
{
	return static_cast<x64>(static_cast<uint32_t>(reg) | (size << static_cast<uint32_t>(x64::max)));
}

static const std::unordered_map<x64, x86::Gp> reg_to_sized_reg = {
	{ x64::rax | SIZE8,   AL   },
	{ x64::rax | SIZE16,  AX   },
	{ x64::rax | SIZE32,  EAX  },
	{ x64::rbx | SIZE8,   BL   },
	{ x64::rbx | SIZE16,  BX   },
	{ x64::rbx | SIZE32,  EBX  },
	{ x64::rcx | SIZE8,   CL   },
	{ x64::rcx | SIZE16,  CX   },
	{ x64::rcx | SIZE32,  ECX  },
	{ x64::rdx | SIZE8,   DL   },
	{ x64::rdx | SIZE16,  DX   },
	{ x64::rdx | SIZE32,  EDX  },
	{ x64::r8  | SIZE8,   R8B  },
	{ x64::r8  | SIZE16,  R8W  },
	{ x64::r8  | SIZE32,  R8D  },
	{ x64::r9  | SIZE8,   R9B  },
	{ x64::r9  | SIZE16,  R9W  },
	{ x64::r9  | SIZE32,  R9D  },
	{ x64::r10 | SIZE8,   R10B },
	{ x64::r10 | SIZE16,  R10W },
	{ x64::r10 | SIZE32,  R10D },
	{ x64::r11 | SIZE8,   R11B },
	{ x64::r11 | SIZE16,  R11W },
	{ x64::r11 | SIZE32,  R11D },
};

// The following calculates how much stack is needed to hold the stack arguments for any callable function from the jitted code. This value is then
// increased of a fixed amount to hold the stack local variables of the main jitted function and the register args of the callees
// NOTE1: the jitted main() and exit() are also called during code linking, but those only use register args
// NOTE2: this assumes the Windows x64 calling convention

template<typename R, typename... Args>
consteval std::integral_constant<size_t, sizeof...(Args)>
get_arg_count(R(JIT_API *f)(Args...))
{
	return std::integral_constant<size_t, sizeof...(Args)>{};
}

template<size_t idx>
consteval size_t
max_stack_required_for_func()
{
	if constexpr (constexpr size_t num_args = decltype(get_arg_count(std::get<idx>(all_callable_funcs)))::value; num_args > 4) {
		return (num_args - 4) * 8;
	}

	return 0;
}

template<size_t idx>
struct max_stack_required
{
	static constexpr size_t stack = std::max(max_stack_required<idx - 1>::stack, max_stack_required_for_func<idx>());
};

template<>
struct max_stack_required<0>
{
	static constexpr size_t stack = max_stack_required_for_func<0>();
};

consteval size_t
get_tot_args_stack_required()
{
	// on WIN64, the stack is 16 byte aligned
	return (max_stack_required<std::tuple_size_v<decltype(all_callable_funcs)> - 1>::stack + 15) & ~15;
}

constexpr size_t local_vars_size = JIT_LOCAL_VARS_STACK_SIZE;
constexpr size_t reg_args_size = JIT_REG_ARGS_STACK_SIZE;
constexpr size_t stack_args_size = get_tot_args_stack_required();
constexpr size_t tot_arg_size = stack_args_size + reg_args_size + local_vars_size;

size_t
get_jit_stack_required_runtime()
{
	// runtime version used by x64_exceptions.cpp
	return tot_arg_size;
}
static constexpr size_t
get_jit_stack_required()
{
	return tot_arg_size;
}

static constexpr size_t
get_jit_reg_args_size()
{
	return reg_args_size;
}

static constexpr size_t
get_jit_stack_args_size()
{
	return stack_args_size;
}

static constexpr size_t
get_jit_local_vars_size()
{
	return local_vars_size;
}

// calculates a stack offset at runtime
static size_t
get_local_var_offset(size_t idx)
{
	if (idx > (get_jit_local_vars_size() / 8 - 1)) {
		LIB86CPU_ABORT_msg("Attempted to use a local variable for which not enough stack was allocated for");
	}
	else {
		return idx * 8 + get_jit_reg_args_size() + get_jit_stack_args_size();
	}
}

// calculates a stack offset at compile time
template<size_t idx>
static constexpr size_t
get_local_var_offset()
{
	if (idx > (get_jit_local_vars_size() / 8 - 1)) {
		throw std::logic_error("Attempted to use a local variable for which not enough stack was allocated for");
	}
	else {
		return idx * 8 + get_jit_reg_args_size() + get_jit_stack_args_size();
	}
}

template<x86::Gp reg>
constexpr size_t
get_reg_arg_offset()
{
	// this adds get_jit_stack_required() to revert SUB(RSP, get_jit_stack_required()), then adds 8 to revert PUSH(RBX)

	if (reg == RCX) {
		return get_jit_stack_required() + 8 + RCX_HOME_off;
	}
	else if (reg == RDX) {
		return get_jit_stack_required() + 8 + RDX_HOME_off;
	}
	else if (reg == R8) {
		return get_jit_stack_required() + 8 + R8_HOME_off;
	}
	else if (reg == R9) {
		return get_jit_stack_required() + 8 + R9_HOME_off;
	}
	else {
		LIB86CPU_ABORT_msg("Unknown register specified in %s", __func__);
	}
}

#define LOCAL_VARS_off(idx) get_local_var_offset<idx>()
#define STACK_ARGS_off get_jit_reg_args_size()
#define REG_ARG_off(reg) get_reg_arg_offset<reg>()

static_assert((LOCAL_VARS_off(0) & 15) == 0); // must be 16 byte aligned so that sse can work on it in lc86_jit::load_mem

// [reg]
#define MEM8(reg)  x86::byte_ptr(reg)
#define MEM16(reg) x86::word_ptr(reg)
#define MEM32(reg) x86::dword_ptr(reg)
#define MEM64(reg) x86::qword_ptr(reg)
#define MEM128(reg) x86::xmmword_ptr(reg)
#define MEM(reg, size) x86::Mem(reg, size)
// [reg + disp]
#define MEMD8(reg, disp)  x86::byte_ptr(reg, disp)
#define MEMD16(reg, disp) x86::word_ptr(reg, disp)
#define MEMD32(reg, disp) x86::dword_ptr(reg, disp)
#define MEMD64(reg, disp) x86::qword_ptr(reg, disp)
#define MEMD80(reg, disp) x86::tword_ptr(reg, disp)
#define MEMD128(reg, disp) x86::xmmword_ptr(reg, disp)
#define MEMD(reg, disp, size) x86::Mem(reg, disp, size)
// [reg + idx * scale], scale specified as 1 << n; e.g. scale = 8 -> n = 3
#define MEMS8(reg, idx, scale)  x86::byte_ptr(reg, idx, scale)
#define MEMS16(reg, idx, scale) x86::word_ptr(reg, idx, scale)
#define MEMS32(reg, idx, scale) x86::dword_ptr(reg, idx, scale)
#define MEMS64(reg, idx, scale) x86::qword_ptr(reg, idx, scale)
#define MEMS(reg, idx, scale, size) x86::Mem(reg, idx, scale, size)
// [idx * scale + disp], scale specified as 1 << n; e.g. scale = 8 -> n = 3
#define MEMSb8(idx, scale, disp)  x86::byte_ptr(disp, idx, scale)
#define MEMSb16(idx, scale, disp) x86::word_ptr(disp, idx, scale)
#define MEMSb32(idx, scale, disp) x86::dword_ptr(disp, idx, scale)
#define MEMSb64(idx, scale, disp) x86::qword_ptr(disp, idx, scale)
#define MEMSb(idx, scale, disp, size) x86::Mem(disp, idx, scale, size)
// [reg + idx * scale + disp], scale specified as 1 << n; e.g. scale = 8 -> n = 3
#define MEMSD8(reg, idx, scale, disp)  x86::byte_ptr(reg, idx, scale, disp)
#define MEMSD16(reg, idx, scale, disp) x86::word_ptr(reg, idx, scale, disp)
#define MEMSD32(reg, idx, scale, disp) x86::dword_ptr(reg, idx, scale, disp)
#define MEMSD64(reg, idx, scale, disp) x86::qword_ptr(reg, idx, scale, disp)
#define MEMSD80(reg, idx, scale, disp) x86::tword_ptr(reg, idx, scale, disp)
#define MEMSD(reg, idx, scale, disp, size) x86::Mem(reg, idx, scale, disp, size)

#define MOV(dst, src) m_a.mov(dst, src)
#define MOVZX(dst, src) m_a.movzx(dst, src)
#define MOVSX(dst, src) m_a.movsx(dst, src)
#define MOVSXD(dst, src) m_a.movsxd(dst, src)
#define LEA(dst, src) m_a.lea(dst, src)
#define AND(dst, src) m_a.and_(dst, src)
#define OR(dst, src) m_a.or_(dst, src)
#define XOR(dst, src) m_a.xor_(dst, src)
#define SHL(dst, src) m_a.shl(dst, src)
#define SHR(dst, src) m_a.shr(dst, src)
#define SAR(dst, src) m_a.sar(dst, src)
#define SHLD(dst, src, third) m_a.shld(dst, src, third)
#define SHRD(dst, src, third) m_a.shrd(dst, src, third)
#define RCL(dst, src) m_a.rcl(dst, src)
#define RCR(dst, src) m_a.rcr(dst, src)
#define ROL(dst, src) m_a.rol(dst, src)
#define ROR(dst, src) m_a.ror(dst, src)
#define NEG(dst) m_a.neg(dst)
#define NOT(dst) m_a.not_(dst)
#define BSF(dst, src) m_a.bsf(dst, src)
#define BSR(dst, src) m_a.bsr(dst, src)
#define BSWAP(dst) m_a.bswap(dst)
#define BT(dst, src) m_a.bt(dst, src)
#define BTC(dst, src) m_a.btc(dst, src)
#define BTR(dst, src) m_a.btr(dst, src)
#define BTS(dst, src) m_a.bts(dst, src)
#define TEST(dst, src) m_a.test(dst, src)
#define ADD(dst, src) m_a.add(dst, src)
#define SUB(dst, src) m_a.sub(dst, src)
#define DEC(dst) m_a.dec(dst)
#define CMP(dst, src) m_a.cmp(dst, src)
#define MUL(op) m_a.mul(op)
#define IMUL1(op) m_a.imul(op)
#define IMUL2(dst, src) m_a.imul(dst, src)
#define IMUL3(dst, src, imm) m_a.imul(dst, src, imm)
#define DIV(op) m_a.div(op)
#define IDIV(op) m_a.idiv(op)
#define XCHG(dst, src) m_a.xchg(dst, src);
#define CLC() m_a.clc()
#define STC() m_a.stc()
#define CALL(addr) m_a.call(addr)
#define RET() m_a.ret()
#define PUSH(dst) m_a.push(dst)
#define POP(dst) m_a.pop(dst)
#define INT3() m_a.int3()
#define PAUSE() m_a.pause()

#define BR_UNCOND(dst) m_a.jmp(dst)
#define BR_EQ(label) m_a.je(label)
#define BR_NE(label) m_a.jne(label)
#define BR_UGT(label) m_a.ja(label)
#define BR_UGE(label) m_a.jae(label)
#define BR_ULT(label) m_a.jb(label)
#define BR_ULE(label) m_a.jbe(label)
#define BR_SGT(label) m_a.jg(label)
#define BR_SGE(label) m_a.jge(label)
#define BR_SLT(label) m_a.jl(label)
#define BR_SLE(label) m_a.jle(label)

#define SETC(dst) m_a.setc(dst)
#define SETO(dst) m_a.seto(dst)
#define SETNZ(dst) m_a.setnz(dst)
#define SET_EQ(dst) m_a.sete(dst)
#define SET_NE(dst) m_a.setne(dst)
#define SET_SGT(dst) m_a.setg(dst)
#define SET_SLT(dst) m_a.setl(dst)

#define CMOV_EQ(dst, src) m_a.cmove(dst, src)
#define CMOV_NE(dst, src) m_a.cmovne(dst, src)

#define EMMS() m_a.emms()
#define FLDCW(src) m_a.fldcw(src)
#define FNSTCW(dst) m_a.fnstcw(dst)
#define FNSTSW(dst) m_a.fnstsw(dst)
#define FNCLEX() m_a.fnclex()
#define FLD(src) m_a.fld(src)
#define FSTP(dst) m_a.fstp(dst)

#define MOVAPS(dst, src) m_a.movaps(dst, src)
#define XORPS(dst, src) m_a.xorps(dst, src)

#define LD_R8L(dst, reg_offset) MOV(dst, MEMD8(RCX, reg_offset))
#define LD_R8H(dst, reg_offset) MOV(dst, MEMD8(RCX, reg_offset + 1))
#define LD_R16(dst, reg_offset) MOV(dst, MEMD16(RCX, reg_offset))
#define LD_R32(dst, reg_offset) MOV(dst, MEMD32(RCX, reg_offset))
#define LD_REG_val(dst, reg_offset, size) load_reg(dst, reg_offset, size)
#define LD_SEG(dst, seg_offset) MOV(dst, MEMD16(RCX, seg_offset))
#define LD_SEG_BASE(dst, seg_offset) MOV(dst, MEMD32(RCX, seg_offset + seg_base_offset))
#define LD_SEG_LIMIT(dst, seg_offset) MOV(dst, MEMD32(RCX, seg_offset + seg_limit_offset))
#define ST_R8L(reg_offset, src) MOV(MEMD8(RCX, reg_offset), src)
#define ST_R8H(reg_offset, src) MOV(MEMD8(RCX, reg_offset + 1), src)
#define ST_R16(reg_offset, src) MOV(MEMD16(RCX, reg_offset), src)
#define ST_R32(reg_offset, src) MOV(MEMD32(RCX, reg_offset), src)
#define ST_REG_val(val, reg_offset, size) store_reg(val, reg_offset, size)
#define ST_SEG(seg_offset, val) MOV(MEMD16(RCX, seg_offset), val)
#define ST_SEG_BASE(seg_offset, val) MOV(MEMD32(RCX, seg_offset + seg_base_offset), val)
#define ST_SEG_LIMIT(seg_offset, val) MOV(MEMD32(RCX, seg_offset + seg_limit_offset), val)

#define LD_MEM() load_mem(m_cpu->size_mode, 0)
#define LD_MEMs(size) load_mem(size, 0)
#define LD_MEM80(idx) load_mem(SIZE80, 0)
#define LD_MEM128() load_mem(SIZE128, 0)
#define ST_MEM(val) store_mem(val, m_cpu->size_mode, 0)
#define ST_MEMs(val, size) store_mem(val, size, 0)
#define ST_MEM128(val) store_mem(val, SIZE128, 0)
#define ST_MEMv(val) store_mem<decltype(val), true>(val, m_cpu->size_mode, 0)

#define LD_IO() load_io(m_cpu->size_mode)
#define ST_IO() store_io(m_cpu->size_mode)

#define LD_CF(dst) MOV(dst, MEMD32(RCX, CPU_CTX_EFLAGS_AUX)); AND(dst, 0x80000000)
#define LD_OF(dst, aux) ld_of(dst, aux)
#define LD_ZF(dst) MOV(dst, MEMD32(RCX, CPU_CTX_EFLAGS_RES))
#define LD_SF(res_dst, aux) ld_sf(res_dst, aux)
#define LD_PF(dst, res, aux) ld_pf(dst, res, aux)
#define LD_AF(dst) MOV(dst, MEMD32(RCX, CPU_CTX_EFLAGS_AUX)); AND(dst, 8)

#define RAISEin_no_param_t() gen_raise_exp_inline<true>()
#define RAISEin_no_param_f() gen_raise_exp_inline<false>()
#define RAISEin_t(addr, code, idx, eip) gen_raise_exp_inline<true>(addr, code, idx, eip)
#define RAISEin_f(addr, code, idx, eip) gen_raise_exp_inline<false>(addr, code, idx, eip)
#define RAISEin0_t(idx) gen_raise_exp_inline<true>(0, 0, idx, m_cpu->instr_eip)
#define RAISEin0_f(idx) gen_raise_exp_inline<false>(0, 0, idx, m_cpu->instr_eip)

#define SIZED_REG(reg, size) reg_to_sized_reg.find(reg | size)->second
#define GET_REG(op) get_register_op(instr, op)
#define GET_OP(op) get_operand(instr, op)
#define GET_IMM() get_immediate_op(instr, OPNUM_SRC)

#define IS_PE() (m_cpu->cpu_ctx.hflags & HFLG_PE_MODE)
#define IS_VM86() (m_cpu->cpu_ctx.regs.eflags & VM_MASK)
#define IS_PE_NOT_VM86() (IS_PE() | IS_VM86()) == HFLG_PE_MODE

#define RELOAD_RCX_CTX() MOV(RCX, &m_cpu->cpu_ctx)
#define RESTORE_FPU_CTX() FLDCW(MEMD16(RSP, LOCAL_VARS_off(5)))
#define CALL_F(func) MOV(RAX, func); CALL(RAX); RELOAD_RCX_CTX()

#define CALL_FPU_SET_CTX() MOV(RAX, m_cpu->set_host_fpu_ctx_fn); CALL(RAX)
#define CALL_FPU_EXP_CHK() MOV(RAX, m_cpu->fpu_exp_post_check_fn); CALL(RAX)
#define CALL_FPU_STACK_CHK(is_push, instr_ty) LEA(R8, MEMD64(RSP, LOCAL_VARS_off(0))); \
LEA(RDX, MEMD64(RSP, LOCAL_VARS_off(2))); \
CALL_F((&fpu_stack_check<is_push, instr_ty>)); \
MOV(EBX, EAX); \
MOV(R8D, MEMD32(RSP, LOCAL_VARS_off(2)));

lc86_jit::lc86_jit(cpu_t *cpu)
{
	m_cpu = cpu;
	_environment = Environment::host();
	_environment.setObjectFormat(ObjectFormat::kJIT);
	gen_aux_funcs();
}

void
lc86_jit::start_new_session()
{
	m_code.reset();
	m_code.init(_environment);
	m_code.attach(m_a.as<BaseEmitter>());
}

void
lc86_jit::gen_code_block()
{
	translated_code_t *tc = m_cpu->tc;

	if (auto err = m_code.flatten()) {
		std::string err_str("Asmjit failed at flatten() with the error ");
		err_str += DebugUtils::errorAsString(err);
		throw lc86_exp_abort(err_str, lc86_status::internal_error);
	}

	if (auto err = m_code.resolveUnresolvedLinks()) {
		std::string err_str("Asmjit failed at resolveUnresolvedLinks() with the error ");
		err_str += DebugUtils::errorAsString(err);
		throw lc86_exp_abort(err_str, lc86_status::internal_error);
	}

	size_t estimated_code_size = m_code.codeSize();
	if (estimated_code_size == 0) {
		throw lc86_exp_abort("The generated code has a zero size", lc86_status::internal_error);
	}

#if defined(_WIN64)
	// Increase estimated_code_size by 12 + 12, to accommodate the .pdata and .xdata sections required to unwind the function
	// when an exception is thrown. Note that the sections need to be DWORD aligned
	estimated_code_size += 24;
	estimated_code_size = (estimated_code_size + 3) & ~3;
#elif defined (__linux__)
	// Increase estimated_code_size by 24 + 40 + 4, to accommodate the .eh_frame section required to unwind the function
	// when an exception is thrown. Note that the section needs to be 8 byte aligned
	estimated_code_size += (24 + 40 + 4);
	estimated_code_size = (estimated_code_size + 7) & ~7;
#endif

	auto block = m_mem.allocate_sys_mem(estimated_code_size);
	if (auto err = m_code.relocateToBase(reinterpret_cast<uintptr_t>(block.addr))) {
		std::string err_str("Asmjit failed at relocateToBase() with the error ");
		err_str += DebugUtils::errorAsString(err);
		throw lc86_exp_abort(err_str, lc86_status::internal_error);
	}

	// NOTE: there should only be a single .text section
	assert(m_code.sectionCount() == 1);

	Section *section = m_code.textSection();
	size_t offset = static_cast<size_t>(section->offset()); // should be zero for the first section
	size_t buff_size = static_cast<size_t>(section->bufferSize());

	assert(offset + buff_size <= estimated_code_size);
	uint8_t *exit_offset = static_cast<uint8_t *>(block.addr) + offset;
	uint8_t *main_offset = exit_offset + 16;
	std::memcpy(exit_offset, section->data(), buff_size);

#if defined(_WIN64) || defined(__linux__)
	// According to asmjit's source code, the code size can decrease after the relocation above, so we need to query it again
	gen_exception_info(main_offset, m_code.codeSize() - 16);
#endif

	// This code block is complete, so protect and flush the instruction cache now
	m_mem.protect_sys_mem(block, MEM_READ | MEM_EXEC);

	tc->ptr_code = reinterpret_cast<entry_t>(main_offset);
	tc->jmp_offset[0] = tc->jmp_offset[1] = tc->jmp_offset[2] = reinterpret_cast<entry_t>(exit_offset);

	// we are done with code generation for this block, so we null the tc pointer to prevent accidental usage
	m_cpu->tc = nullptr;
}

void
lc86_jit::gen_aux_funcs()
{
	// These are leaf functions, so they don't need an exception table on WIN64

	start_new_session();

	// read int
	MOV(EAX, MEMD32(RCX, CPU_CTX_INT));
	RET();

	const auto &align_next_func_start = [this]() {
		size_t off = m_a.offset(), off_aligned16 = (off + 15) & ~15;
		if (off_aligned16 > off) {
			for (unsigned i = 0; i < (off_aligned16 - off); ++i) {
				INT3();
			}
		}
		return off_aligned16;
		};

	// raise any int
	size_t raise_int_off_aligned16 = align_next_func_start();
	m_a.lock().or_(MEMD32(RCX, CPU_CTX_INT), EDX);
	RET();

	// clear any int
	size_t clear_int_off_aligned16 = align_next_func_start();
	NOT(EDX);
	m_a.lock().and_(MEMD32(RCX, CPU_CTX_INT), EDX);
	RET();

	// We generate the following fpu related functions once here, to avoid having to generate them at every guest fpu encountered. We cannot use host helpers for these
	// because the host needs to mirror the guest control word state to the host when it emulates a guest fpu instruction, and the WIN64 calling convention
	// states that the control word is non-volatile across function calls

	// gen_set_host_fpu_ctx
	size_t gen_set_host_fpu_ctx_off_aligned16 = align_next_func_start();
	gen_set_host_fpu_ctx();
	RET();

	// gen_fpu_exp_post_check
	size_t gen_fpu_exp_post_check_off_aligned16 = align_next_func_start();
	gen_fpu_exp_post_check();
	RET();

	if (auto err = m_code.flatten()) {
		std::string err_str("Asmjit failed at flatten() with the error ");
		err_str += DebugUtils::errorAsString(err);
		throw lc86_exp_abort(err_str, lc86_status::internal_error);
	}

	if (auto err = m_code.resolveUnresolvedLinks()) {
		std::string err_str("Asmjit failed at resolveUnresolvedLinks() with the error ");
		err_str += DebugUtils::errorAsString(err);
		throw lc86_exp_abort(err_str, lc86_status::internal_error);
	}

	size_t estimated_code_size = m_code.codeSize();
	if (estimated_code_size == 0) {
		throw lc86_exp_abort("The generated code has a zero size", lc86_status::internal_error);
	}

	auto block = m_mem.allocate_non_pooled_sys_mem(estimated_code_size);
	if (auto err = m_code.relocateToBase(reinterpret_cast<uintptr_t>(block.addr))) {
		std::string err_str("Asmjit failed at relocateToBase() with the error ");
		err_str += DebugUtils::errorAsString(err);
		throw lc86_exp_abort(err_str, lc86_status::internal_error);
	}

	assert(m_code.sectionCount() == 1);

	Section *section = m_code.textSection();
	size_t offset = static_cast<size_t>(section->offset());
	size_t buff_size = static_cast<size_t>(section->bufferSize());

	assert(offset + buff_size <= estimated_code_size);
	std::memcpy(static_cast<uint8_t *>(block.addr) + offset, section->data(), buff_size);

	m_mem.protect_sys_mem(block, MEM_READ | MEM_EXEC);

	m_cpu->read_int_fn = reinterpret_cast<read_int_t>(static_cast<uint8_t *>(block.addr) + offset);
	m_cpu->raise_int_fn = reinterpret_cast<raise_int_t>(static_cast<uint8_t *>(block.addr) + offset + raise_int_off_aligned16);
	m_cpu->clear_int_fn = reinterpret_cast<clear_int_t>(static_cast<uint8_t *>(block.addr) + offset + clear_int_off_aligned16);
	m_cpu->set_host_fpu_ctx_fn = reinterpret_cast<fpu_func_t>(static_cast<uint8_t *>(block.addr) + offset + gen_set_host_fpu_ctx_off_aligned16);
	m_cpu->fpu_exp_post_check_fn = reinterpret_cast<fpu_func_t>(static_cast<uint8_t *>(block.addr) + offset + gen_fpu_exp_post_check_off_aligned16);
}

void
lc86_jit::gen_exit_func()
{
	// this should be emitted before main(), so that we can calculate the tc ptr from tc->ptr_code by simply subtracting an offset

	size_t exit_off_start = m_a.offset();
	MOV(RAX, m_cpu->tc);
	RET();
	size_t exit_off_end = m_a.offset();
	assert((exit_off_end - exit_off_start) == 11);

	size_t main_off_aligned16 = (exit_off_end + 15) & ~15;
	for (unsigned i = 0; i < (main_off_aligned16 - exit_off_end); ++i) {
		INT3();
	}
}

void
lc86_jit::gen_interrupt_check()
{
	Label no_int = m_a.newLabel();
	if (m_cpu->cpu_ctx.hflags & HFLG_TIMEOUT) {
		Label no_timeout = m_a.newLabel();
		CALL_F(&cpu_timer_helper);
		TEST(EAX, EAX);
		BR_EQ(no_int);
		TEST(EAX, CPU_HW_INT | CPU_NON_HW_INT);
		BR_NE(no_timeout);
		MOV(MEMD8(RCX, CPU_CTX_EXIT), 1); // request an exit
		m_a.bind(no_timeout);
	}
	else {
		MOV(EDX, MEMD32(RCX, CPU_CTX_INT));
		TEST(EDX, EDX);
		BR_EQ(no_int);
		MOV(RAX, &cpu_do_int);
		CALL(RAX);
	}
	XOR(EAX, EAX);
	gen_epilogue_main<false>();
	m_a.bind(no_int);
}

void
lc86_jit::gen_no_link_checks()
{
	if ((m_cpu->disas_ctx.flags & DISAS_FLG_INHIBIT_INT) && (m_cpu->cpu_ctx.hflags & HFLG_INHIBIT_INT)) {
		assert(m_cpu->disas_ctx.flags & DISAS_FLG_ONE_INSTR);

		MOV(EAX, MEMD32(RCX, CPU_CTX_HFLG));
		AND(EAX, ~HFLG_INHIBIT_INT);
		MOV(MEMD32(RCX, CPU_CTX_HFLG), EAX);
		m_cpu->cpu_flags |= CPU_FORCE_INSERT;
	}

	if (m_cpu->cpu_ctx.hflags & HFLG_DBG_TRAP) {
		LD_R32(EAX, CPU_CTX_EIP);
		gen_raise_exp_inline<true>(0, 0, EXP_DB, EAX);
		return;
	}

	if (gen_check_rf_single_step()) {
		return;
	}

	gen_interrupt_check();
}

void
lc86_jit::gen_prologue_main()
{
	// Prolog of our main() function:
	// push rbx
	// sub rsp, 0x20 + sizeof(stack args) + sizeof(local vars)
	//
	// How to write the jitted function:
	// RCX always holds the cpu_ctx arg, and should never be changed. If you still need to (e.g. after a call to an external function), you should always restore it
	// immediately after with a MOV rcx, &m_cpu->cpu_ctx, since the cu_ctx is a constant and never changes at runtime while the emulation is running. Prologue and
	// epilog always push and pop RBX, so it's volatile too. Prefer using RAX, RDX, RBX over R8, R9, R10 and R11 to reduce the code size, and only use the host stack
	// as a last resort. Calling external functions from main() must be done with CALL(RAX), and not with rip offsets, because the function can be farther than
	// 4 GiB from the current code.
	// Some optimizations used in the main() function:
	// Offsets from cpu_ctx can be calculated with displacements, to avoid having to use additional ADD instructions. Local variables on the stack are always allocated
	// at a fixed offset computed at compile time, and the shadow area to spill registers is available too (always allocated by the caller of the jitted function).
	// Two additions and a shift can be done with LEA and the sib addressing mode. Comparisons with zero are usually done with TEST reg, reg instead of CMP. Left shifting
	// by one can be done with ADD reg, reg. Reading an 8/16 bit reg and then zero/sign extending to 32 can be done with a single MOVZ/SX reg, word/byte ptr [rcx, off] instead
	// of MOV and then MOVZ/SX. Call external C++ helper functions to implement the most difficult instructions.
	// Guest SSE is currently emulated with host SSE. If the library is compiled with AVX support, then the jit should emit VZEROUPPER to avoid the performance penalty
	// associated with mixing legacy SSE with AVX, or better, it should just emit AVX instructions directly

	PUSH(RBX);
	SUB(RSP, get_jit_stack_required());

	m_needs_epilogue = true;
}

template<bool set_ret>
void lc86_jit::gen_epilogue_main()
{
	if constexpr (set_ret) {
		MOV(RAX, m_cpu->tc);
	}
	ADD(RSP, get_jit_stack_required());
	POP(RBX);
	RET();
}

void
lc86_jit::gen_tail_call(x86::Gp addr)
{
	ADD(RSP, get_jit_stack_required());
	POP(RBX);
	BR_UNCOND(addr);
}

void
lc86_jit::gen_tc_epilogue()
{
	// update the eip if we stopped decoding without a terminating instr
	if (m_cpu->translate_next == 1) {
		assert((m_cpu->disas_ctx.flags & (DISAS_FLG_PAGE_CROSS | DISAS_FLG_PAGE_CROSS_NEXT | DISAS_FLG_ONE_INSTR)) != 0);
		assert((m_cpu->tc->flags & TC_FLG_LINK_MASK) == 0);

		MOV(MEMD32(RCX, CPU_CTX_EIP), m_cpu->virt_pc - m_cpu->cpu_ctx.regs.cs_hidden.base);
		gen_no_link_checks();
	}

	if (m_needs_epilogue) {
		gen_epilogue_main();
	}
}

template<bool terminates, typename T1, typename T2, typename T3, typename T4>
void lc86_jit::gen_raise_exp_inline(T1 fault_addr, T2 code, T3 idx, T4 eip)
{
	// should be false when generating a conditional exception, true when taking an unconditional exception
	if constexpr (terminates) {
		m_needs_epilogue = false;
		m_cpu->translate_next = 0;
	}

	MOV(MEMD32(RCX, CPU_EXP_ADDR), fault_addr);
	MOV(MEMD16(RCX, CPU_EXP_CODE), code);
	MOV(MEMD16(RCX, CPU_EXP_IDX), idx);
	MOV(MEMD32(RCX, CPU_EXP_EIP), eip);
	MOV(RAX, &cpu_raise_exception<>);
	CALL(RAX);
	gen_epilogue_main<false>();
}

template<bool terminates>
void lc86_jit::gen_raise_exp_inline()
{
	// same as the function above, but it doesn't populate the exception data
	if constexpr (terminates) {
		m_needs_epilogue = false;
		m_cpu->translate_next = 0;
	}

	MOV(RAX, &cpu_raise_exception<>);
	CALL(RAX);
	gen_epilogue_main<false>();
}

void
lc86_jit::gen_hook(hook_t hook_addr)
{
	CALL_F(hook_addr);
	gen_link_ret();
}

void
lc86_jit::gen_raise_exp_inline(uint32_t fault_addr, uint16_t code, uint16_t idx, uint32_t eip)
{
	gen_raise_exp_inline<true>(fault_addr, code, idx, eip);
}

bool
lc86_jit::gen_check_rf_single_step()
{
	if ((m_cpu->cpu_ctx.regs.eflags & (RF_MASK | TF_MASK)) | (m_cpu->cpu_flags & CPU_SINGLE_STEP)) {

		if (m_cpu->cpu_ctx.regs.eflags & (RF_MASK | TF_MASK)) {
			m_cpu->cpu_flags |= CPU_FORCE_INSERT;
		}

		if (m_cpu->cpu_ctx.regs.eflags & RF_MASK) {
			// clear rf if it is set. This happens in the one-instr tc that contains the instr that originally caused the instr breakpoint. This must be done at runtime
			// because otherwise tc_cache_insert will register rf as clear, when it was set at the beginning of this tc
			MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS));
			AND(EDX, ~RF_MASK);
			MOV(MEMD32(RCX, CPU_CTX_EFLAGS), EDX);
		}

		if ((m_cpu->cpu_ctx.regs.eflags & TF_MASK) | (m_cpu->cpu_flags & CPU_SINGLE_STEP)) {
			// NOTE: if this instr also has a watchpoint, the other DB exp won't be generated
			MOV(EDX, MEMD32(RCX, CPU_CTX_DR6));
			OR(EDX, DR6_BS_MASK);
			MOV(MEMD32(RCX, CPU_CTX_DR6), EDX);
			MOV(EDX, MEMD32(RCX, CPU_CTX_EIP));
			RAISEin_f(0, 0, EXP_DB, EDX);
			return true;
		}
	}

	return false;
}

template<typename T>
void lc86_jit::gen_link_direct(addr_t dst_pc, addr_t *next_pc, T target_pc)
{
	// dst_pc: destination pc, next_pc: pc of next instr, target_addr: pc where instr jumps to at runtime
	// If target_pc is an integral type, then we know already where the instr will jump, and so we can perform the comparisons at compile time
	// and only emit the taken code path. If it's in a reg, it must be ebx because otherwise a volatile reg might be trashed by the timer and
	// interrupt calls in gen_no_link_checks

	m_needs_epilogue = false;

	gen_no_link_checks();

	// vec_addr: instr_pc, dst_pc, next_pc
	addr_t page_addr = m_cpu->virt_pc & ~PAGE_MASK;
	uint32_t n, dst = (dst_pc & ~PAGE_MASK) == page_addr;
	if (next_pc) {
		n = dst + ((*next_pc & ~PAGE_MASK) == page_addr);
	}
	else {
		n = dst;
	}
	m_cpu->tc->flags |= (n & TC_FLG_NUM_JMP);

	switch (n)
	{
	case 0:
		gen_epilogue_main();
		return;

	case 1: {
		if (next_pc) { // if(dst_pc) -> cond jmp dst_pc; if(next_pc) -> cond jmp next_pc
			if (dst) {
				MOV(RDX, &m_cpu->tc->flags);
				MOV(EAX, MEM32(RDX));
				AND(EAX, ~TC_FLG_JMP_TAKEN);
				if constexpr (std::is_integral_v<T>) {
					if (target_pc == dst_pc) {
						MOV(MEM32(RDX), EAX);
						MOV(RDX, &m_cpu->tc->jmp_offset[0]);
						MOV(RAX, MEM64(RDX));
						gen_tail_call(RAX);
					}
					else {
						OR(EAX, TC_JMP_RET << 4);
						MOV(MEM32(RDX), EAX);
						gen_epilogue_main();
					}
				}
				else {
					Label ret = m_a.newLabel();
					CMP(target_pc, dst_pc);
					BR_NE(ret);
					MOV(MEM32(RDX), EAX);
					MOV(RDX, &m_cpu->tc->jmp_offset[0]);
					MOV(RAX, MEM64(RDX));
					gen_tail_call(RAX);
					m_a.bind(ret);
					OR(EAX, TC_JMP_RET << 4);
					MOV(MEM32(RDX), EAX);
					gen_epilogue_main();
				}
			}
			else {
				MOV(RDX, &m_cpu->tc->flags);
				MOV(EAX, MEM32(RDX));
				AND(EAX, ~TC_FLG_JMP_TAKEN);
				if constexpr (std::is_integral_v<T>) {
					if (target_pc == *next_pc) {
						OR(EAX, TC_JMP_NEXT_PC << 4);
						MOV(MEM32(RDX), EAX);
						MOV(RDX, &m_cpu->tc->jmp_offset[1]);
						MOV(RAX, MEM64(RDX));
						gen_tail_call(RAX);
					}
					else {
						OR(EAX, TC_JMP_RET << 4);
						MOV(MEM32(RDX), EAX);
						gen_epilogue_main();
					}
				}
				else {
					Label ret = m_a.newLabel();
					CMP(target_pc, *next_pc);
					BR_NE(ret);
					OR(EAX, TC_JMP_NEXT_PC << 4);
					MOV(MEM32(RDX), EAX);
					MOV(RDX, &m_cpu->tc->jmp_offset[1]);
					MOV(RAX, MEM64(RDX));
					gen_tail_call(RAX);
					m_a.bind(ret);
					OR(EAX, TC_JMP_RET << 4);
					MOV(MEM32(RDX), EAX);
					gen_epilogue_main();
				}
			}
		}
		else { // uncond jmp dst_pc
			MOV(RDX, &m_cpu->tc->jmp_offset[0]);
			MOV(RAX, MEM64(RDX));
			gen_tail_call(RAX);
		}
	}
	break;

	case 2: { // cond jmp next_pc + uncond jmp dst_pc
		MOV(RDX, &m_cpu->tc->flags);
		MOV(EAX, MEM32(RDX));
		AND(EAX, ~TC_FLG_JMP_TAKEN);
		if constexpr (std::is_integral_v<T>) {
			if (target_pc == *next_pc) {
				OR(EAX, TC_JMP_NEXT_PC << 4);
				MOV(MEM32(RDX), EAX);
				MOV(RDX, &m_cpu->tc->jmp_offset[1]);
				MOV(RAX, MEM64(RDX));
				gen_tail_call(RAX);
			}
			else {
				MOV(MEM32(RDX), EAX);
				MOV(RDX, &m_cpu->tc->jmp_offset[0]);
				MOV(RAX, MEM64(RDX));
				gen_tail_call(RAX);
			}
		}
		else {
			Label ret = m_a.newLabel();
			CMP(target_pc, *next_pc);
			BR_NE(ret);
			OR(EAX, TC_JMP_NEXT_PC << 4);
			MOV(MEM32(RDX), EAX);
			MOV(RDX, &m_cpu->tc->jmp_offset[1]);
			MOV(RAX, MEM64(RDX));
			gen_tail_call(RAX);
			m_a.bind(ret);
			MOV(MEM32(RDX), EAX);
			MOV(RDX, &m_cpu->tc->jmp_offset[0]);
			MOV(RAX, MEM64(RDX));
			gen_tail_call(RAX);
		}
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::gen_link_dst_only()
{
	m_needs_epilogue = false;

	gen_no_link_checks();

	m_cpu->tc->flags |= (1 & TC_FLG_NUM_JMP);

	MOV(RDX, &m_cpu->tc->jmp_offset[0]);
	MOV(RAX, MEM64(RDX));
	gen_tail_call(RAX);
}

void
lc86_jit::gen_link_indirect()
{
	m_needs_epilogue = false;

	gen_no_link_checks();

	MOV(RDX, m_cpu->tc);
	CALL_F(&link_indirect_handler);
	gen_tail_call(RAX);
}

void
lc86_jit::gen_link_ret()
{
	// NOTE: perhaps find a way to use a return stack buffer to link to the next tc

	gen_link_indirect();
}

template<typename T>
void lc86_jit::gen_link_dst_cond(T &&lambda)
{
	// condition result should be in ebx; if true, jumps to dst, otherwise jumps to next

	m_needs_epilogue = false;

	gen_no_link_checks();

	if ((m_cpu->virt_pc & ~PAGE_MASK) == (m_cpu->virt_pc + m_cpu->instr_bytes & ~PAGE_MASK)) {
		MOV(RDX, &m_cpu->tc->flags);
		MOV(EAX, MEM32(RDX));
		AND(EAX, ~TC_FLG_JMP_TAKEN);
		lambda();
		Label dst = m_a.newLabel();
		BR_EQ(dst);
		OR(EAX, TC_JMP_NEXT_PC << 4);
		MOV(MEM32(RDX), EAX);
		MOV(RDX, &m_cpu->tc->jmp_offset[1]);
		MOV(RAX, MEM64(RDX));
		gen_tail_call(RAX);
		m_a.bind(dst);
		MOV(MEM32(RDX), EAX);
		MOV(RDX, &m_cpu->tc->jmp_offset[0]);
		MOV(RAX, MEM64(RDX));
		gen_tail_call(RAX);

		m_cpu->tc->flags |= ((2 & TC_FLG_NUM_JMP) | TC_FLG_DST_COND);
	}
	else {
		gen_epilogue_main();
	}
}

template<bool add_seg_base>
op_info lc86_jit::get_operand(decoded_instr *instr, const unsigned opnum)
{
	ZydisDecodedOperand *operand = &instr->o[opnum];

	switch (operand->type)
	{
	case ZYDIS_OPERAND_TYPE_MEMORY: // final 32 bit addr in edx, r10 and r11 are clobbered
	{
		switch (operand->encoding)
		{
		case ZYDIS_OPERAND_ENCODING_DISP16_32_64: {
			uint32_t disp = instr->i.address_width == 32 ? operand->mem.disp.value : operand->mem.disp.value & 0xFFFF;
			if constexpr (add_seg_base) {
				LD_SEG_BASE(EDX, REG_off(operand->mem.segment));
				ADD(EDX, disp);
			}
			else {
				MOV(EDX, disp);
			}
		}
		return {};

		case ZYDIS_OPERAND_ENCODING_MODRM_RM: {
			if (instr->i.address_width == 32) {
				if (operand->mem.base != ZYDIS_REGISTER_NONE) {
					LD_R32(R10D, REG_off(operand->mem.base));
				}
				else {
					XOR(R10D, R10D);
				}

				if (operand->mem.scale) {
					// asmjit wants the scale expressed as indexed value scale = 1 << n, so don't use operand->mem.scale
					LD_R32(R11D, REG_off(operand->mem.index));
					LEA(R10D, MEMS32(R10D, R11D, instr->i.raw.sib.scale));
				}

				if (operand->mem.disp.has_displacement) {
					if constexpr (add_seg_base) {
						LD_SEG_BASE(EDX, REG_off(operand->mem.segment));
						if (instr->i.raw.modrm.mod == 1) {
							LEA(EDX, MEMSD32(EDX, R10D, 0, static_cast<int32_t>(static_cast<int8_t>(operand->mem.disp.value))));
						}
						else {
							LEA(EDX, MEMSD32(EDX, R10D, 0, operand->mem.disp.value));
						}
					}
					else {
						if (instr->i.raw.modrm.mod == 1) {
							LEA(EDX, MEMSb32(R10D, 0, static_cast<int32_t>(static_cast<int8_t>(operand->mem.disp.value))));
						}
						else {
							LEA(EDX, MEMSb32(R10D, 0, operand->mem.disp.value));
						}
					}
					return {};
				}

				if constexpr (add_seg_base) {
					LD_SEG_BASE(EDX, REG_off(operand->mem.segment));
					ADD(EDX, R10D);
				}
				else {
					MOV(EDX, R10D);
				}
				return {};
			}
			else {
				if (operand->mem.base != ZYDIS_REGISTER_NONE) {
					LD_R16(R10W, REG_off(operand->mem.base));
				}
				else {
					XOR(R10W, R10W);
				}

				if (operand->mem.scale) {
					// asmjit wants the scale expressed as indexed value scale = 1 << n, so don't use operand->mem.scale
					LD_R16(R11W, REG_off(operand->mem.index));
					SHL(R11W, instr->i.raw.sib.scale);
					ADD(R10W, R11W);
				}

				if (operand->mem.disp.has_displacement) {
					if constexpr (add_seg_base) {
						LD_SEG_BASE(EDX, REG_off(operand->mem.segment));
						if (instr->i.raw.modrm.mod == 1) {
							ADD(R10W, static_cast<int16_t>(static_cast<int8_t>(operand->mem.disp.value)));
							MOVZX(R10D, R10W);
							ADD(EDX, R10D);
						}
						else {
							ADD(R10W, operand->mem.disp.value);
							MOVZX(R10D, R10W);
							ADD(EDX, R10D);
						}
					}
					else {
						if (instr->i.raw.modrm.mod == 1) {
							ADD(R10W, static_cast<int16_t>(static_cast<int8_t>(operand->mem.disp.value)));
							MOVZX(EDX, R10W);
						}
						else {
							ADD(R10W, operand->mem.disp.value);
							MOVZX(EDX, R10W);
						}
					}
					return {};
				}

				if constexpr (add_seg_base) {
					LD_SEG_BASE(EDX, REG_off(operand->mem.segment));
					MOVZX(R10D, R10W);
					ADD(EDX, R10D);
				}
				else {
					MOVZX(EDX, R10W);
				}
				return {};
			}
		}
		break;

		default:
			LIB86CPU_ABORT_msg("Unhandled mem operand encoding %d in %s", operand->encoding, __func__);
		}
	}
	break;

	case ZYDIS_OPERAND_TYPE_REGISTER: { // op_info with reg offset and bit size
		size_t offset = REG_off(operand->reg.value);
		switch (operand->size)
		{
		case 8:
			return { offset, SIZE8 };

		case 16:
			return { offset, SIZE16 };

		case 32:
			return { offset, SIZE32 };

		case 128:
			return { offset, SIZE128 };

		default:
			LIB86CPU_ABORT();
		}
	}
	break;

	case ZYDIS_OPERAND_TYPE_POINTER:
		LIB86CPU_ABORT_msg("Segment and offset of pointer type operand should be read directly by the translator instead of from %s", __func__);
		break;

	case ZYDIS_OPERAND_TYPE_IMMEDIATE: { // op_info with imm value and bit size
		switch (operand->encoding)
		{
		case ZYDIS_OPERAND_ENCODING_UIMM16:
			return { operand->imm.value.u, SIZE16 };

		case ZYDIS_OPERAND_ENCODING_UIMM8:
		case ZYDIS_OPERAND_ENCODING_JIMM8:
			return { operand->imm.value.u, SIZE8 };

		case ZYDIS_OPERAND_ENCODING_JIMM16_32_32:
			if (operand->size == 32) {
				return { operand->imm.value.u, SIZE32 };
			}
			else {
				return { operand->imm.value.u, SIZE16 };
			}

		default:
			LIB86CPU_ABORT_msg("Unhandled imm operand encoding %d in %s", operand->encoding, __func__);
		}
	}

	default:
		LIB86CPU_ABORT_msg("Unhandled operand type specified");
	}
}

op_info
lc86_jit::get_register_op(decoded_instr *instr, const unsigned opnum)
{
	assert(instr->o[opnum].type == ZYDIS_OPERAND_TYPE_REGISTER);
	return get_operand(instr, opnum);
}

uint32_t
lc86_jit::get_immediate_op(decoded_instr *instr, const unsigned opnum)
{
	assert(instr->o[opnum].type == ZYDIS_OPERAND_TYPE_IMMEDIATE);
	return instr->o[opnum].imm.value.u;
}

template<unsigned opnum, typename T1, typename T2>
auto lc86_jit::get_rm(decoded_instr *instr, T1 &&reg, T2 &&mem)
{
	const op_info rm = GET_OP(opnum);
	switch (instr->o[opnum].type)
	{
	case ZYDIS_OPERAND_TYPE_REGISTER:
		return reg(rm);

	case ZYDIS_OPERAND_TYPE_MEMORY:
		return mem(rm);

	default:
		LIB86CPU_ABORT_msg("Invalid operand type used in %s!", __func__);
	}
}

template<bool write_dst, typename T>
void lc86_jit::r_to_rm(decoded_instr *instr, T &&lambda)
{
	get_rm<OPNUM_DST>(instr,
		[this, instr, &lambda](const op_info rm)
		{
			const auto src = GET_REG(OPNUM_SRC);
			auto src_host_reg = SIZED_REG(x64::rdx, src.bits);
			auto dst_host_reg = SIZED_REG(x64::rax, rm.bits);
			LD_REG_val(src_host_reg, src.val, src.bits);
			LD_REG_val(dst_host_reg, rm.val, rm.bits);
			lambda(dst_host_reg, src_host_reg);
			if constexpr (write_dst) {
				ST_REG_val(dst_host_reg, rm.val, rm.bits);
			}
			set_flags(dst_host_reg, 0, rm.bits);
		},
		[this, instr, &lambda](const op_info rm)
		{
			const auto src = GET_REG(OPNUM_SRC);
			auto src_host_reg = SIZED_REG(x64::rdx, src.bits);
			auto dst_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
			if constexpr (write_dst) {
				auto res_host_reg = SIZED_REG(x64::rbx, m_cpu->size_mode);
				MOV(EBX, EDX);
				LD_MEM();
				LD_REG_val(src_host_reg, src.val, src.bits);
				lambda(dst_host_reg, src_host_reg);
				MOV(EDX, EBX);
				MOV(res_host_reg, dst_host_reg);
				ST_MEM(res_host_reg);
				set_flags(res_host_reg, 0, m_cpu->size_mode);
			}
			else {
				LD_MEM();
				LD_REG_val(src_host_reg, src.val, src.bits);
				lambda(dst_host_reg, src_host_reg);
				set_flags(dst_host_reg, 0, m_cpu->size_mode);
			}
		});
}

template<bool is_sum, bool write_dst, typename T>
void lc86_jit::r_to_rm_flags(decoded_instr *instr, T &&lambda)
{
	get_rm<OPNUM_DST>(instr,
		[this, instr, &lambda](const op_info rm)
		{
			const auto src = GET_REG(OPNUM_SRC);
			auto src_host_reg = SIZED_REG(x64::rbx, src.bits);
			auto dst_host_reg = SIZED_REG(x64::rax, rm.bits);
			auto res_host_reg = SIZED_REG(x64::r8, rm.bits);
			LD_REG_val(dst_host_reg, rm.val, rm.bits);
			LD_REG_val(src_host_reg, src.val, src.bits);
			MOV(res_host_reg, dst_host_reg);
			lambda(res_host_reg, src_host_reg);
			if constexpr (write_dst) {
				ST_REG_val(res_host_reg, rm.val, rm.bits);
			}
			if constexpr (is_sum) {
				set_flags_sum(dst_host_reg, src_host_reg, res_host_reg);
			}
			else {
				set_flags_sub(dst_host_reg, src_host_reg, res_host_reg);
			}
		},
		[this, instr, &lambda](const op_info rm)
		{
			const auto src = GET_REG(OPNUM_SRC);
			auto src_host_reg = SIZED_REG(x64::rbx, src.bits);
			auto dst_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
			auto res_host_reg = SIZED_REG(x64::r8, m_cpu->size_mode);
			if constexpr (write_dst) {
				MOV(EBX, EDX);
				LD_MEM();
				MOV(EDX, EBX);
				LD_REG_val(src_host_reg, src.val, src.bits);
				MOV(res_host_reg, dst_host_reg);
				lambda(res_host_reg, src_host_reg);
				MOV(MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode), dst_host_reg);
				MOV(MEMD(RSP, LOCAL_VARS_off(1), m_cpu->size_mode), res_host_reg);
				ST_MEM(res_host_reg);
				MOV(dst_host_reg, MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode));
				MOV(res_host_reg, MEMD(RSP, LOCAL_VARS_off(1), m_cpu->size_mode));
			}
			else {
				LD_MEM();
				LD_REG_val(src_host_reg, src.val, src.bits);
				MOV(res_host_reg, dst_host_reg);
				lambda(res_host_reg, src_host_reg);
			}
			if constexpr (is_sum) {
				set_flags_sum(dst_host_reg, src_host_reg, res_host_reg);
			}
			else {
				set_flags_sub(dst_host_reg, src_host_reg, res_host_reg);
			}
		});
}

template<bool write_dst, typename T>
void lc86_jit::rm_to_r(decoded_instr *instr, T &&lambda)
{
	const auto dst = GET_REG(OPNUM_DST);
	auto dst_host_reg = SIZED_REG(x64::rbx, dst.bits);
	LD_REG_val(dst_host_reg, dst.val, dst.bits);
	get_rm<OPNUM_SRC>(instr,
		[this, dst_host_reg, dst, instr, &lambda](const op_info rm)
		{
			auto src_host_reg = SIZED_REG(x64::rax, rm.bits);
			LD_REG_val(src_host_reg, rm.val, rm.bits);
			lambda(dst_host_reg, src_host_reg);
			if constexpr (write_dst) {
				ST_REG_val(dst_host_reg, dst.val, dst.bits);
			}
		},
		[this, dst_host_reg, dst, instr, &lambda](const op_info rm)
		{
			auto src_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
			LD_MEM();
			lambda(dst_host_reg, src_host_reg);
			if constexpr (write_dst) {
				ST_REG_val(dst_host_reg, dst.val, dst.bits);
			}
		});
	set_flags(dst_host_reg, 0, dst.bits);
}

template<bool is_sum, bool write_dst, typename T>
void lc86_jit::rm_to_r_flags(decoded_instr *instr, T &&lambda)
{
	get_rm<OPNUM_SRC>(instr,
		[this, instr, &lambda](const op_info rm)
		{
			auto dst = GET_REG(OPNUM_DST);
			auto dst_host_reg = SIZED_REG(x64::rax, dst.bits);
			auto src_host_reg = SIZED_REG(x64::rbx, rm.bits);
			auto res_host_reg = SIZED_REG(x64::r8, rm.bits);
			LD_REG_val(dst_host_reg, dst.val, dst.bits);
			LD_REG_val(src_host_reg, rm.val, rm.bits);
			MOV(res_host_reg, dst_host_reg);
			lambda(res_host_reg, src_host_reg);
			if constexpr (write_dst) {
				ST_REG_val(res_host_reg, dst.val, dst.bits);
			}
			if constexpr (is_sum) {
				set_flags_sum(dst_host_reg, src_host_reg, res_host_reg);
			}
			else {
				set_flags_sub(dst_host_reg, src_host_reg, res_host_reg);
			}
		},
		[this, instr, &lambda](const op_info rm)
		{
			auto dst = GET_REG(OPNUM_DST);
			auto dst_host_reg = SIZED_REG(x64::rbx, dst.bits);
			auto src_host_reg = SIZED_REG(x64::rdx, m_cpu->size_mode);
			auto res_host_reg = SIZED_REG(x64::r8, m_cpu->size_mode);
			auto rax_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
			LD_MEM();
			MOV(src_host_reg, rax_host_reg);
			LD_REG_val(dst_host_reg, dst.val, dst.bits);
			MOV(res_host_reg, dst_host_reg);
			lambda(res_host_reg, src_host_reg);
			if constexpr (write_dst) {
				ST_REG_val(res_host_reg, dst.val, dst.bits);
			}
			if constexpr (is_sum) {
				set_flags_sum(dst_host_reg, src_host_reg, res_host_reg);
			}
			else {
				set_flags_sub(dst_host_reg, src_host_reg, res_host_reg);
			}
		});
}

template<bool write_dst, typename T>
void lc86_jit::imm_to_eax(decoded_instr *instr, T &&lambda)
{
	const auto dst = GET_REG(OPNUM_DST);
	auto dst_host_reg = SIZED_REG(x64::rax, dst.bits);
	LD_REG_val(dst_host_reg, dst.val, dst.bits);
	lambda(dst_host_reg, GET_IMM());
	if constexpr (write_dst) {
		ST_REG_val(dst_host_reg, dst.val, dst.bits);
	}
	set_flags(dst_host_reg, 0, dst.bits);
}

template<bool is_sum, bool write_dst, typename T>
void lc86_jit::imm_to_eax_flags(decoded_instr *instr, T &&lambda)
{
	auto dst = GET_REG(OPNUM_DST);
	auto dst_host_reg = SIZED_REG(x64::rax, dst.bits);
	auto res_host_reg = SIZED_REG(x64::r8, dst.bits);
	uint32_t src_imm = GET_IMM();
	LD_REG_val(dst_host_reg, dst.val, dst.bits);
	MOV(res_host_reg, dst_host_reg);
	lambda(res_host_reg, src_imm);
	if constexpr (write_dst) {
		ST_REG_val(res_host_reg, dst.val, dst.bits);
	}
	if constexpr (is_sum) {
		set_flags_sum(dst_host_reg, src_imm, res_host_reg);
	}
	else {
		set_flags_sub(dst_host_reg, src_imm, res_host_reg);
	}
}

template<typename Imm, bool write_dst, typename T>
void lc86_jit::imm_to_rm(decoded_instr *instr, Imm src_imm, T &&lambda)
{
	get_rm<OPNUM_DST>(instr,
		[this, src_imm, instr, &lambda](const op_info rm)
		{
			auto dst_host_reg = SIZED_REG(x64::rax, rm.bits);
			LD_REG_val(dst_host_reg, rm.val, rm.bits);
			lambda(dst_host_reg, src_imm);
			if constexpr (write_dst) {
				ST_REG_val(dst_host_reg, rm.val, rm.bits);
			}
			set_flags(dst_host_reg, 0, rm.bits);
		},
		[this, src_imm, instr, &lambda](const op_info rm)
		{
			auto dst_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
			if constexpr (write_dst) {
				auto res_host_reg = SIZED_REG(x64::rbx, m_cpu->size_mode);
				MOV(EBX, EDX);
				LD_MEM();
				lambda(dst_host_reg, src_imm);
				MOV(EDX, EBX);
				MOV(res_host_reg, dst_host_reg);
				ST_MEM(res_host_reg);
				set_flags(res_host_reg, 0, m_cpu->size_mode);
			}
			else {
				LD_MEM();
				lambda(dst_host_reg, src_imm);
				set_flags(dst_host_reg, 0, m_cpu->size_mode);
			}
		});
}

template<bool is_sum, typename Imm, bool write_dst, typename T>
void lc86_jit::imm_to_rm_flags(decoded_instr *instr, Imm src_imm, T &&lambda)
{
	get_rm<OPNUM_DST>(instr,
		[this, src_imm, &lambda](const op_info rm)
		{
			auto dst_host_reg = SIZED_REG(x64::rax, rm.bits);
			auto res_host_reg = SIZED_REG(x64::r8, rm.bits);
			LD_REG_val(dst_host_reg, rm.val, rm.bits);
			MOV(res_host_reg, dst_host_reg);
			lambda(res_host_reg, src_imm);
			if constexpr (write_dst) {
				ST_REG_val(res_host_reg, rm.val, rm.bits);
			}
			if constexpr (is_sum) {
				set_flags_sum(dst_host_reg, src_imm, res_host_reg);
			}
			else {
				set_flags_sub(dst_host_reg, src_imm, res_host_reg);
			}
		},
		[this, src_imm, &lambda](const op_info rm)
		{
			auto dst_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
			auto res_host_reg = SIZED_REG(x64::rbx, m_cpu->size_mode);
			auto r8_host_reg = SIZED_REG(x64::r8, m_cpu->size_mode);
			if constexpr (write_dst) {
				MOV(EBX, EDX);
				LD_MEM();
				MOV(EDX, EBX);
				MOV(res_host_reg, dst_host_reg);
				lambda(res_host_reg, src_imm);
				MOV(MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode), dst_host_reg);
				ST_MEM(res_host_reg);
				MOV(dst_host_reg, MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode));
				MOV(r8_host_reg, res_host_reg);
			}
			else {
				LD_MEM();
				MOV(res_host_reg, dst_host_reg);
				lambda(res_host_reg, src_imm);
				MOV(r8_host_reg, res_host_reg);
			}
			if constexpr (is_sum) {
				set_flags_sum(dst_host_reg, src_imm, r8_host_reg);
			}
			else {
				set_flags_sub(dst_host_reg, src_imm, r8_host_reg);
			}
		});
}

template<unsigned size, typename T>
void lc86_jit::gen_sum_vec16_8(T b, x86::Gp sum)
{
	// a: cx/cl, b: (d|b)x/(d|b)l or imm16/8, sum: r8w/r8b

	assert(sum.id() == x86::Gp::kIdR8);
	if constexpr (!std::is_integral_v<T>) {
		assert(b.id() == x86::Gp::kIdDx || b.id() == x86::Gp::kIdBx);
	}

	x86::Gp temp, a;
	size_t shift;

	if constexpr (size == SIZE16) {
		a = CX;
		temp = AX;
		shift = 16;
	}
	else {
		a = CL;
		temp = AL;
		shift = 24;
	}

	AND(a, b);
	OR(temp, b);
	NOT(sum);
	AND(temp, sum);
	OR(a, temp);
	MOVZX(EAX, a);
	MOV(R9D, EAX);
	SHL(EAX, shift);
	OR(EAX, R9D);
	AND(EAX, 0xC0000008);
}

template<typename T>
void lc86_jit::gen_sum_vec32(T b)
{
	// a: ecx, b: e(d|b)x or imm32, sum: r8d

	if constexpr (!std::is_integral_v<T>) {
		assert(b.id() == x86::Gp::kIdDx || b.id() == x86::Gp::kIdBx);
	}

	NOT(R8D);
	OR(EAX, b);
	AND(ECX, b);
	AND(EAX, R8D);
	OR(EAX, ECX);
	AND(EAX, 0xC0000008);
}

template<unsigned size, typename T>
void lc86_jit::gen_sub_vec16_8(T b, x86::Gp sub)
{
	// a: cx/cl, b: (d|b)x/(d|b)l or imm16/8, sub: r8w/r8b

	assert(sub.id() == x86::Gp::kIdR8);
	if constexpr (!std::is_integral_v<T>) {
		assert(b.id() == x86::Gp::kIdDx || b.id() == x86::Gp::kIdBx);
	}

	x86::Gp temp, a;
	size_t shift;

	if constexpr (size == SIZE16) {
		a = CX;
		temp = AX;
		shift = 16;
	}
	else {
		a = CL;
		temp = AL;
		shift = 24;
	}

	NOT(a);
	AND(a, b);
	XOR(temp, b);
	NOT(temp);
	AND(temp, sub);
	OR(a, temp);
	MOVZX(EAX, a);
	MOV(R9D, EAX);
	SHL(EAX, shift);
	OR(EAX, R9D);
	AND(EAX, 0xC0000008);
}

template<typename T>
void lc86_jit::gen_sub_vec32(T b)
{
	// a: ecx, b: e(d|b)x or imm32, sub: r8d

	if constexpr (!std::is_integral_v<T>) {
		assert(b.id() == x86::Gp::kIdDx || b.id() == x86::Gp::kIdBx);
	}

	NOT(ECX);
	XOR(EAX, b);
	AND(ECX, b);
	NOT(EAX);
	AND(EAX, R8D);
	OR(EAX, ECX);
	AND(EAX, 0xC0000008);
}

template<typename T>
void lc86_jit::set_flags_sum(x86::Gp a, T b, x86::Gp sum)
{
	// a: reg, b: e(d|b)x/(d|b)x/(d|b)l or imm32/16/8, sum: r8d/w/b

	assert(sum.id() == x86::Gp::kIdR8);
	if constexpr (!std::is_integral_v<T>) {
		assert(b.id() == x86::Gp::kIdDx || b.id() == x86::Gp::kIdBx);
	}

	bool is_eax = false;
	if (a.id() == x86::Gp::kIdAx) {
		is_eax = true;
	}

	switch (m_cpu->size_mode)
	{
	case SIZE8:
		MOVSX(R8D, sum);
		MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), R8D);
		MOV(CL, a);
		if (!is_eax) {
			MOV(AL, CL);
		}
		gen_sum_vec16_8<SIZE8>(b, sum);
		break;

	case SIZE16:
		MOVSX(R8D, sum);
		MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), R8D);
		MOV(CX, a);
		if (!is_eax) {
			MOV(AX, CX);
		}
		gen_sum_vec16_8<SIZE16>(b, sum);
		break;

	case SIZE32:
		MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), R8D);
		MOV(ECX, a);
		if (!is_eax) {
			MOV(EAX, ECX);
		}
		gen_sum_vec32(b);
		break;

	default:
		LIB86CPU_ABORT_msg("Invalid size_mode \"%c\" used in %s", m_cpu->size_mode, __func__);
	}

	RELOAD_RCX_CTX();
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EAX);
}

template<typename T1, typename T2>
void lc86_jit::set_flags_sub(T1 a, T2 b, x86::Gp sub)
{
	// a: reg or imm32/16/8, b: e(d|b)x/(d|b)x/(d|b)l or imm32/16/8, sub: r8d/w/b

	assert(sub.id() == x86::Gp::kIdR8);
	if constexpr (!std::is_integral_v<T2>) {
		assert(b.id() == x86::Gp::kIdDx || b.id() == x86::Gp::kIdBx);
	}

	bool is_eax = false;
	if constexpr (!std::is_integral_v<T1>) {
		if (a.id() == x86::Gp::kIdAx) {
			is_eax = true;
		}
	}

	switch (m_cpu->size_mode)
	{
	case SIZE8:
		MOVSX(R8D, sub);
		MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), R8D);
		MOV(CL, a);
		if (!is_eax) {
			MOV(AL, CL);
		}
		gen_sub_vec16_8<SIZE8>(b, sub);
		break;

	case SIZE16:
		MOVSX(R8D, sub);
		MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), R8D);
		MOV(CX, a);
		if (!is_eax) {
			MOV(AX, CX);
		}
		gen_sub_vec16_8<SIZE16>(b, sub);
		break;

	case SIZE32:
		MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), R8D);
		MOV(ECX, a);
		if (!is_eax) {
			MOV(EAX, ECX);
		}
		gen_sub_vec32(b);
		break;

	default:
		LIB86CPU_ABORT_msg("Invalid size_mode \"%c\" used in %s", m_cpu->size_mode, __func__);
	}

	RELOAD_RCX_CTX();
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EAX);
}

template<typename T1, typename T2>
void lc86_jit::set_flags(T1 res, T2 aux, size_t res_size)
{
	if (res_size != SIZE32) {
		if constexpr (std::is_integral_v<T1>) {
			int32_t res1 = static_cast<int32_t>(res);
			MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), res1);
		}
		else {
			MOVSX(EAX, res);
			MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), EAX);
		}
	}
	else {
		MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), res);
	}

	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), aux);
}

void
lc86_jit::ld_of(x86::Gp dst, x86::Gp aux)
{
	LEA(dst, MEMS32(aux, aux, 0));
	XOR(dst, aux);
	AND(dst, 0x80000000);
}

void
lc86_jit::ld_sf(x86::Gp res_dst, x86::Gp aux)
{
	SHR(res_dst, 0x1F);
	AND(aux, 1);
	XOR(res_dst, aux);
}

void
lc86_jit::ld_pf(x86::Gp dst, x86::Gp res, x86::Gp aux)
{
	MOV(dst, res);
	MOV(R8D, aux);
	SHR(R8, 8);
	LEA(res.r64(), MEMD64(RCX, CPU_CTX_EFLAGS_PAR));
	XOR(R8, dst.r64());
	MOVZX(dst, R8B);
	MOVZX(dst, MEMS8(dst.r64(), res.r64(), 0));
}

void
lc86_jit::load_reg(x86::Gp dst, size_t reg_offset, size_t size)
{
	switch (size)
	{
	case SIZE8:
		MOV(dst, MEMD8(RCX, reg_offset));
		break;

	case SIZE16:
		MOV(dst, MEMD16(RCX, reg_offset));
		break;

	case SIZE32:
		MOV(dst, MEMD32(RCX, reg_offset));
		break;

	default:
		LIB86CPU_ABORT();
	}
}

template<typename T>
void lc86_jit::store_reg(T val, size_t reg_offset, size_t size)
{
	switch (size)
	{
	case SIZE8:
		MOV(MEMD8(RCX, reg_offset), val);
		break;

	case SIZE16:
		MOV(MEMD16(RCX, reg_offset), val);
		break;

	case SIZE32:
		MOV(MEMD32(RCX, reg_offset), val);
		break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::load_mem(uint8_t size, uint8_t is_priv)
{
	// RCX: cpu_ctx, EDX: addr, R8: instr_eip, R9B: is_priv
	// for SIZE128/80 -> RCX: ptr to stack-allocated uint128/80_t, RDX: cpu_ctx, R8: addr, R9: instr_eip, stack: is_priv

	switch (size)
	{
	case SIZE128:
		LEA(RCX, MEMD64(RSP, LOCAL_VARS_off(0)));
		MOV(R8D, EDX);
		MOV(RDX, &m_cpu->cpu_ctx);
		MOV(R9D, m_cpu->instr_eip);
		MOV(MEMD8(RSP, LOCAL_VARS_off(2)), is_priv);
		CALL_F(&mem_read_helper<uint128_t>);
		break;

	case SIZE80:
		LEA(RCX, MEMD64(RSP, LOCAL_VARS_off(0)));
		MOV(R8D, EDX);
		MOV(RDX, &m_cpu->cpu_ctx);
		MOV(R9D, m_cpu->instr_eip);
		MOV(MEMD8(RSP, LOCAL_VARS_off(2)), is_priv);
		CALL_F(&mem_read_helper<uint80_t>);
		break;

	default:
		MOV(R9B, is_priv);
		MOV(R8D, m_cpu->instr_eip);

		switch (size)
		{
		case SIZE64:
			CALL_F(&mem_read_helper<uint64_t>);
			break;

		case SIZE32:
			CALL_F(&mem_read_helper<uint32_t>);
			break;

		case SIZE16:
			CALL_F(&mem_read_helper<uint16_t>);
			break;

		case SIZE8:
			CALL_F(&mem_read_helper<uint8_t>);
			break;

		default:
			LIB86CPU_ABORT();
		}
	}
}

template<typename T, bool dont_write>
void lc86_jit::store_mem(T val, uint8_t size, uint8_t is_priv)
{
	// RCX: cpu_ctx, EDX: addr, R8B/R8W/R8D: val, R9D: instr_eip, stack: is_priv

	MOV(MEMD32(RSP, STACK_ARGS_off), is_priv);
	MOV(R9D, m_cpu->instr_eip);

	bool is_r8 = false;
	if constexpr (!std::is_integral_v<T>) {
		if (val.id() == x86::Gp::kIdR8) {
			is_r8 = true;
		}
	}

	switch (size)
	{
	case SIZE128:
		if (!is_r8) {
			MOV(R8, val);
		}
		CALL_F((&mem_write_helper<uint128_t, dont_write>));
		break;

	case SIZE64:
		if (!is_r8) {
			MOV(R8, val);
		}
		CALL_F((&mem_write_helper<uint64_t, dont_write>));
		break;

	case SIZE32:
		if (!is_r8) {
			MOV(R8D, val);
		}
		CALL_F((&mem_write_helper<uint32_t, dont_write>));
		break;

	case SIZE16:
		if (!is_r8) {
			MOV(R8W, val);
		}
		CALL_F((&mem_write_helper<uint16_t, dont_write>));
		break;

	case SIZE8:
		if (!is_r8) {
			MOV(R8B, val);
		}
		CALL_F((&mem_write_helper<uint8_t, dont_write>));
		break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::load_io(uint8_t size_mode)
{
	// RCX: cpu_ctx, EDX: port

	MOV(R8D, m_cpu->instr_eip);

	switch (size_mode)
	{
	case SIZE32:
		CALL_F(&io_read_helper<uint32_t>);
		break;

	case SIZE16:
		CALL_F(&io_read_helper<uint16_t>);
		break;

	case SIZE8:
		CALL_F(&io_read_helper<uint8_t>);
		break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::store_io(uint8_t size_mode)
{
	// RCX: cpu_ctx, EDX: port, R8B/R8W/R8D: val

	MOV(R9D, m_cpu->instr_eip);

	switch (size_mode)
	{
	case SIZE32:
		CALL_F(&io_write_helper<uint32_t>);
		break;

	case SIZE16:
		CALL_F(&io_write_helper<uint16_t>);
		break;

	case SIZE8:
		CALL_F(&io_write_helper<uint8_t>);
		break;

	default:
		LIB86CPU_ABORT();
	}
}

template<typename T>
bool lc86_jit::gen_check_io_priv(T port)
{
	// port is either an immediate or in EDX

	static const uint8_t op_size_to_mem_size[3] = { 4, 2, 1 };

	if (((m_cpu->cpu_ctx.hflags & HFLG_CPL) > ((m_cpu->cpu_ctx.regs.eflags & IOPL_MASK) >> 12)) || (IS_VM86())) {
		Label exp = m_a.newLabel();
		LD_SEG_BASE(R10D, CPU_CTX_TR);
		LD_SEG_LIMIT(R11D, CPU_CTX_TR);
		CMP(R11D, 103);
		BR_ULT(exp);
		if constexpr (!std::is_integral_v<T>) {
			MOV(MEMD32(RSP, LOCAL_VARS_off(0)), EDX);
		}
		ADD(R10D, 102);
		MOV(EDX, R10D);
		LD_MEMs(SIZE16);
		MOVZX(EAX, AX);
		if constexpr (std::is_integral_v<T>) {
			ADD(EAX, (port >> 3) + 1);
		}
		else {
			MOV(EDX, MEMD32(RSP, LOCAL_VARS_off(0)));
			SHR(EDX, 3);
			LEA(EAX, MEMSD32(EAX, EDX, 0, 1));
		}
		CMP(EAX, R11D);
		BR_UGT(exp);
		ADD(EAX, R10D);
		MOV(EDX, EAX);
		LD_MEMs(SIZE16);
		MOVZX(EAX, AX);
		if constexpr (std::is_integral_v<T>) {
			SHR(EAX, port & 7);
		}
		else {
			MOV(EDX, MEMD32(RSP, LOCAL_VARS_off(0)));
			AND(EDX, 7);
			MOV(ECX, EDX);
			SHR(EAX, CL);
			RELOAD_RCX_CTX();
		}
		AND(EAX, (1 << op_size_to_mem_size[m_cpu->size_mode]) - 1);
		BR_NE(exp);
		Label ok = m_a.newLabel();
		BR_UNCOND(ok);
		m_a.bind(exp);
		RAISEin0_f(EXP_GP);
		m_a.bind(ok);
		return true;
	}

	return false;
}

Label
lc86_jit::rep_start(Label end)
{
	Label start = m_a.newLabel();
	if (m_cpu->addr_mode == ADDR16) {
		MOVZX(EAX, MEMD16(RCX, CPU_CTX_ECX));
	}
	else {
		LD_R32(EAX, CPU_CTX_ECX);
	}
	TEST(EAX, EAX);
	BR_EQ(end);
	m_a.bind(start);
	return start;
}

template<unsigned rep_prfx>
void lc86_jit::rep(Label start, Label end)
{
	if (m_cpu->addr_mode == ADDR16) {
		MOVZX(EAX, MEMD16(RCX, CPU_CTX_ECX));
		SUB(AX, 1);
		ST_R16(CPU_CTX_ECX, AX);
	}
	else {
		LD_R32(EAX, CPU_CTX_ECX);
		SUB(EAX, 1);
		ST_R32(CPU_CTX_ECX, EAX);
	}
	TEST(EAX, EAX);
	BR_EQ(end);
	if constexpr (rep_prfx != ZYDIS_ATTRIB_HAS_REP) {
		LD_ZF(EAX);
		TEST(EAX, EAX);
		if constexpr (rep_prfx == ZYDIS_ATTRIB_HAS_REPZ) {
			BR_NE(end);
		}
		else {
			BR_EQ(end);
		}
	}
	BR_UNCOND(start);
}

template<bool use_esp, typename... Args>
void lc86_jit::gen_stack_push(Args... pushed_args)
{
	// edx, ebx, eax are clobbered, pushed val is either a sized imm or sized reg (1st arg only, remaining in mem) -> same size of pushed val
	// when use_esp is true, the guest esp is used for the pushes, otherwise a variable in the host ebx is used

	assert(m_cpu->size_mode != SIZE8);
	static_assert(sizeof...(Args), "Cannot push zero values!");

	switch ((m_cpu->size_mode << 1) | ((m_cpu->cpu_ctx.hflags & HFLG_SS32) >> SS32_SHIFT))
	{
	case (SIZE32 << 1) | 0: { // sp, push 32
		if constexpr (use_esp) {
			LD_R16(BX, CPU_CTX_ESP);
		}
		([this, &pushed_args] {
			SUB(BX, 4);
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			MOVZX(EAX, BX);
			ADD(EDX, EAX);
			ST_MEM(pushed_args);
			}(), ...);
		if constexpr (use_esp) {
			ST_R16(CPU_CTX_ESP, BX);
		}
	}
	break;

	case (SIZE32 << 1) | 1: { // esp, push 32
		if constexpr (use_esp) {
			LD_R32(EBX, CPU_CTX_ESP);
		}
		([this, &pushed_args] {
			SUB(EBX, 4);
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			ADD(EDX, EBX);
			ST_MEM(pushed_args);
			}(), ...);
		if constexpr (use_esp) {
			ST_R32(CPU_CTX_ESP, EBX);
		}
	}
	break;

	case (SIZE16 << 1) | 0: { // sp, push 16
		if constexpr (use_esp) {
			LD_R16(BX, CPU_CTX_ESP);
		}
		([this, &pushed_args] {
			SUB(BX, 2);
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			MOVZX(EAX, BX);
			ADD(EDX, EAX);
			ST_MEM(pushed_args);
			}(), ...);
		if constexpr (use_esp) {
			ST_R16(CPU_CTX_ESP, BX);
		}
	}
	break;

	case (SIZE16 << 1) | 1: { // esp, push 16
		if constexpr (use_esp) {
			LD_R32(EBX, CPU_CTX_ESP);
		}
		([this, &pushed_args] {
			SUB(EBX, 2);
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			ADD(EDX, EBX);
			ST_MEM(pushed_args);
			}(), ...);
		if constexpr (use_esp) {
			ST_R32(CPU_CTX_ESP, EBX);
		}
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::gen_virtual_stack_push()
{
	// Currently, this is only used by the ENTER instruction to check if a stack push with the final value of (e)sp will cause a page fault

	assert(m_cpu->size_mode != SIZE8);

	switch ((m_cpu->size_mode << 1) | ((m_cpu->cpu_ctx.hflags & HFLG_SS32) >> SS32_SHIFT))
	{
	case (SIZE32 << 1) | 0: { // sp, push 32
		LD_SEG_BASE(EDX, CPU_CTX_SS);
		MOVZX(EAX, BX);
		ADD(EDX, EAX);
		ST_MEMv(0);
	}
	break;

	case (SIZE32 << 1) | 1: { // esp, push 32
		LD_SEG_BASE(EDX, CPU_CTX_SS);
		ADD(EDX, EBX);
		ST_MEMv(0);
	}
	break;

	case (SIZE16 << 1) | 0: { // sp, push 16
		LD_SEG_BASE(EDX, CPU_CTX_SS);
		MOVZX(EAX, BX);
		ADD(EDX, EAX);
		ST_MEMv(0);
	}
	break;

	case (SIZE16 << 1) | 1: { // esp, push 16
		LD_SEG_BASE(EDX, CPU_CTX_SS);
		ADD(EDX, EBX);
		ST_MEMv(0);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

template<unsigned num, unsigned store_at, bool write_esp>
void lc86_jit::gen_stack_pop()
{
	// edx, ebx, eax are clobbered, popped vals are at r11d/w (esp + 0) and on the stack (any after the first)

	assert(m_cpu->size_mode != SIZE8);
	static_assert(num, "Cannot pop zero values!");

	unsigned i = 0, stack_idx = store_at;

	switch ((m_cpu->size_mode << 1) | ((m_cpu->cpu_ctx.hflags & HFLG_SS32) >> SS32_SHIFT))
	{
	case (SIZE32 << 1 ) | 0: // sp, pop 32
		LD_R16(BX, CPU_CTX_ESP);
		for (; i < num; ++i, ++stack_idx) {
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			MOVZX(EBX, BX);
			ADD(EDX, EBX);
			LD_MEM();
			if constexpr (num == 1) {
				MOV(R11D, EAX);
			}
			else {
				MOV(MEMD32(RSP, get_local_var_offset(stack_idx)), EAX);
			}
			ADD(BX, 4);
		}
		if constexpr (write_esp) {
			ST_R16(CPU_CTX_ESP, BX);
		}
		break;

	case (SIZE32 << 1) | 1: // esp, pop 32
		LD_R32(EBX, CPU_CTX_ESP);
		for (; i < num; ++i, ++stack_idx) {
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			ADD(EDX, EBX);
			LD_MEM();
			if constexpr (num == 1) {
				MOV(R11D, EAX);
			}
			else {
				MOV(MEMD32(RSP, get_local_var_offset(stack_idx)), EAX);
			}
			ADD(EBX, 4);
		}
		if constexpr (write_esp) {
			ST_R32(CPU_CTX_ESP, EBX);
		}
		break;

	case (SIZE16 << 1) | 0: // sp, pop 16
		LD_R16(BX, CPU_CTX_ESP);
		for (; i < num; ++i, ++stack_idx) {
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			MOVZX(EBX, BX);
			ADD(EDX, EBX);
			LD_MEM();
			if constexpr (num == 1) {
				MOV(R11W, AX);
			}
			else {
				MOV(MEMD16(RSP, get_local_var_offset(stack_idx)), AX);
			}
			ADD(BX, 2);
		}
		if constexpr (write_esp) {
			ST_R16(CPU_CTX_ESP, BX);
		}
		break;

	case (SIZE16 << 1) | 1: // esp, pop 16
		LD_R32(EBX, CPU_CTX_ESP);
		for (; i < num; ++i, ++stack_idx) {
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			ADD(EDX, EBX);
			LD_MEM();
			if constexpr (num == 1) {
				MOV(R11W, AX);
			}
			else {
				MOV(MEMD16(RSP, get_local_var_offset(stack_idx)), AX);
			}
			ADD(EBX, 2);
		}
		if constexpr (write_esp) {
			ST_R32(CPU_CTX_ESP, EBX);
		}
		break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::gen_simd_mem_align_check()
{
	Label ok = m_a.newLabel();
	TEST(EDX, 15);
	BR_EQ(ok);
	RAISEin0_f(EXP_GP);
	m_a.bind(ok);
}

void
lc86_jit::gen_fpu_exp_post_check()
{
	// this function should be called immediately after the fpu instr to check exceptions for. It expects to find in R8W the flags of the status word following
	// a previous stack fault (if any happened)
	// NOTE: we only support masked exceptions for now

	Label no_exp = m_a.newLabel();
	FNSTSW(AX);
	TEST(AX, FPU_EXP_ALL);
	BR_EQ(no_exp);
	LD_R16(DX, CPU_CTX_FCTRL);
	AND(DX, FPU_EXP_ALL);
	CMP(DX, FPU_EXP_ALL);
	BR_EQ(no_exp);
	static const char *abort_msg = "Unmasked fpu exceptions are not supported";
	MOV(RCX, abort_msg);
	MOV(RAX, &cpu_runtime_abort);
	CALL(RAX); // won't return
	INT3();
	m_a.bind(no_exp);
	AND(AX, ~(FPU_FLG_SF | FPU_FLG_ES | FPU_FLG_TOP | FPU_FLG_BSY));
	OR(AX, R8W);
	ST_R16(CPU_CTX_FSTATUS, AX);
}

void
lc86_jit::gen_set_host_fpu_ctx()
{
	EMMS(); // clear fpu tag word to avoid possible fpu stack faults
	FNSTCW(MEMD16(RSP, LOCAL_VARS_off(5))); // save host control word so that we can restore it later
	FLDCW(MEMD16(RCX, FPU_DATA_FRP)); // set precision and rounding according to the guest settings (fpu exceptions are all masked)
	FNCLEX(); // clear all pending fpu exceptions, so that we can use the host to detect guest fpu exceptions
}

template<bool update_fdp>
void lc86_jit::gen_update_fpu_ptr(decoded_instr *instr)
{
	ST_R16(CPU_CTX_FCS, m_cpu->cpu_ctx.regs.cs);
	ST_R32(CPU_CTX_FIP, m_cpu->instr_eip);
	MOV(AX, MEMD16(RCX, CPU_CTX_DS));
	ST_R16(CPU_CTX_FDS, AX);
	if constexpr (update_fdp) {
		ST_R32(CPU_CTX_FDP, m_cpu->instr_eip + instr->i.raw.modrm.offset);
	}
}

template<unsigned idx>
void lc86_jit::shift(decoded_instr *instr)
{
	// idx 0 -> shl, 1 -> shr, 2 -> sar

	std::optional<uint64_t> imm_count;
	switch (instr->i.opcode)
	{
	case 0xD2:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xD3:
		LD_R8L(R9B, CPU_CTX_ECX);
		AND(R9B, 0x1F);
		break;

	case 0xD0:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xD1:
		imm_count = 1;
		break;

	case 0xC0:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xC1:
		imm_count = instr->o[OPNUM_SRC].imm.value.u & 0x1F;
		break;

	default:
		LIB86CPU_ABORT();
	}

	if (imm_count) {
		if (*imm_count > 0) {
			get_rm<OPNUM_DST>(instr,
				[this, &imm_count](const op_info rm)
				{
					auto dst_host_reg = SIZED_REG(x64::rax, rm.bits);
					LD_REG_val(dst_host_reg, rm.val, rm.bits);
					if constexpr (idx == 0) {
						SHL(dst_host_reg, (*imm_count) & 0x1F);
					}
					else if constexpr (idx == 1) {
						SHR(dst_host_reg, (*imm_count) & 0x1F);
					}
					else if constexpr (idx == 2) {
						SAR(dst_host_reg, (*imm_count) & 0x1F);
					}
					else {
						LIB86CPU_ABORT_msg("Unknown shift operation specified with index of %u", idx);
					}
					SETC(BL);
					SETO(DL);
					MOVZX(EBX, BL);
					MOVZX(EDX, DL);
					XOR(EDX, EBX);
					ADD(EBX, EBX);
					OR(EBX, EDX);
					SHL(EBX, 0x1E);
					ST_REG_val(dst_host_reg, rm.val, rm.bits);
					set_flags(dst_host_reg, EBX, rm.bits);
				},
				[this, &imm_count](const op_info rm)
				{
					auto dst_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
					MOV(EBX, EDX);
					LD_MEM();
					if constexpr (idx == 0) {
						SHL(dst_host_reg, (*imm_count) & 0x1F);
					}
					else if constexpr (idx == 1) {
						SHR(dst_host_reg, (*imm_count) & 0x1F);
					}
					else if constexpr (idx == 2) {
						SAR(dst_host_reg, (*imm_count) & 0x1F);
					}
					else {
						LIB86CPU_ABORT_msg("Unknown shift operation specified with index of %u", idx);
					}
					MOV(MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode), dst_host_reg);
					auto dst2_host_reg = SIZED_REG(x64::r10, m_cpu->size_mode);
					MOV(dst2_host_reg, dst_host_reg);
					MOV(EDX, EBX);
					SETC(BL);
					SETO(AL);
					MOVZX(EBX, BL);
					MOVZX(EAX, AL);
					XOR(EAX, EBX);
					ADD(EBX, EBX);
					OR(EBX, EAX);
					SHL(EBX, 0x1E);
					ST_MEM(dst2_host_reg);
					MOV(dst_host_reg, MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode));
					set_flags(dst_host_reg, EBX, m_cpu->size_mode);
				});
		}
	}
	else {
		Label nop = m_a.newLabel();
		CMP(R9B, 0);
		BR_EQ(nop);
		get_rm<OPNUM_DST>(instr,
			[this](const op_info rm)
			{
				auto dst_host_reg = SIZED_REG(x64::rax, rm.bits);
				LD_REG_val(dst_host_reg, rm.val, rm.bits);
				MOV(CL, R9B);
				if constexpr (idx == 0) {
					SHL(dst_host_reg, CL);
				}
				else if constexpr (idx == 1) {
					SHR(dst_host_reg, CL);
				}
				else if constexpr (idx == 2) {
					SAR(dst_host_reg, CL);
				}
				else {
					LIB86CPU_ABORT_msg("Unknown shift operation specified with index of %u", idx);
				}
				RELOAD_RCX_CTX();
				SETC(BL);
				SETO(DL);
				MOVZX(EBX, BL);
				MOVZX(EDX, DL);
				XOR(EDX, EBX);
				ADD(EBX, EBX);
				OR(EBX, EDX);
				SHL(EBX, 0x1E);
				ST_REG_val(dst_host_reg, rm.val, rm.bits);
				set_flags(dst_host_reg, EBX, rm.bits);
			},
			[this](const op_info rm)
			{
				auto dst_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
				MOV(EBX, EDX);
				MOV(MEMD8(RSP, LOCAL_VARS_off(0)), R9B);
				LD_MEM();
				MOV(CL, MEMD8(RSP, LOCAL_VARS_off(0)));
				if constexpr (idx == 0) {
					SHL(dst_host_reg, CL);
				}
				else if constexpr (idx == 1) {
					SHR(dst_host_reg, CL);
				}
				else if constexpr (idx == 2) {
					SAR(dst_host_reg, CL);
				}
				else {
					LIB86CPU_ABORT_msg("Unknown shift operation specified with index %u", idx);
				}
				MOV(MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode), dst_host_reg);
				auto dst2_host_reg = SIZED_REG(x64::r10, m_cpu->size_mode);
				MOV(dst2_host_reg, dst_host_reg);
				MOV(EDX, EBX);
				RELOAD_RCX_CTX();
				SETC(BL);
				SETO(AL);
				MOVZX(EBX, BL);
				MOVZX(EAX, AL);
				XOR(EAX, EBX);
				ADD(EBX, EBX);
				OR(EBX, EAX);
				SHL(EBX, 0x1E);
				ST_MEM(dst2_host_reg);
				MOV(dst_host_reg, MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode));
				set_flags(dst_host_reg, EBX, m_cpu->size_mode);
			});
		m_a.bind(nop);
	}
}

template<unsigned idx>
void lc86_jit::double_shift(decoded_instr *instr)
{
	// idx 0 -> shld, 1 -> shrd

	std::optional<uint64_t> imm_count;
	switch (instr->i.opcode)
	{
	case 0xA4:
	case 0xAC:
		imm_count = instr->o[OPNUM_THIRD].imm.value.u & 0x1F;
		break;

	case 0xA5:
	case 0xAD:
		LD_R8L(R9B, CPU_CTX_ECX);
		AND(R9B, 0x1F);
		break;

	default:
		LIB86CPU_ABORT();
	}

	auto src = GET_REG(OPNUM_SRC);
	if (imm_count) {
		if (*imm_count > 0) {
			get_rm<OPNUM_DST>(instr,
				[this, &imm_count, src](const op_info rm)
				{
					auto dst_host_reg = SIZED_REG(x64::rax, rm.bits);
					auto src_host_reg = SIZED_REG(x64::rbx, rm.bits);
					LD_REG_val(dst_host_reg, rm.val, rm.bits);
					LD_REG_val(src_host_reg, src.val, src.bits);
					if constexpr (idx == 0) {
						SHLD(dst_host_reg, src_host_reg, *imm_count);
					}
					else if constexpr (idx == 1) {
						SHRD(dst_host_reg, src_host_reg, *imm_count);
					}
					else {
						LIB86CPU_ABORT_msg("Unknown double shift operation specified with index of %u", idx);
					}
					SETC(BL);
					SETO(DL);
					MOVZX(EBX, BL);
					MOVZX(EDX, DL);
					XOR(EDX, EBX);
					ADD(EBX, EBX);
					OR(EBX, EDX);
					SHL(EBX, 0x1E);
					ST_REG_val(dst_host_reg, rm.val, rm.bits);
					set_flags(dst_host_reg, EBX, rm.bits);
				},
				[this, &imm_count, src](const op_info rm)
				{
					auto dst_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
					auto src_host_reg = SIZED_REG(x64::rbx, m_cpu->size_mode);
					MOV(EBX, EDX);
					LD_MEM();
					MOV(EDX, EBX);
					LD_REG_val(src_host_reg, src.val, src.bits);
					if constexpr (idx == 0) {
						SHLD(dst_host_reg, src_host_reg, *imm_count);
					}
					else if constexpr (idx == 1) {
						SHRD(dst_host_reg, src_host_reg, *imm_count);
					}
					else {
						LIB86CPU_ABORT_msg("Unknown double shift operation specified with index of %u", idx);
					}
					MOV(MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode), dst_host_reg);
					auto dst2_host_reg = SIZED_REG(x64::r10, m_cpu->size_mode);
					MOV(dst2_host_reg, dst_host_reg);
					SETC(BL);
					SETO(AL);
					MOVZX(EBX, BL);
					MOVZX(EAX, AL);
					XOR(EAX, EBX);
					ADD(EBX, EBX);
					OR(EBX, EAX);
					SHL(EBX, 0x1E);
					ST_MEM(dst2_host_reg);
					MOV(dst_host_reg, MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode));
					set_flags(dst_host_reg, EBX, m_cpu->size_mode);
				});
		}
	}
	else {
		Label nop = m_a.newLabel();
		CMP(R9B, 0);
		BR_EQ(nop);
		get_rm<OPNUM_DST>(instr,
			[this, src](const op_info rm)
			{
				auto dst_host_reg = SIZED_REG(x64::rax, rm.bits);
				auto src_host_reg = SIZED_REG(x64::rbx, rm.bits);
				LD_REG_val(dst_host_reg, rm.val, rm.bits);
				LD_REG_val(src_host_reg, src.val, src.bits);
				MOV(CL, R9B);
				if constexpr (idx == 0) {
					SHLD(dst_host_reg, src_host_reg, CL);
				}
				else if constexpr (idx == 1) {
					SHRD(dst_host_reg, src_host_reg, CL);
				}
				else {
					LIB86CPU_ABORT_msg("Unknown double shift operation specified with index of %u", idx);
				}
				RELOAD_RCX_CTX();
				SETC(BL);
				SETO(DL);
				MOVZX(EBX, BL);
				MOVZX(EDX, DL);
				XOR(EDX, EBX);
				ADD(EBX, EBX);
				OR(EBX, EDX);
				SHL(EBX, 0x1E);
				ST_REG_val(dst_host_reg, rm.val, rm.bits);
				set_flags(dst_host_reg, EBX, rm.bits);
			},
			[this, src](const op_info rm)
			{
				auto dst_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
				auto src_host_reg = SIZED_REG(x64::rbx, m_cpu->size_mode);
				MOV(EBX, EDX);
				MOV(MEMD8(RSP, LOCAL_VARS_off(0)), R9B);
				LD_MEM();
				MOV(EDX, EBX);
				LD_REG_val(src_host_reg, src.val, src.bits);
				MOV(CL, MEMD8(RSP, LOCAL_VARS_off(0)));
				if constexpr (idx == 0) {
					SHLD(dst_host_reg, src_host_reg, CL);
				}
				else if constexpr (idx == 1) {
					SHRD(dst_host_reg, src_host_reg, CL);
				}
				else {
					LIB86CPU_ABORT_msg("Unknown double shift operation specified with index of %u", idx);
				}
				MOV(MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode), dst_host_reg);
				auto dst2_host_reg = SIZED_REG(x64::r10, m_cpu->size_mode);
				MOV(dst2_host_reg, dst_host_reg);
				RELOAD_RCX_CTX();
				SETC(BL);
				SETO(AL);
				MOVZX(EBX, BL);
				MOVZX(EAX, AL);
				XOR(EAX, EBX);
				ADD(EBX, EBX);
				OR(EBX, EAX);
				SHL(EBX, 0x1E);
				ST_MEM(dst2_host_reg);
				MOV(dst_host_reg, MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode));
				set_flags(dst_host_reg, EBX, m_cpu->size_mode);
			});
		m_a.bind(nop);
	}
}

template<unsigned idx>
void lc86_jit::rotate(decoded_instr *instr)
{
	// idx 0 -> rcl, 1 -> rcr, 2 -> rol, 3 -> ror

	std::optional<uint64_t> imm_count;
	switch (instr->i.opcode)
	{
	case 0xD2:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xD3:
		LD_R8L(R9B, CPU_CTX_ECX);
		AND(R9B, 0x1F);
		break;

	case 0xD0:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xD1:
		imm_count = 1;
		break;

	case 0xC0:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xC1:
		imm_count = instr->o[OPNUM_SRC].imm.value.u & 0x1F;
		break;

	default:
		LIB86CPU_ABORT();
	}

	if (imm_count) {
		if (*imm_count > 0) {
			get_rm<OPNUM_DST>(instr,
				[this, &imm_count](const op_info rm)
				{
					auto dst_host_reg = SIZED_REG(x64::rax, rm.bits);
					LD_REG_val(dst_host_reg, rm.val, rm.bits);
					if constexpr ((idx == 0) || (idx == 1)) {
						Label clear_cf = m_a.newLabel();
						Label rot = m_a.newLabel();
						LD_CF(EDX);
						TEST(EDX, EDX);
						BR_EQ(clear_cf);
						STC();
						BR_UNCOND(rot);
						m_a.bind(clear_cf);
						CLC();
						m_a.bind(rot);
						if constexpr (idx == 0) {
							RCL(dst_host_reg, *imm_count);
						}
						else {
							RCR(dst_host_reg, *imm_count);
						}
					}
					else if constexpr (idx == 2) {
						ROL(dst_host_reg, *imm_count);
					}
					else if constexpr (idx == 3) {
						ROR(dst_host_reg, *imm_count);
					}
					else {
						LIB86CPU_ABORT_msg("Unknown rotate operation specified with index of %u", idx);
					}
					SETC(BL);
					SETO(DL);
					MOVZX(EBX, BL);
					MOVZX(EDX, DL);
					XOR(EDX, EBX);
					ADD(EBX, EBX);
					OR(EBX, EDX);
					SHL(EBX, 0x1E);
					ST_REG_val(dst_host_reg, rm.val, rm.bits);
					MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
					AND(EAX, 0x3FFFFFFF);
					OR(EAX, EBX);
					MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EAX);
				},
				[this, &imm_count](const op_info rm)
				{
					auto dst_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
					MOV(EBX, EDX);
					LD_MEM();
					if constexpr ((idx == 0) || (idx == 1)) {
						Label clear_cf = m_a.newLabel();
						Label rot = m_a.newLabel();
						LD_CF(EDX);
						TEST(EDX, EDX);
						BR_EQ(clear_cf);
						STC();
						BR_UNCOND(rot);
						m_a.bind(clear_cf);
						CLC();
						m_a.bind(rot);
						if constexpr (idx == 0) {
							RCL(dst_host_reg, *imm_count);
						}
						else {
							RCR(dst_host_reg, *imm_count);
						}
					}
					else if constexpr (idx == 2) {
						ROL(dst_host_reg, *imm_count);
					}
					else if constexpr (idx == 3) {
						ROR(dst_host_reg, *imm_count);
					}
					else {
						LIB86CPU_ABORT_msg("Unknown rotate operation specified with index of %u", idx);
					}
					auto dst2_host_reg = SIZED_REG(x64::r10, m_cpu->size_mode);
					MOV(dst2_host_reg, dst_host_reg);
					MOV(EDX, EBX);
					SETC(BL);
					SETO(AL);
					MOVZX(EBX, BL);
					MOVZX(EAX, AL);
					XOR(EAX, EBX);
					ADD(EBX, EBX);
					OR(EBX, EAX);
					SHL(EBX, 0x1E);
					ST_MEM(dst2_host_reg);
					MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
					AND(EAX, 0x3FFFFFFF);
					OR(EAX, EBX);
					MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EAX);
				});
		}
	}
	else {
		Label nop = m_a.newLabel();
		CMP(R9B, 0);
		BR_EQ(nop);
		get_rm<OPNUM_DST>(instr,
			[this](const op_info rm)
			{
				auto dst_host_reg = SIZED_REG(x64::rax, rm.bits);
				LD_REG_val(dst_host_reg, rm.val, rm.bits);
				if constexpr ((idx == 0) || (idx == 1)) {
					Label clear_cf = m_a.newLabel();
					Label rot = m_a.newLabel();
					LD_CF(EDX);
					TEST(EDX, EDX);
					BR_EQ(clear_cf);
					STC();
					BR_UNCOND(rot);
					m_a.bind(clear_cf);
					CLC();
					m_a.bind(rot);
					MOV(CL, R9B);
					if constexpr (idx == 0) {
						RCL(dst_host_reg, CL);
					}
					else {
						RCR(dst_host_reg, CL);
					}
				}
				else if constexpr (idx == 2) {
					MOV(CL, R9B);
					ROL(dst_host_reg, CL);
				}
				else if constexpr (idx == 3) {
					MOV(CL, R9B);
					ROR(dst_host_reg, CL);
				}
				else {
					LIB86CPU_ABORT_msg("Unknown rotate operation specified with index of %u", idx);
				}
				RELOAD_RCX_CTX();
				SETC(BL);
				SETO(DL);
				MOVZX(EBX, BL);
				MOVZX(EDX, DL);
				XOR(EDX, EBX);
				ADD(EBX, EBX);
				OR(EBX, EDX);
				SHL(EBX, 0x1E);
				ST_REG_val(dst_host_reg, rm.val, rm.bits);
				MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
				AND(EAX, 0x3FFFFFFF);
				OR(EAX, EBX);
				MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EAX);
			},
			[this](const op_info rm)
			{
				auto dst_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
				MOV(EBX, EDX);
				MOV(MEMD8(RSP, LOCAL_VARS_off(0)), R9B);
				LD_MEM();
				if constexpr ((idx == 0) || (idx == 1)) {
					Label clear_cf = m_a.newLabel();
					Label rot = m_a.newLabel();
					LD_CF(EDX);
					TEST(EDX, EDX);
					BR_EQ(clear_cf);
					STC();
					BR_UNCOND(rot);
					m_a.bind(clear_cf);
					CLC();
					m_a.bind(rot);
					MOV(CL, MEMD8(RSP, LOCAL_VARS_off(0)));
					if constexpr (idx == 0) {
						RCL(dst_host_reg, CL);
					}
					else {
						RCR(dst_host_reg, CL);
					}
				}
				else if constexpr (idx == 2) {
					MOV(CL, MEMD8(RSP, LOCAL_VARS_off(0)));
					ROL(dst_host_reg, CL);
				}
				else if constexpr (idx == 3) {
					MOV(CL, MEMD8(RSP, LOCAL_VARS_off(0)));
					ROR(dst_host_reg, CL);
				}
				else {
					LIB86CPU_ABORT_msg("Unknown rotate operation specified with index of %u", idx);
				}
				auto dst2_host_reg = SIZED_REG(x64::r10, m_cpu->size_mode);
				MOV(dst2_host_reg, dst_host_reg);
				MOV(EDX, EBX);
				RELOAD_RCX_CTX();
				SETC(BL);
				SETO(AL);
				MOVZX(EBX, BL);
				MOVZX(EAX, AL);
				XOR(EAX, EBX);
				ADD(EBX, EBX);
				OR(EBX, EAX);
				SHL(EBX, 0x1E);
				ST_MEM(dst2_host_reg);
				MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
				AND(EAX, 0x3FFFFFFF);
				OR(EAX, EBX);
				MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EAX);
			});
		m_a.bind(nop);
	}
}

template<unsigned idx>
void lc86_jit::load_sys_seg_reg(decoded_instr *instr)
{
	switch (idx)
	{
	case GDTR_idx:
		assert(instr->i.raw.modrm.reg == 2);
		break;

	case IDTR_idx:
		assert(instr->i.raw.modrm.reg == 3);
		break;

	case LDTR_idx:
		assert(instr->i.raw.modrm.reg == 2);
		break;

	case TR_idx:
		assert(instr->i.raw.modrm.reg == 3);
		break;

	default:
		LIB86CPU_ABORT_msg("Unknown selector specified with index %u", idx);
	}

	if constexpr ((idx == GDTR_idx) || (idx == IDTR_idx)) {
		if (m_cpu->cpu_ctx.hflags & HFLG_CPL) {
			RAISEin0_t(EXP_GP);
			return;
		}

		get_rm<OPNUM_SINGLE>(instr,
			[](const op_info rm)
			{
				assert(0);
			},
			[this](const op_info rm)
			{
				MOV(EBX, EDX);
				LD_MEMs(SIZE16);
				ADD(EBX, 2);
				MOV(EDX, EBX);
				MOVZX(EBX, AX);
				LD_MEMs(SIZE32);
			});

		if (m_cpu->size_mode == SIZE16) {
			AND(EAX, 0x00FFFFFF);
		}

		if constexpr (idx == IDTR_idx) {
			ST_SEG_BASE(CPU_CTX_IDTR, EAX);
			ST_SEG_LIMIT(CPU_CTX_IDTR, EBX);

			if (m_cpu->cpu_flags & CPU_DBG_PRESENT) {
				// hook the breakpoint exception handler so that the debugger can catch it
				CALL_F(&dbg_update_exp_hook);
			}
		}
		else {
			ST_SEG_BASE(CPU_CTX_GDTR, EAX);
			ST_SEG_LIMIT(CPU_CTX_GDTR, EBX);
		}
	}
	else {
		uint32_t is_vm86 = IS_VM86();
		if (is_vm86 | (m_cpu->cpu_ctx.hflags & HFLG_CPL)) {
			RAISEin0_t(is_vm86 ? EXP_UD : EXP_GP);
			return;
		}

		get_rm<OPNUM_SINGLE>(instr,
			[this](const op_info rm)
			{
				LD_R16(AX, rm.val);
			},
			[this](const op_info rm)
			{
				LD_MEMs(SIZE16);
			});

		Label ok = m_a.newLabel();
		MOV(R8D, m_cpu->instr_eip);
		MOV(DX, AX);
		if constexpr (idx == LDTR_idx) {
			CALL_F(&lldt_helper);
		}
		else {
			CALL_F(&ltr_helper);
		}
		TEST(EAX, EAX);
		BR_EQ(ok);
		RAISEin_no_param_f();
		m_a.bind(ok);
	}
}

template<unsigned idx>
void lc86_jit::store_sys_seg_reg(decoded_instr *instr)
{
	switch (idx)
	{
	case GDTR_idx:
		assert(instr->i.raw.modrm.reg == 0);
		break;

	case LDTR_idx:
		assert(instr->i.raw.modrm.reg == 0);
		break;

	case IDTR_idx:
		assert(instr->i.raw.modrm.reg == 1);
		break;

	case TR_idx:
		assert(instr->i.raw.modrm.reg == 1);
		break;

	default:
		LIB86CPU_ABORT_msg("Unknown selector specified with index %u", idx);
	}

	const auto &gp_exp_check = [this]() {
		if (m_cpu->cpu_ctx.hflags & HFLG_CPL) {
			Label ok = m_a.newLabel();
			LD_R32(EAX, CPU_CTX_CR4);
			AND(EAX, CR4_UMIP_MASK);
			TEST(EAX, EAX);
			BR_EQ(ok);
			RAISEin0_f(EXP_GP);
			m_a.bind(ok);
		}
	};

	if constexpr ((idx == GDTR_idx) || (idx == IDTR_idx)) {
		gp_exp_check();

		get_rm<OPNUM_SINGLE>(instr,
			[](const op_info rm)
			{
				assert(0);
			},
			[this](const op_info rm)
			{
				constexpr auto seg_offset = idx == GDTR_idx ? CPU_CTX_GDTR : CPU_CTX_IDTR;
				MOV(EBX, EDX);
				MOV(AX, MEMD16(RCX, seg_offset + seg_limit_offset));
				ST_MEMs(AX, SIZE16);
				ADD(EBX, 2);
				MOV(EDX, EBX);
				LD_SEG_BASE(EAX, seg_offset);
				ST_MEMs(EAX, SIZE32);
			});
	}
	else if constexpr ((idx == TR_idx) || (idx == LDTR_idx)) {
		if (IS_VM86()) {
			RAISEin0_t(EXP_UD);
			return;
		}

		gp_exp_check();

		constexpr auto seg_offset = idx == TR_idx ? CPU_CTX_TR : CPU_CTX_LDTR;
		get_rm<OPNUM_SINGLE>(instr,
			[this](const op_info rm)
			{
				MOVZX(EAX, MEMD16(RCX, seg_offset));
				ST_R32(rm.val, EAX);
			},
			[this](const op_info rm)
			{
				MOV(AX, MEMD16(RCX, seg_offset));
				ST_MEMs(AX, SIZE16);
			});
	}
	else {
		LIB86CPU_ABORT_msg("Unknown selector specified with index %u", idx);
	}
}

template<bool is_verr>
void lc86_jit::verx(decoded_instr *instr)
{
	assert(instr->o[OPNUM_SINGLE].size == 16);

	if (IS_VM86()) {
		RAISEin0_t(EXP_UD);
		return;
	}

	get_rm<OPNUM_SINGLE>(instr,
		[this](const op_info rm)
		{
			LD_R16(AX, rm.val);
		},
		[this](const op_info rm)
		{
			LD_MEMs(SIZE16);
		});

	MOV(R8D, m_cpu->instr_eip);
	MOV(DX, AX);
	if constexpr (is_verr) {
		CALL_F(&verrw_helper<true>);
	}
	else {
		CALL_F(&verrw_helper<false>);
	}
}

template<unsigned idx>
void lc86_jit::lxs(decoded_instr *instr)
{
	auto dst = GET_REG(OPNUM_DST);
	auto offset_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
	auto rbx_host_reg = SIZED_REG(x64::rbx, m_cpu->size_mode);
	get_rm<OPNUM_SRC>(instr,
		[](const op_info rm)
		{
			assert(0);
		},
		[this](const op_info rm)
		{
			MOV(EBX, EDX);
			LD_MEM();
		});
	ADD(EBX, 1 << m_cpu->size_mode);
	MOV(EDX, EBX);
	MOV(rbx_host_reg, offset_host_reg);
	LD_MEMs(SIZE16);

	if (IS_PE_NOT_VM86()) {
		MOV(R8D, m_cpu->instr_eip);
		MOV(DX, AX);

		switch (idx)
		{
		case SS_idx:
			CALL_F(&mov_sel_pe_helper<SS_idx>);
			break;

		case FS_idx:
			CALL_F(&mov_sel_pe_helper<FS_idx>);
			break;

		case GS_idx:
			CALL_F(&mov_sel_pe_helper<GS_idx>);
			break;

		case ES_idx:
			CALL_F(&mov_sel_pe_helper<ES_idx>);
			break;

		case DS_idx:
			CALL_F(&mov_sel_pe_helper<DS_idx>);
			break;

		default:
			LIB86CPU_ABORT();
		}

		Label ok = m_a.newLabel();
		TEST(EAX, EAX);
		BR_EQ(ok);
		RAISEin_no_param_f();
		m_a.bind(ok);
		ST_REG_val(rbx_host_reg, dst.val, dst.bits);

		if constexpr (idx == SS_idx) {
			ST_R32(CPU_CTX_EIP, m_cpu->instr_eip + m_cpu->instr_bytes);

			gen_link_dst_cond([this] {
				MOV(EBX, MEMD32(RCX, CPU_CTX_HFLG));
				TEST(EBX, HFLG_SS32);
				});
			m_cpu->translate_next = 0;
		}
	}
	else {
		size_t seg_offset = get_reg_offset(instr->o[OPNUM_THIRD].reg.value);
		ST_SEG(seg_offset, AX);
		MOVZX(EAX, AX);
		SHL(EAX, 4);
		ST_SEG_BASE(seg_offset, EAX);
		ST_REG_val(rbx_host_reg, dst.val, dst.bits);
	}
}

template<unsigned idx>
void lc86_jit::bit(decoded_instr *instr)
{
	// idx 0 -> bt, 1 -> btc, 2 -> btr, 3 -> bts

	auto lambda = [this]<bool is_reg, typename T1, typename T2>(T1 src, T2 dst, const op_info op_dst)
	{
		switch (idx)
		{
		case 0:
			BT(dst, src);
			break;

		case 1:
			BTC(dst, src);
			break;

		case 2:
			BTR(dst, src);
			break;

		case 3:
			BTS(dst, src);
			break;

		default:
			LIB86CPU_ABORT_msg("Unknown bit operation specified with index %u", idx);
		}

		SETC(BL);
		if constexpr (idx != 0) {
			if constexpr (is_reg) {
				ST_REG_val(dst, op_dst.val, op_dst.bits);
			}
			else {
				auto dst_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
				MOV(dst_host_reg, dst);
				ST_MEM(dst_host_reg);
			}
		}
	};

	get_rm<OPNUM_DST>(instr,
		[this, instr, &lambda](const op_info rm)
		{
			auto dst_host_reg = SIZED_REG(x64::rax, rm.bits);
			LD_REG_val(dst_host_reg, rm.val, rm.bits);
			if (instr->i.opcode != 0xBA) {
				auto src = GET_REG(OPNUM_SRC);
				auto src_host_reg = SIZED_REG(x64::rbx, src.bits);
				LD_REG_val(src_host_reg, src.val, src.bits);
				lambda.template operator()<true>(src_host_reg, dst_host_reg, rm);
			}
			else {
				lambda.template operator()<true>(GET_IMM(), dst_host_reg, rm);
			}
		},
		[this, instr, &lambda](const op_info rm)
		{
			auto dst_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
			MOV(EBX, EDX);
			LD_MEM();
			MOV(EDX, EBX);
			auto dst_mem = MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode);
			MOV(dst_mem, dst_host_reg);
			if (instr->i.opcode != 0xBA) {
				auto src = GET_REG(OPNUM_SRC);
				auto src_host_reg = SIZED_REG(x64::rbx, src.bits);
				LD_REG_val(src_host_reg, src.val, src.bits);
				lambda.template operator()<false>(src_host_reg, dst_mem, rm);
			}
			else {
				lambda.template operator()<false>(GET_IMM(), dst_mem, rm);
			}
		});

	MOVZX(EBX, BL);
	SHL(EBX, 0x1F);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EBX);
}

template<unsigned idx>
void lc86_jit::int_(decoded_instr *instr)
{
	// idx 1 -> int3, 2 -> int n, 3 -> into

	if constexpr (idx == 3) {
		Label no_exp = m_a.newLabel();
		MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EDX, EAX);
		TEST(EDX, EDX);
		BR_EQ(no_exp);
		MOV(MEMD32(RCX, CPU_EXP_ADDR), 0);
		MOV(MEMD16(RCX, CPU_EXP_CODE), 0);
		MOV(MEMD16(RCX, CPU_EXP_IDX), EXP_OF);
		MOV(MEMD32(RCX, CPU_EXP_EIP), m_cpu->instr_eip + m_cpu->instr_bytes);
		MOV(RAX, &cpu_raise_exception<idx>);
		CALL(RAX);
		gen_epilogue_main<false>();
		m_a.bind(no_exp);
	}
	else {
		MOV(MEMD32(RCX, CPU_EXP_ADDR), 0);
		MOV(MEMD16(RCX, CPU_EXP_CODE), 0);
		if constexpr (idx == 1) {
			MOV(MEMD16(RCX, CPU_EXP_IDX), EXP_BP);
		}
		else if constexpr (idx == 2) {
			MOV(MEMD16(RCX, CPU_EXP_IDX), static_cast<uint8_t>(instr->o[OPNUM_SINGLE].imm.value.u));
		}
		else {
			LIB86CPU_ABORT_msg("Unknown int instruction specified with index %u", idx);
		}

		MOV(MEMD32(RCX, CPU_EXP_EIP), m_cpu->instr_eip + m_cpu->instr_bytes);
		MOV(RAX, &cpu_raise_exception<idx>);
		CALL(RAX);
		gen_epilogue_main<false>();

		m_needs_epilogue = false;
		m_cpu->translate_next = 0;
	}
}

void
lc86_jit::aaa(decoded_instr *instr)
{
	Label al = m_a.newLabel();
	Label add = m_a.newLabel();
	Label no_add = m_a.newLabel();
	LD_R16(AX, CPU_CTX_EAX);
	MOV(DX, AX);
	AND(DX, 0xF);
	CMP(DL, 9);
	BR_UGT(add);
	LD_AF(EBX);
	CMP(EBX, 0);
	BR_EQ(no_add);
	m_a.bind(add);
	ADD(AX, 0x106);
	MOV(DX, AX);
	AND(DL, 0xF);
	ST_R16(CPU_CTX_EAX, AX);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), 0x80000008);
	BR_UNCOND(al);
	m_a.bind(no_add);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), 0);
	m_a.bind(al);
	ST_R8L(CPU_CTX_EAX, DL);
}

void
lc86_jit::aad(decoded_instr *instr)
{
	LD_R8L(BL, CPU_CTX_EAX);
	LD_R8H(DL, CPU_CTX_EAX);
	MOV(EAX, instr->o[OPNUM_SINGLE].imm.value.u);
	MOVZX(EDX, DL);
	IMUL2(EDX, EAX);
	ADD(DL, BL);
	ST_R8L(CPU_CTX_EAX, DL);
	ST_R8H(CPU_CTX_EAX, 0);
	MOVSX(EDX, DL);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), EDX);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), 0);
}

void
lc86_jit::aam(decoded_instr *instr)
{
	if (instr->o[OPNUM_SINGLE].imm.value.u == 0) {
		RAISEin0_t(EXP_DE);
	}
	else {
		MOVZX(EAX, MEMD8(RCX, CPU_CTX_EAX));
		XOR(EDX, EDX);
		MOV(EBX, instr->o[OPNUM_SINGLE].imm.value.u);
		DIV(EBX);
		ST_R8L(CPU_CTX_EAX, DL);
		ST_R8H(CPU_CTX_EAX, AL);
		MOVSX(EDX, DL);
		MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), EDX);
		MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), 0);
	}
}

void
lc86_jit::aas(decoded_instr *instr)
{
	Label al = m_a.newLabel();
	Label sub = m_a.newLabel();
	Label no_sub = m_a.newLabel();
	LD_R16(BX, CPU_CTX_EAX);
	MOV(AX, BX);
	AND(AX, 0xF);
	CMP(AL, 9);
	BR_UGT(sub);
	LD_AF(EDX);
	CMP(EDX, 0);
	BR_EQ(no_sub);
	m_a.bind(sub);
	MOV(EAX, 0xFFFA);
	MOV(EDX, 0xFF);
	ADD(BX, AX);
	MOVZX(EAX, BX);
	AND(BX, DX);
	SHR(AX, 8);
	DEC(AL);
	MOVZX(EAX, AL);
	SHL(AX, 8);
	OR(AX, BX);
	ST_R16(CPU_CTX_EAX, AX);
	AND(AL, 0xF);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), 0x80000008);
	BR_UNCOND(al);
	m_a.bind(no_sub);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), 0);
	m_a.bind(al);
	ST_R8L(CPU_CTX_EAX, AL);
}

void
lc86_jit::adc(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x10:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x11: {
		r_to_rm_flags<true>(instr,
			[this](x86::Gp sum_host_reg, x86::Gp src_host_reg)
			{
				auto cf_host_reg = SIZED_REG(x64::r9, m_cpu->size_mode);
				LD_CF(R9D);
				SHR(R9D, 31);
				ADD(sum_host_reg, src_host_reg);
				ADD(sum_host_reg, cf_host_reg);
			});
	}
	break;

	case 0x12:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x13: {
		rm_to_r_flags<true>(instr,
			[this](x86::Gp sum_host_reg, x86::Gp src_host_reg)
			{
				auto cf_host_reg = SIZED_REG(x64::r9, m_cpu->size_mode);
				LD_CF(R9D);
				SHR(R9D, 31);
				ADD(sum_host_reg, src_host_reg);
				ADD(sum_host_reg, cf_host_reg);
			});
	}
	break;

	case 0x14:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x15: {
		imm_to_eax_flags<true>(instr,
			[this](x86::Gp sum_host_reg, uint32_t src_imm)
			{
				auto cf_host_reg = SIZED_REG(x64::r9, m_cpu->size_mode);
				LD_CF(R9D);
				SHR(R9D, 31);
				ADD(sum_host_reg, src_imm);
				ADD(sum_host_reg, cf_host_reg);
			});
	}
	break;

	case 0x80:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x81: {
		assert(instr->i.raw.modrm.reg == 2);

		uint32_t src_imm = GET_IMM();
		imm_to_rm_flags<true, uint32_t>(instr, src_imm,
			[this](x86::Gp sum_host_reg, uint32_t src_imm)
			{
				auto cf_host_reg = SIZED_REG(x64::r9, m_cpu->size_mode);
				LD_CF(R9D);
				SHR(R9D, 31);
				ADD(sum_host_reg, src_imm);
				ADD(sum_host_reg, cf_host_reg);
			});
	}
	break;

	case 0x83: {
		assert(instr->i.raw.modrm.reg == 2);

		if (m_cpu->size_mode == SIZE16) {
			int16_t src_imm = static_cast<int16_t>(static_cast<int8_t>(GET_IMM()));
			imm_to_rm_flags<true, int16_t>(instr, src_imm,
				[this](x86::Gp sum_host_reg, int16_t src_imm)
				{
					auto cf_host_reg = SIZED_REG(x64::r9, m_cpu->size_mode);
					LD_CF(R9D);
					SHR(R9D, 31);
					ADD(sum_host_reg, src_imm);
					ADD(sum_host_reg, cf_host_reg);
				});
		}
		else {
			int32_t src_imm = static_cast<int32_t>(static_cast<int8_t>(GET_IMM()));
			imm_to_rm_flags<true, int32_t>(instr, src_imm,
				[this](x86::Gp sum_host_reg, int32_t src_imm)
				{
					auto cf_host_reg = SIZED_REG(x64::r9, m_cpu->size_mode);
					LD_CF(R9D);
					SHR(R9D, 31);
					ADD(sum_host_reg, src_imm);
					ADD(sum_host_reg, cf_host_reg);
				});
		}
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::add(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x00:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x01: {
		r_to_rm_flags<true>(instr,
			[this](x86::Gp sum_host_reg, x86::Gp src_host_reg)
			{
				ADD(sum_host_reg, src_host_reg);
			});
	}
	break;

	case 0x02:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x03: {
		rm_to_r_flags<true>(instr,
			[this](x86::Gp sum_host_reg, x86::Gp src_host_reg)
			{
				ADD(sum_host_reg, src_host_reg);
			});
	}
	break;

	case 0x04:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x05: {
		imm_to_eax_flags<true>(instr,
			[this](x86::Gp sum_host_reg, uint32_t src_imm)
			{
				ADD(sum_host_reg, src_imm);
			});
	}
	break;

	case 0x80:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x81: {
		assert(instr->i.raw.modrm.reg == 0);

		uint32_t src_imm = GET_IMM();
		imm_to_rm_flags<true, uint32_t>(instr, src_imm,
			[this](x86::Gp sum_host_reg, uint32_t src_imm)
			{
				ADD(sum_host_reg, src_imm);
			});
	}
	break;

	case 0x83: {
		assert(instr->i.raw.modrm.reg == 0);

		if (m_cpu->size_mode == SIZE16) {
			int16_t src_imm = static_cast<int16_t>(static_cast<int8_t>(GET_IMM()));
			imm_to_rm_flags<true, int16_t>(instr, src_imm,
				[this](x86::Gp sum_host_reg, int16_t src_imm)
				{
					ADD(sum_host_reg, src_imm);
				});
		}
		else {
			int32_t src_imm = static_cast<int32_t>(static_cast<int8_t>(GET_IMM()));
			imm_to_rm_flags<true, int32_t>(instr, src_imm,
				[this](x86::Gp sum_host_reg, int32_t src_imm)
				{
					ADD(sum_host_reg, src_imm);
				});
		}
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::and_(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x20:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x21: {
		r_to_rm(instr,
			[this](x86::Gp res_host_reg, x86::Gp src_host_reg)
			{
				AND(res_host_reg, src_host_reg);
			});
	}
	break;

	case 0x22:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x23: {
		rm_to_r(instr,
			[this](x86::Gp res_host_reg, x86::Gp src_host_reg)
			{
				AND(res_host_reg, src_host_reg);
			});
	}
	break;

	case 0x24:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x25: {
		imm_to_eax(instr,
			[this](x86::Gp res_host_reg, uint32_t src_imm)
			{
				AND(res_host_reg, src_imm);
			});
	}
	break;

	case 0x80:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x81: {
		assert(instr->i.raw.modrm.reg == 4);

		uint32_t src_imm = GET_IMM();
		imm_to_rm<uint32_t>(instr, src_imm,
			[this](x86::Gp res_host_reg, uint32_t src_imm)
			{
				AND(res_host_reg, src_imm);
			});
	}
	break;

	case 0x83: {
		assert(instr->i.raw.modrm.reg == 4);

		if (m_cpu->size_mode == SIZE16) {
			int16_t src_imm = static_cast<int16_t>(static_cast<int8_t>(GET_IMM()));
			imm_to_rm<int16_t>(instr, src_imm,
				[this](x86::Gp res_host_reg, int16_t src_imm)
				{
					AND(res_host_reg, src_imm);
				});
		}
		else {
			int32_t src_imm = static_cast<int32_t>(static_cast<int8_t>(GET_IMM()));
			imm_to_rm<int32_t>(instr, src_imm,
				[this](x86::Gp res_host_reg, int32_t src_imm)
				{
					AND(res_host_reg, src_imm);
				});
		}
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::arpl(decoded_instr *instr)
{
	assert((instr->o[OPNUM_DST].size == 16) && (instr->o[OPNUM_SRC].size == 16));

	if (IS_VM86()) {
		RAISEin0_t(EXP_UD);
		return;
	}

	Label ok = m_a.newLabel();
	auto src = GET_REG(OPNUM_SRC);
	LD_REG_val(BX, src.val, SIZE16);

	get_rm<OPNUM_DST>(instr,
		[this, src, &ok](const op_info rm)
		{
			Label adjust = m_a.newLabel();
			LD_REG_val(AX, rm.val, SIZE16);
			MOV(R8W, AX);
			AND(BX, 3);
			AND(AX, 3);
			CMP(AX, BX);
			BR_ULT(adjust);
			MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
			OR(EAX, 0x100);
			MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), EAX);
			BR_UNCOND(ok);
			m_a.bind(adjust);
			AND(R8W, ~3);
			OR(R8W, BX);
			ST_REG_val(R8W, rm.val, SIZE16);
			MOV(R8D, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
			MOV(R9D, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
			MOV(EAX, R8D);
			MOV(EDX, R9D);
			SHL(EAX, 8);
			XOR(EAX, EDX);
			AND(EDX, 0xFFFF00FE);
			AND(EAX, 0xFF00);
			OR(EAX, EDX);
			LD_SF(R8D, R9D);
			OR(EAX, R8D);
			MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), 0);
			MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EAX);
		},
		[this, src, &ok](const op_info rm)
		{
			Label adjust = m_a.newLabel();
			MOV(MEMD32(RSP, LOCAL_VARS_off(0)), EDX);
			LD_MEMs(SIZE16);
			MOV(EDX, MEMD32(RSP, LOCAL_VARS_off(0)));
			MOV(R8W, AX);
			AND(BX, 3);
			AND(AX, 3);
			CMP(AX, BX);
			BR_ULT(adjust);
			MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
			OR(EAX, 0x100);
			MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), EAX);
			BR_UNCOND(ok);
			m_a.bind(adjust);
			AND(R8W, ~3);
			OR(R8W, BX);
			ST_MEMs(R8W, SIZE16);
			MOV(R8D, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
			MOV(R9D, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
			MOV(EAX, R8D);
			MOV(EDX, R9D);
			SHL(EAX, 8);
			XOR(EAX, EDX);
			AND(EDX, 0xFFFF00FE);
			AND(EAX, 0xFF00);
			OR(EAX, EDX);
			LD_SF(R8D, R9D);
			OR(EAX, R8D);
			MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), 0);
			MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EAX);
		});
	m_a.bind(ok);
}

void
lc86_jit::bound(decoded_instr *instr)
{
	Label ok = m_a.newLabel();
	auto dst = GET_REG(OPNUM_DST);
	auto src_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
	auto dst_host_reg = SIZED_REG(x64::rbx, dst.bits);
	auto rdx_host_reg = SIZED_REG(x64::rdx, m_cpu->size_mode);
	LD_REG_val(dst_host_reg, dst.val, dst.bits); // idx
	GET_OP(OPNUM_SRC);
	MOV(MEMD32(RSP, LOCAL_VARS_off(0)), EDX);
	LD_MEM();
	MOV(EDX, MEMD32(RSP, LOCAL_VARS_off(0)));
	MOV(MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode), src_host_reg);
	ADD(EDX, 1 << m_cpu->size_mode);
	LD_MEM(); //upper
	MOV(rdx_host_reg, MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode)); // lower
	CMP(dst_host_reg, rdx_host_reg);
	SET_SLT(R8B);
	MOV(DL, R8B);
	CMP(dst_host_reg, src_host_reg);
	SET_SGT(R8B);
	OR(DL, R8B);
	CMP(DL, 0);
	BR_EQ(ok);
	RAISEin0_f(EXP_BR);
	m_a.bind(ok);
}

void
lc86_jit::bsf(decoded_instr *instr)
{
	auto dst = GET_REG(OPNUM_DST);
	get_rm<OPNUM_SRC>(instr,
		[this, dst](const op_info rm)
		{
			auto src_host_reg = SIZED_REG(x64::rax, rm.bits);
			auto r8_host_reg = SIZED_REG(x64::r8, rm.bits);
			LD_REG_val(src_host_reg, rm.val, rm.bits);
			BSF(r8_host_reg, src_host_reg);
			SETNZ(BL);
			ST_REG_val(r8_host_reg, dst.val, dst.bits);
		},
		[this, dst](const op_info rm)
		{
			auto src_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
			auto r8_host_reg = SIZED_REG(x64::r8, m_cpu->size_mode);
			LD_MEM();
			BSF(r8_host_reg, src_host_reg);
			SETNZ(BL);
			ST_REG_val(r8_host_reg, dst.val, dst.bits);
		});

	MOVZX(EBX, BL);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), EBX);
}

void
lc86_jit::bsr(decoded_instr *instr)
{
	auto dst = GET_REG(OPNUM_DST);
	get_rm<OPNUM_SRC>(instr,
		[this, dst](const op_info rm)
		{
			auto src_host_reg = SIZED_REG(x64::rax, rm.bits);
			auto r8_host_reg = SIZED_REG(x64::r8, rm.bits);
			LD_REG_val(src_host_reg, rm.val, rm.bits);
			BSR(r8_host_reg, src_host_reg);
			SETNZ(BL);
			ST_REG_val(r8_host_reg, dst.val, dst.bits);
		},
		[this, dst](const op_info rm)
		{
			auto src_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
			auto r8_host_reg = SIZED_REG(x64::r8, m_cpu->size_mode);
			LD_MEM();
			BSR(r8_host_reg, src_host_reg);
			SETNZ(BL);
			ST_REG_val(r8_host_reg, dst.val, dst.bits);
		});

	MOVZX(EBX, BL);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), EBX);
}

void
lc86_jit::bswap(decoded_instr *instr)
{
	auto reg = GET_REG(OPNUM_SINGLE);
	LD_R32(EAX, reg.val);
	BSWAP(EAX);
	ST_R32(reg.val, EAX);
}

void
lc86_jit::bt(decoded_instr *instr)
{
	bit<0>(instr);
}

void
lc86_jit::btc(decoded_instr *instr)
{
	bit<1>(instr);
}

void
lc86_jit::btr(decoded_instr *instr)
{
	bit<2>(instr);
}

void
lc86_jit::bts(decoded_instr *instr)
{
	bit<3>(instr);
}

void
lc86_jit::call(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x9A: {
		// cs holds the cpl, so it can be assumed a constant
		addr_t ret_eip = m_cpu->instr_eip + m_cpu->instr_bytes;
		addr_t call_eip = instr->o[OPNUM_SINGLE].ptr.offset;
		uint16_t new_sel = instr->o[OPNUM_SINGLE].ptr.segment;
		if (m_cpu->size_mode == SIZE16) {
			call_eip &= 0x0000FFFF;
		}

		if (IS_PE_NOT_VM86()) {
			Label exp = m_a.newLabel();
			MOV(MEMD32(RSP, STACK_ARGS_off + 8), m_cpu->instr_eip);
			MOV(MEMD32(RSP, STACK_ARGS_off), ret_eip);
			MOV(R9B, m_cpu->size_mode);
			MOV(R8D, call_eip);
			MOV(EDX, new_sel);
			CALL_F( &lcall_pe_helper);
			TEST(EAX, EAX);
			BR_NE(exp);
			gen_link_indirect();
			m_a.bind(exp);
			RAISEin_no_param_f();
			m_cpu->tc->flags |= TC_FLG_INDIRECT;
		}
		else {
			gen_stack_push(m_cpu->cpu_ctx.regs.cs, ret_eip);
			uint32_t new_cs_base = new_sel << 4;
			ST_SEG(CPU_CTX_CS, new_sel);
			ST_R32(CPU_CTX_EIP, call_eip);
			ST_SEG_BASE(CPU_CTX_CS, new_cs_base);
			gen_link_direct(new_cs_base + call_eip, nullptr, new_cs_base + call_eip);
			m_cpu->tc->flags |= TC_FLG_DIRECT;
		}
	}
	break;

	case 0xE8: {
		addr_t ret_eip = m_cpu->instr_eip + m_cpu->instr_bytes;
		addr_t call_eip = ret_eip + instr->o[OPNUM_SINGLE].imm.value.s;
		if (m_cpu->size_mode == SIZE16) {
			call_eip &= 0x0000FFFF;
		}
		addr_t call_pc = m_cpu->cpu_ctx.regs.cs_hidden.base + call_eip;

		gen_stack_push(ret_eip);
		ST_R32(CPU_CTX_EIP, call_eip);
		gen_link_direct(call_pc, nullptr, call_pc);
		m_cpu->tc->flags |= TC_FLG_DIRECT;
	}
	break;

	case 0xFF: {
		if (instr->i.raw.modrm.reg == 2) {
			addr_t ret_eip = m_cpu->instr_eip + m_cpu->instr_bytes;
			get_rm<OPNUM_SINGLE>(instr,
				[this](const op_info rm)
				{
					auto dst_host_reg = SIZED_REG(x64::rax, rm.bits);
					LD_REG_val(dst_host_reg, rm.val, rm.bits);
				},
				[this](const op_info rm)
				{
					LD_MEM();
				});
			MOV(MEMD32(RSP, LOCAL_VARS_off(0)), EAX);
			gen_stack_push(ret_eip);
			MOV(EAX, MEMD16(RSP, LOCAL_VARS_off(0)));
			if (m_cpu->size_mode == SIZE16) {
				MOVZX(EAX, AX);
			}
			ST_R32(CPU_CTX_EIP, EAX);
			gen_link_indirect();
			m_cpu->tc->flags |= TC_FLG_INDIRECT;
		}
		else if (instr->i.raw.modrm.reg == 3) {
			assert(instr->o[OPNUM_SINGLE].type == ZYDIS_OPERAND_TYPE_MEMORY);

			// cs holds the cpl, so it can be assumed a constant
			addr_t ret_eip = m_cpu->instr_eip + m_cpu->instr_bytes;
			GET_OP(OPNUM_SINGLE);
			MOV(EBX, EDX);
			LD_MEM();
			if (m_cpu->size_mode == SIZE16) {
				MOVZX(EAX, AX);
				ADD(EBX, 2);
			}
			else {
				ADD(EBX, 4);
			}
			MOV(EDX, EBX);
			MOV(EBX, EAX);
			LD_MEMs(SIZE16);
			if (IS_PE_NOT_VM86()) {
				Label exp = m_a.newLabel();
				MOV(MEMD32(RSP, STACK_ARGS_off + 8), m_cpu->instr_eip);
				MOV(MEMD32(RSP, STACK_ARGS_off), ret_eip);
				MOV(R9B, m_cpu->size_mode);
				MOV(R8D, EBX);
				MOV(EDX, EAX);
				CALL_F(&lcall_pe_helper);
				TEST(EAX, EAX);
				BR_NE(exp);
				gen_link_indirect();
				m_a.bind(exp);
				RAISEin_no_param_f();
			}
			else {
				MOV(MEMD16(RSP, LOCAL_VARS_off(0)), AX);
				MOV(MEMD32(RSP, LOCAL_VARS_off(1)), EBX);
				gen_stack_push(m_cpu->cpu_ctx.regs.cs, ret_eip);
				MOV(AX, MEMD16(RSP, LOCAL_VARS_off(0)));
				MOV(EDX, MEMD32(RSP, LOCAL_VARS_off(1)));
				ST_SEG(CPU_CTX_CS, AX);
				ST_R32(CPU_CTX_EIP, EDX);
				MOVZX(EAX, AX);
				SHL(EAX, 4);
				ST_SEG_BASE(CPU_CTX_CS, EAX);
				gen_link_indirect();
			}
			m_cpu->tc->flags |= TC_FLG_INDIRECT;
		}
		else {
			LIB86CPU_ABORT();
		}
	}
	break;

	default:
		LIB86CPU_ABORT();
	}

	m_cpu->translate_next = 0;
}

void
lc86_jit::cbw(decoded_instr *instr)
{
	MOVSX(EDX, MEMD8(RCX, CPU_CTX_EAX));
	ST_R16(CPU_CTX_EAX, DX);
}

void
lc86_jit::cdq(decoded_instr *instr)
{
	MOVSXD(RDX, MEMD32(RCX, CPU_CTX_EAX));
	SHR(RDX, 32);
	ST_R32(CPU_CTX_EDX, EDX);
}

void
lc86_jit::clc(decoded_instr *instr)
{
	assert(instr->i.opcode == 0xF8);

	MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
	LD_OF(EDX, EAX);
	AND(EAX, 0x3FFFFFFF);
	SHR(EDX, 1);
	OR(EAX, EDX);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EAX);
}

void
lc86_jit::cld(decoded_instr *instr)
{
	assert(instr->i.opcode == 0xFC);

	LD_R32(EDX, CPU_CTX_EFLAGS);
	AND(EDX, ~DF_MASK);
	ST_R32(CPU_CTX_EFLAGS, EDX);
}

void
lc86_jit::cli(decoded_instr *instr)
{
	assert(instr->i.opcode == 0xFA);

	uint32_t mask;
	if (IS_PE()) {
		if (((m_cpu->cpu_ctx.regs.eflags & IOPL_MASK) >> 12) >= (m_cpu->cpu_ctx.hflags & HFLG_CPL)) {
			mask = IF_MASK;
		}
		else {
			if (m_cpu->cpu_ctx.hflags & (HFLG_CR4_VME | HFLG_CR4_PVI)) {
				mask = VIF_MASK;
			}
			else {
				RAISEin0_t(EXP_GP);
				return;
			}
		}
	}
	else {
		mask = IF_MASK;
	}

	LD_R32(EDX, CPU_CTX_EFLAGS);
	AND(EDX, ~mask);
	ST_R32(CPU_CTX_EFLAGS, EDX);
}

void
lc86_jit::clts(decoded_instr* instr)
{
	if (m_cpu->cpu_ctx.hflags & HFLG_CPL) {
		RAISEin0_t(EXP_GP);
	}
	else {
		MOV(EDX, 0);
		MOV(R8D, CR0_idx - CR_offset);
		CALL_F(&update_crN_helper<2>);

		addr_t dst_eip = m_cpu->instr_eip + m_cpu->instr_bytes;
		ST_R32(CPU_CTX_EIP, dst_eip);
		gen_link_direct(dst_eip + m_cpu->cpu_ctx.regs.cs_hidden.base, nullptr, 0);
		m_cpu->tc->flags |= TC_FLG_DIRECT;
		m_cpu->translate_next = 0;
	}
}

void
lc86_jit::cmc(decoded_instr *instr)
{
	assert(instr->i.opcode == 0xF5);

	MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
	MOV(EDX, EAX);
	NOT(EDX);
	AND(EDX, 0x80000000);
	LD_OF(EBX, EAX);
	AND(EAX, 0x3FFFFFFF);
	XOR(EBX, EDX);
	SHR(EBX, 1);
	OR(EDX, EBX);
	OR(EAX, EDX);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EAX);
}

void
lc86_jit::cmovcc(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x40:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EAX, EDX);
		CMP(EAX, 0x80000000);
		SET_EQ(R8B); // OF != 0
		break;

	case 0x41:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EAX, EDX);
		CMP(EAX, 0);
		SET_EQ(R8B); // OF == 0
		break;

	case 0x42:
		LD_CF(EAX);
		CMP(EAX, 0x80000000);
		SET_EQ(R8B); // CF != 0
		break;

	case 0x43:
		LD_CF(EAX);
		CMP(EAX, 0);
		SET_EQ(R8B); // CF == 0
		break;

	case 0x44:
		LD_ZF(EAX);
		CMP(EAX, 0);
		SET_EQ(R8B); // ZF != 0
		break;

	case 0x45:
		LD_ZF(EAX);
		CMP(EAX, 0);
		SET_NE(R8B); // ZF == 0
		break;

	case 0x46:
		LD_CF(EAX);
		CMP(EAX, 0x80000000);
		SET_EQ(DL);
		LD_ZF(EAX);
		CMP(EAX, 0);
		SET_EQ(R8B);
		OR(DL, R8B);
		CMP(DL, 1);
		SET_EQ(R8B); // CF != 0 OR ZF != 0
		break;

	case 0x47:
		LD_CF(EAX);
		CMP(EAX, 0);
		SET_EQ(DL);
		LD_ZF(EAX);
		CMP(EAX, 0);
		SET_NE(R8B);
		AND(DL, R8B);
		CMP(DL, 1);
		SET_EQ(R8B); // CF == 0 AND ZF == 0
		break;

	case 0x48:
		MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_SF(EAX, EDX);
		CMP(EAX, 1);
		SET_EQ(R8B); // SF != 0
		break;

	case 0x49:
		MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_SF(EAX, EDX);
		CMP(EAX, 0);
		SET_EQ(R8B); // SF == 0
		break;

	case 0x4A:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		MOV(EBX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_PF(EAX, EDX, EBX);
		CMP(EAX, 0);
		SET_EQ(R8B); // PF != 0
		break;

	case 0x4B:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		MOV(EBX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_PF(EAX, EDX, EBX);
		CMP(EAX, 1);
		SET_EQ(R8B); // PF == 0
		break;

	case 0x4C:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EAX, EDX);
		MOV(EBX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		LD_SF(EBX, EDX);
		SHR(EAX, 0x1F);
		XOR(EAX, EBX);
		CMP(EAX, 1);
		SET_EQ(R8B); // SF != OF
		break;

	case 0x4D:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EAX, EDX);
		MOV(EBX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		LD_SF(EBX, EDX);
		SHR(EAX, 0x1F);
		XOR(EAX, EBX);
		CMP(EAX, 0);
		SET_EQ(R8B); // SF == OF
		break;

	case 0x4E:
		LD_ZF(EAX);
		CMP(EAX, 0);
		SET_EQ(R8B);
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EBX, EDX);
		LD_SF(EAX, EDX);
		SHR(EBX, 0x1F);
		XOR(EAX, EBX);
		CMP(EAX, 1);
		SET_EQ(R9B);
		OR(R8B, R9B);
		CMP(R8B, 1);
		SET_EQ(R8B); // ZF != 0 OR SF != OF
		break;

	case 0x4F:
		LD_ZF(EAX);
		CMP(EAX, 0);
		SET_NE(R8B);
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EBX, EDX);
		LD_SF(EAX, EDX);
		SHR(EBX, 0x1F);
		XOR(EAX, EBX);
		CMP(EAX, 0);
		SET_EQ(R9B);
		AND(R8B, R9B);
		CMP(R8B, 1);
		SET_EQ(R8B); // ZF == 0 AND SF == OF
		break;

	default:
		LIB86CPU_ABORT();
	}

	MOVZX(EBX, R8B);

	size_t size = get_rm<OPNUM_SRC>(instr,
		[this](const op_info rm)
		{
			auto src_host_reg = SIZED_REG(x64::rax, rm.bits);
			LD_REG_val(src_host_reg, rm.val, rm.bits);
			return rm.bits;
		},
		[this](const op_info rm)
		{
			LD_MEM();
			return static_cast<size_t>(m_cpu->size_mode);
		});

	auto dst = GET_REG(OPNUM_DST);
	auto dst_host_reg = SIZED_REG(x64::rdx, dst.bits);
	auto src_host_reg = SIZED_REG(x64::rax, size);
	TEST(EBX, EBX);
	LD_REG_val(dst_host_reg, dst.val, dst.bits);
	CMOV_NE(dst_host_reg, src_host_reg);
	ST_REG_val(dst_host_reg, dst.val, dst.bits);
}

void
lc86_jit::cmp(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x38:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x39: {
		r_to_rm_flags<false, false>(instr,
			[this](x86::Gp sub_host_reg, x86::Gp src_host_reg)
			{
				SUB(sub_host_reg, src_host_reg);
			});
	}
	break;

	case 0x3A:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x3B: {
		rm_to_r_flags<false, false>(instr,
			[this](x86::Gp sub_host_reg, x86::Gp src_host_reg)
			{
				SUB(sub_host_reg, src_host_reg);
			});
	}
	break;

	case 0x3C:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x3D: {
		imm_to_eax_flags<false, false>(instr,
			[this](x86::Gp sub_host_reg, uint32_t src_imm)
			{
				SUB(sub_host_reg, src_imm);
			});
	}
	break;

	case 0x80:
	case 0x82:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x81: {
		uint32_t src_imm = GET_IMM();
		imm_to_rm_flags<false, uint32_t, false>(instr, src_imm,
			[this](x86::Gp sub_host_reg, uint32_t src_imm)
			{
				SUB(sub_host_reg, src_imm);
			});
	}
	break;

	case 0x83: {
		if (m_cpu->size_mode == SIZE16) {
			int16_t src_imm = static_cast<int16_t>(static_cast<int8_t>(GET_IMM()));
			imm_to_rm_flags<false, int16_t, false>(instr, src_imm,
				[this](x86::Gp sub_host_reg, int16_t src_imm)
				{
					SUB(sub_host_reg, src_imm);
				});
		}
		else {
			int32_t src_imm = static_cast<int32_t>(static_cast<int8_t>(GET_IMM()));
			imm_to_rm_flags<false, int32_t, false>(instr, src_imm,
				[this](x86::Gp sub_host_reg, int32_t src_imm)
				{
					SUB(sub_host_reg, src_imm);
				});
		}
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::cmps(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xA6:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xA7: {
		Label start, end = m_a.newLabel();
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REPNZ | ZYDIS_ATTRIB_HAS_REPZ)) {
			start = rep_start(end);
		}

		LD_SEG_BASE(EAX, CPU_CTX_ES);
		if (m_cpu->addr_mode == ADDR16) {
			MOVZX(EDX, MEMD16(RCX, CPU_CTX_EDI));
		}
		else {
			LD_R32(EDX, CPU_CTX_EDI);
		}
		MOV(MEMD32(RSP, LOCAL_VARS_off(0)), EDX);
		ADD(EDX, EAX);

		auto eax_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
		auto ebx_host_reg = SIZED_REG(x64::rbx, m_cpu->size_mode);
		auto edx_host_reg = SIZED_REG(x64::rdx, m_cpu->size_mode);
		auto r8_host_reg = SIZED_REG(x64::r8, m_cpu->size_mode);
		LD_MEM();
		MOV(ebx_host_reg, eax_host_reg);

		LD_SEG_BASE(EAX, get_seg_prfx_offset(instr));
		if (m_cpu->addr_mode == ADDR16) {
			MOVZX(EDX, MEMD16(RCX, CPU_CTX_ESI));
		}
		else {
			LD_R32(EDX, CPU_CTX_ESI);
		}
		MOV(MEMD32(RSP, LOCAL_VARS_off(1)), EDX);
		ADD(EDX, EAX);

		LD_MEM();
		MOV(r8_host_reg, eax_host_reg);
		SUB(r8_host_reg, ebx_host_reg);
		set_flags_sub(eax_host_reg, ebx_host_reg, r8_host_reg);

		Label sub = m_a.newLabel();
		uint32_t k = 1 << m_cpu->size_mode;
		MOV(EDX, MEMD32(RSP, LOCAL_VARS_off(0)));
		MOV(EAX, MEMD32(RSP, LOCAL_VARS_off(1)));
		LD_R32(EBX, CPU_CTX_EFLAGS);
		AND(EBX, DF_MASK);
		TEST(EBX, EBX);
		BR_NE(sub);

		ADD(EDX, k);
		ADD(EAX, k);
		if (m_cpu->addr_mode == ADDR16) {
			ST_R16(CPU_CTX_EDI, DX);
			ST_R16(CPU_CTX_ESI, AX);
		}
		else {
			ST_R32(CPU_CTX_EDI, EDX);
			ST_R32(CPU_CTX_ESI, EAX);
		}
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REPNZ | ZYDIS_ATTRIB_HAS_REPZ)) {
			if (instr->i.attributes & ZYDIS_ATTRIB_HAS_REPNZ) {
				rep<ZYDIS_ATTRIB_HAS_REPNZ>(start, end);
			}
			else {
				rep<ZYDIS_ATTRIB_HAS_REPZ>(start, end);
			}
		}
		else {
			BR_UNCOND(end);
		}

		m_a.bind(sub);
		SUB(EDX, k);
		SUB(EAX, k);
		if (m_cpu->addr_mode == ADDR16) {
			ST_R16(CPU_CTX_EDI, DX);
			ST_R16(CPU_CTX_ESI, AX);
		}
		else {
			ST_R32(CPU_CTX_EDI, EDX);
			ST_R32(CPU_CTX_ESI, EAX);
		}
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REPNZ | ZYDIS_ATTRIB_HAS_REPZ)) {
			if (instr->i.attributes & ZYDIS_ATTRIB_HAS_REPNZ) {
				rep<ZYDIS_ATTRIB_HAS_REPNZ>(start, end);
			}
			else {
				rep<ZYDIS_ATTRIB_HAS_REPZ>(start, end);
			}
		}

		m_a.bind(end);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::cmpxchg(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xB0:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xB1: {
		auto src = GET_REG(OPNUM_SRC);
		auto cmp_host_reg = SIZED_REG(x64::rbx, m_cpu->size_mode);
		LD_REG_val(cmp_host_reg, CPU_CTX_EAX, m_cpu->size_mode);
		get_rm<OPNUM_DST>(instr,
			[this, cmp_host_reg, src](const op_info rm)
			{
				Label equal = m_a.newLabel(), done = m_a.newLabel();
				auto src_host_reg = SIZED_REG(x64::rdx, src.bits);
				auto dst_host_reg = SIZED_REG(x64::rax, rm.bits);
				auto sub_host_reg = SIZED_REG(x64::r8, rm.bits);
				LD_REG_val(dst_host_reg, rm.val, rm.bits);
				MOV(sub_host_reg, dst_host_reg);
				SUB(sub_host_reg, cmp_host_reg);
				BR_EQ(equal);
				ST_REG_val(dst_host_reg, CPU_CTX_EAX, m_cpu->size_mode);
				BR_UNCOND(done);
				m_a.bind(equal);
				LD_REG_val(src_host_reg, src.val, src.bits);
				ST_REG_val(src_host_reg, rm.val, rm.bits);
				m_a.bind(done);
				set_flags_sub(dst_host_reg, cmp_host_reg, sub_host_reg);
			},
			[this, cmp_host_reg, src](const op_info rm)
			{
				Label equal = m_a.newLabel(), done = m_a.newLabel();
				auto src_host_reg = SIZED_REG(x64::r10, src.bits);
				auto dst_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
				auto sub_host_reg = SIZED_REG(x64::r8, m_cpu->size_mode);
				MOV(MEMD32(RSP, LOCAL_VARS_off(0)), EDX);
				LD_MEM();
				MOV(EDX, MEMD32(RSP, LOCAL_VARS_off(0)));
				MOV(sub_host_reg, dst_host_reg);
				SUB(sub_host_reg, cmp_host_reg);
				MOV(MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode), dst_host_reg);
				MOV(MEMD(RSP, LOCAL_VARS_off(1), m_cpu->size_mode), sub_host_reg);
				BR_EQ(equal);
				ST_REG_val(dst_host_reg, CPU_CTX_EAX, m_cpu->size_mode);
				ST_MEM(dst_host_reg);
				BR_UNCOND(done);
				m_a.bind(equal);
				LD_REG_val(src_host_reg, src.val, src.bits);
				ST_MEM(src_host_reg);
				m_a.bind(done);
				MOV(dst_host_reg, MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode));
				MOV(sub_host_reg, MEMD(RSP, LOCAL_VARS_off(1), m_cpu->size_mode));
				set_flags_sub(dst_host_reg, cmp_host_reg, sub_host_reg);
			});
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::cmpxchg8b(decoded_instr *instr)
{
	get_rm<OPNUM_SINGLE>(instr,
		[](const op_info rm)
		{
			assert(0);
		},
		[this](const op_info rm)
		{
			Label equal = m_a.newLabel(), done = m_a.newLabel();
			MOV(MEMD32(RSP, LOCAL_VARS_off(0)), EDX);
			LD_MEMs(SIZE64);
			LD_R32(EDX, CPU_CTX_EDX);
			LD_R32(EBX, CPU_CTX_EAX);
			SHL(RDX, 32);
			OR(RDX, RBX);
			CMP(RAX, RDX);
			MOV(EDX, MEMD32(RSP, LOCAL_VARS_off(0)));
			BR_EQ(equal);
			MOV(RBX, RAX);
			ST_MEMs(RAX, SIZE64);
			ST_R32(CPU_CTX_EAX, EBX);
			SHR(RBX, 32);
			ST_R32(CPU_CTX_EDX, EBX);
			MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
			OR(EDX, 0x100);
			MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), EDX);
			BR_UNCOND(done);
			m_a.bind(equal);
			LD_R32(EAX, CPU_CTX_ECX);
			LD_R32(EBX, CPU_CTX_EBX);
			SHL(RAX, 32);
			OR(RAX, RBX);
			ST_MEMs(RAX, SIZE64);
			MOV(R8D, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
			MOV(R9D, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
			MOV(EAX, R8D);
			MOV(EDX, R9D);
			SHL(EAX, 8);
			XOR(EAX, EDX);
			AND(EDX, 0xFFFF00FE);
			AND(EAX, 0xFF00);
			OR(EAX, EDX);
			LD_SF(R8D, R9D);
			OR(EAX, R8D);
			MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), 0);
			MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EAX);
			m_a.bind(done);
		});
}

void
lc86_jit::cpuid(decoded_instr *instr)
{
	CALL_F(&cpuid_helper);
}

void
lc86_jit::cwd(decoded_instr *instr)
{
	MOVSX(EDX, MEMD16(RCX, CPU_CTX_EAX));
	SHR(EDX, 16);
	ST_R16(CPU_CTX_EDX, DX);
}

void
lc86_jit::cwde(decoded_instr *instr)
{
	MOVSX(EDX, MEMD16(RCX, CPU_CTX_EAX));
	ST_R32(CPU_CTX_EAX, EDX);
}

void
lc86_jit::daa(decoded_instr *instr)
{
	Label jmp1 = m_a.newLabel();
	Label jmp2 = m_a.newLabel();
	Label jmp3 = m_a.newLabel();
	Label jmp4 = m_a.newLabel();
	Label jmp5 = m_a.newLabel();
	Label jmp6 = m_a.newLabel();
	LD_R8L(R10B, CPU_CTX_EAX);
	LD_CF(R11D);

	MOV(R8B, R10B);
	AND(R8B, 0xF);
	CMP(R8B, 9);
	BR_UGT(jmp1);
	LD_AF(EDX);
	CMP(EDX, 0);
	BR_EQ(jmp2);

	m_a.bind(jmp1);
	MOV(RDX, RCX);
	MOV(CL, R10B);
	MOV(R8B, R10B);
	ADD(R8B, 6);
	MOV(MEMD8(RDX, CPU_CTX_EAX), R8B);
	MOV(AL, CL);
	gen_sum_vec16_8<SIZE8>(6, R8B);
	RELOAD_RCX_CTX();
	AND(EAX, 0x80000000);
	OR(EAX, R11D);
	OR(EAX, 8);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EAX);
	BR_UNCOND(jmp3);

	m_a.bind(jmp2);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), 0);

	m_a.bind(jmp3);
	CMP(R10B, 0x99);
	BR_UGT(jmp4);
	CMP(R11D, 0);
	BR_EQ(jmp5);

	m_a.bind(jmp4);
	LD_R8L(R10B, CPU_CTX_EAX);
	ADD(R10B, 0x60);
	ST_R8L(CPU_CTX_EAX, R10B);
	MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
	OR(EDX, 0x80000000);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EDX);
	BR_UNCOND(jmp6);

	m_a.bind(jmp5);
	MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
	AND(EDX, 0x7FFFFFFF);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EDX);

	m_a.bind(jmp6);
	MOVSX(R10D, MEMD8(RCX, CPU_CTX_EAX));
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), R10D);
}

void
lc86_jit::das(decoded_instr *instr)
{
	Label jmp1 = m_a.newLabel();
	Label jmp2 = m_a.newLabel();
	Label jmp3 = m_a.newLabel();
	Label jmp4 = m_a.newLabel();
	Label jmp5 = m_a.newLabel();
	LD_R8L(R10B, CPU_CTX_EAX);
	LD_CF(R11D);

	MOV(R8B, R10B);
	AND(R8B, 0xF);
	CMP(R8B, 9);
	BR_UGT(jmp1);
	LD_AF(EDX);
	CMP(EDX, 0);
	BR_EQ(jmp2);

	m_a.bind(jmp1);
	MOV(RDX, RCX);
	MOV(CL, R10B);
	MOV(R8B, R10B);
	SUB(R8B, 6);
	MOV(MEMD8(RDX, CPU_CTX_EAX), R8B);
	MOV(AL, CL);
	gen_sub_vec16_8<SIZE8>(6, R8B);
	RELOAD_RCX_CTX();
	AND(EAX, 0x80000000);
	OR(EAX, R11D);
	OR(EAX, 8);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EAX);
	BR_UNCOND(jmp3);

	m_a.bind(jmp2);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), 0);

	m_a.bind(jmp3);
	CMP(R10B, 0x99);
	BR_UGT(jmp4);
	CMP(R11D, 0);
	BR_EQ(jmp5);

	m_a.bind(jmp4);
	LD_R8L(R10B, CPU_CTX_EAX);
	SUB(R10B, 0x60);
	ST_R8L(CPU_CTX_EAX, R10B);
	MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
	OR(EDX, 0x80000000);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EDX);

	m_a.bind(jmp5);
	MOVSX(R10D, MEMD8(RCX, CPU_CTX_EAX));
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), R10D);
}

void
lc86_jit::dec(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xFE:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x48:
	case 0x49:
	case 0x4A:
	case 0x4B:
	case 0x4C:
	case 0x4D:
	case 0x4E:
	case 0x4F:
	case 0xFF: {
		size_t size = get_rm<OPNUM_SINGLE>(instr,
			[this](const op_info rm)
			{
				auto sub_host_reg = SIZED_REG(x64::r8, rm.bits);
				auto a_host_reg = SIZED_REG(x64::rbx, rm.bits);
				LD_REG_val(a_host_reg, rm.val, rm.bits);
				MOV(sub_host_reg, a_host_reg);
				SUB(sub_host_reg, 1);
				ST_REG_val(sub_host_reg, rm.val, rm.bits);
				return rm.bits;
			},
			[this](const op_info rm)
			{
				auto sub_host_reg = SIZED_REG(x64::r8, m_cpu->size_mode);
				auto a_host_reg = SIZED_REG(x64::rbx, m_cpu->size_mode);
				auto rax_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
				MOV(EBX, EDX);
				LD_MEM();
				MOV(EDX, EBX);
				MOV(sub_host_reg, rax_host_reg);
				MOV(a_host_reg, rax_host_reg);
				SUB(sub_host_reg, 1);
				MOV(MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode), sub_host_reg);
				ST_MEM(sub_host_reg);
				MOV(sub_host_reg, MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode));
				return static_cast<size_t>(m_cpu->size_mode);
			});

		LD_CF(R11D);
		set_flags_sub(SIZED_REG(x64::rbx, size), 1, SIZED_REG(x64::r8, size));
		MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EDX, EAX);
		XOR(EDX, R11D);
		SHR(EDX, 1);
		OR(EDX, R11D);
		AND(EAX, 0x3FFFFFFF);
		OR(EDX, EAX);
		MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EDX);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::div(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xF6:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xF7: {
		assert(instr->i.raw.modrm.reg == 6);

		switch (m_cpu->size_mode)
		{
		case SIZE8:
			get_rm<OPNUM_SINGLE>(instr,
				[this](const op_info rm)
				{
					LD_R8L(DL, rm.val);
				},
				[this](const op_info rm)
				{
					LD_MEM();
					MOV(DL, AL);
				});
			MOV(RAX, &divb_helper);
			break;

		case SIZE16:
			get_rm<OPNUM_SINGLE>(instr,
				[this](const op_info rm)
				{
					LD_R16(DX, rm.val);
				},
				[this](const op_info rm)
				{
					LD_MEM();
					MOV(DX, AX);
				});
			MOV(RAX, &divw_helper);
			break;

		case SIZE32:
			get_rm<OPNUM_SINGLE>(instr,
				[this](const op_info rm)
				{
					LD_R32(EDX, rm.val);
				},
				[this](const op_info rm)
				{
					LD_MEM();
					MOV(EDX, EAX);
				});
			MOV(RAX, &divd_helper);
			break;

		default:
			LIB86CPU_ABORT();
		}

		Label ok = m_a.newLabel();
		MOV(R8D, m_cpu->instr_eip);
		CALL(RAX);
		RELOAD_RCX_CTX();
		TEST(EAX, EAX);
		BR_EQ(ok);
		RAISEin_no_param_f();
		m_a.bind(ok);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::enter(decoded_instr *instr)
{
	uint32_t stack_sub, nesting_lv = instr->o[OPNUM_SRC].imm.value.u & 0x1F;
	auto rax_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
	auto r10_host_reg = SIZED_REG(x64::r10, m_cpu->size_mode);

	MOV(r10_host_reg, MEMD(RCX, CPU_CTX_EBP, m_cpu->size_mode));
	switch ((m_cpu->size_mode << 1) | ((m_cpu->cpu_ctx.hflags & HFLG_SS32) >> SS32_SHIFT))
	{
	case (SIZE32 << 1) | 0: { // sp, push 32
		stack_sub = 4;
		MOVZX(EBX, MEMD16(RCX, CPU_CTX_ESP));
		gen_stack_push<false>(r10_host_reg);
		MOV(EAX, MEMD32(RCX, CPU_CTX_ESP));
		AND(EAX, 0xFFFF0000);
		OR(EBX, EAX);
		MOV(MEMD32(RSP, LOCAL_VARS_off(0)), EBX);
	}
	break;

	case (SIZE32 << 1) | 1: { // esp, push 32
		stack_sub = 4;
		MOV(EBX, MEMD32(RCX, CPU_CTX_ESP));
		gen_stack_push<false>(r10_host_reg);
		MOV(MEMD32(RSP, LOCAL_VARS_off(0)), EBX);
	}
	break;

	case (SIZE16 << 1) | 0: { // sp, push 16
		stack_sub = 2;
		MOVZX(EBX, MEMD16(RCX, CPU_CTX_ESP));
		gen_stack_push<false>(r10_host_reg);
		MOV(MEMD16(RSP, LOCAL_VARS_off(0)), BX);
	}
	break;

	case (SIZE16 << 1) | 1: { // esp, push 16
		stack_sub = 2;
		MOV(EBX, MEMD32(RCX, CPU_CTX_ESP));
		gen_stack_push<false>(r10_host_reg);
		MOV(MEMD16(RSP, LOCAL_VARS_off(0)), BX);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}

	if (nesting_lv > 0) {
		for (uint32_t i = 1; i < nesting_lv; ++i) {
			if (m_cpu->cpu_ctx.hflags & HFLG_SS32) {
				MOV(EAX, MEMD32(RCX, CPU_CTX_EBP));
			}
			else {
				MOVZX(EAX, MEMD16(RCX, CPU_CTX_EBP));
			}
			SUB(EAX, stack_sub * i);
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			ADD(EDX, EAX);
			LD_MEM();
			MOV(r10_host_reg, rax_host_reg);
			gen_stack_push<false>(r10_host_reg);
		}

		MOV(r10_host_reg, MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode));
		gen_stack_push<false>(r10_host_reg);
	}

	if (m_cpu->cpu_ctx.hflags & HFLG_SS32) {
		SUB(EBX, instr->o[OPNUM_DST].imm.value.u);
		gen_virtual_stack_push();
		ST_R32(CPU_CTX_ESP, EBX);
	}
	else {
		SUB(BX, instr->o[OPNUM_DST].imm.value.u);
		gen_virtual_stack_push();
		ST_R16(CPU_CTX_ESP, BX);
	}

	MOV(rax_host_reg, MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode));
	ST_REG_val(rax_host_reg, CPU_CTX_EBP, m_cpu->size_mode);
}

void
lc86_jit::fld(decoded_instr *instr)
{
	if (m_cpu->cpu_ctx.hflags & (HFLG_CR0_EM | HFLG_CR0_TS)) {
		RAISEin0_t(EXP_NM);
	}
	else {
		get_rm<OPNUM_SRC>(instr,
			[this, instr](const op_info rm)
			{
				Label stack_fault = m_a.newLabel(), ok = m_a.newLabel();
				MOV(MEMD64(RSP, LOCAL_VARS_off(0)), 0);
				CALL_FPU_STACK_CHK(true, fpu_instr_t::float_);
				CALL_FPU_SET_CTX();
				MOV(EDX, instr->i.raw.modrm.rm);
				MOV(EAX, sizeof(uint80_t));
				MUL(DX);
				TEST(MEMD64(RSP, LOCAL_VARS_off(0)), 0);
				BR_NE(stack_fault);
				FLD(MEMSD80(RCX, RAX, 0, CPU_CTX_R0));
				BR_UNCOND(ok);
				m_a.bind(stack_fault);
				FLD(MEMD32(RSP, LOCAL_VARS_off(0)));
				m_a.bind(ok);
				CALL_FPU_EXP_CHK();
				MOV(EAX, sizeof(uint80_t));
				ST_R16(FPU_DATA_FTOP, BX);
				MUL(BX);
				FSTP(MEMSD80(RCX, RAX, 0, CPU_CTX_R0));
				gen_update_fpu_ptr<false>(instr);
			},
			[this, instr](const op_info rm)
			{
				switch (instr->i.opcode)
				{
				case 0xD9:
					LD_MEMs(SIZE32);
					MOV(MEMD32(RSP, LOCAL_VARS_off(0)), EAX);
					CALL_FPU_STACK_CHK(true, fpu_instr_t::float_);
					CALL_FPU_SET_CTX();
					FLD(MEMD32(RSP, LOCAL_VARS_off(0)));
					break;

				case 0xDD:
					LD_MEMs(SIZE64);
					MOV(MEMD64(RSP, LOCAL_VARS_off(0)), RAX);
					CALL_FPU_STACK_CHK(true, fpu_instr_t::float_);
					CALL_FPU_SET_CTX();
					FLD(MEMD64(RSP, LOCAL_VARS_off(0)));
					break;

				case 0xDB:
					LD_MEM80(0);
					CALL_FPU_STACK_CHK(true, fpu_instr_t::float_);
					CALL_FPU_SET_CTX();
					FLD(MEMD80(RSP, LOCAL_VARS_off(0)));
					break;

				default:
					LIB86CPU_ABORT();
				}

				CALL_FPU_EXP_CHK();
				MOV(EAX, sizeof(uint80_t));
				ST_R16(FPU_DATA_FTOP, BX);
				MUL(BX);
				FSTP(MEMSD80(RCX, RAX, 0, CPU_CTX_R0));
				gen_update_fpu_ptr<true>(instr);
			});

		RESTORE_FPU_CTX();
		MOV(EDX, EBX);
		CALL_F(&fpu_update_tag);
	}
}

void
lc86_jit::fninit(decoded_instr *instr)
{
	if (m_cpu->cpu_ctx.hflags & (HFLG_CR0_EM | HFLG_CR0_TS)) {
		RAISEin0_t(EXP_NM);
	}
	else {
		ST_R16(CPU_CTX_FCTRL, 0x37F);
		ST_R16(CPU_CTX_FSTATUS, 0);
		MOV(MEMD32(RCX, CPU_CTX_FTAGS0), 0x03030303); // FPU_TAG_EMPTY for all ftags
		MOV(MEMD32(RCX, CPU_CTX_FTAGS4), 0x03030303);
		ST_R16(CPU_CTX_FCS, 0);
		ST_R32(CPU_CTX_FIP, 0);
		ST_R16(CPU_CTX_FDS, 0);
		ST_R32(CPU_CTX_FDP, 0);
		ST_R16(CPU_CTX_FOP, 0);
		ST_R16(FPU_DATA_FTOP, 0);
		ST_R16(FPU_DATA_FES, 0);
		ST_R16(FPU_DATA_FRP, 0x37F);
	}
}

void
lc86_jit::fnstcw(decoded_instr *instr)
{
	if (m_cpu->cpu_ctx.hflags & (HFLG_CR0_EM | HFLG_CR0_TS)) {
		RAISEin0_t(EXP_NM);
	}
	else {
		LD_R16(R8W, CPU_CTX_FCTRL);
		LD_R16(AX, FPU_DATA_FRP);
		AND(R8W, FPU_EXP_ALL);
		AND(AX, FPU_FLG_PC | FPU_FLG_RC);
		OR(R8W, AX);
		OR(R8W, 0x40);
		get_rm<OPNUM_SINGLE>(instr,
			[](const op_info rm)
			{
				assert(0);
			},
			[this](const op_info rm)
			{
				ST_MEMs(R8W, SIZE16);
			});
	}
}

void
lc86_jit::fnstsw(decoded_instr *instr)
{
	if (m_cpu->cpu_ctx.hflags & (HFLG_CR0_EM | HFLG_CR0_TS)) {
		RAISEin0_t(EXP_NM);
	}
	else {
		LD_R16(R8W, CPU_CTX_FSTATUS);
		get_rm<OPNUM_SINGLE>(instr,
			[this](const op_info rm)
			{
				ST_R16(CPU_CTX_EAX, R8W);
			},
			[this](const op_info rm)
			{
				ST_MEMs(R8W, SIZE16);
			});
	}
}

void
lc86_jit::fwait(decoded_instr *instr)
{
	if ((m_cpu->cpu_ctx.hflags & (HFLG_CR0_MP | HFLG_CR0_TS)) == (HFLG_CR0_MP | HFLG_CR0_TS)) {
		RAISEin0_t(EXP_NM);
	}
	else {
		Label no_exp = m_a.newLabel();
		LD_R16(AX, CPU_CTX_FSTATUS);
		TEST(AX, FPU_EXP_ALL);
		BR_EQ(no_exp);
		LD_R16(AX, CPU_CTX_FCTRL);
		AND(AX, FPU_EXP_ALL);
		CMP(AX, FPU_EXP_ALL);
		BR_EQ(no_exp);
		static const char *abort_msg = "Unmasked fpu exceptions are not supported";
		MOV(RCX, abort_msg);
		MOV(RAX, &cpu_runtime_abort);
		CALL(RAX); // won't return
		INT3();
		m_a.bind(no_exp);
	}
}

void
lc86_jit::fxrstor(decoded_instr *instr)
{
	if (m_cpu->cpu_ctx.hflags & (HFLG_CR0_EM | HFLG_CR0_TS)) {
		RAISEin0_t(EXP_NM);
	}
	else {
		get_rm<OPNUM_SINGLE>(instr,
			[](const op_info rm)
			{
				assert(0);
			},
			[this](const op_info rm)
			{
				MOV(R8D, m_cpu->instr_eip);
				CALL_F(&fxrstor_helper);
				Label ok = m_a.newLabel();
				TEST(EAX, EAX);
				BR_EQ(ok);
				RAISEin0_f(EXP_GP);
				m_a.bind(ok);
			});
	}
}

void
lc86_jit::fxsave(decoded_instr *instr)
{
	if (m_cpu->cpu_ctx.hflags & (HFLG_CR0_EM | HFLG_CR0_TS)) {
		RAISEin0_t(EXP_NM);
	}
	else {
		get_rm<OPNUM_SINGLE>(instr,
			[](const op_info rm)
			{
				assert(0);
			},
			[this](const op_info rm)
			{
				Label ok = m_a.newLabel();
				TEST(EDX, 15);
				BR_EQ(ok);
				RAISEin0_f(EXP_GP);
				m_a.bind(ok);
				MOV(R8D, m_cpu->instr_eip);
				CALL_F(&fxsave_helper);
			});
	}
}

void
lc86_jit::hlt(decoded_instr *instr)
{
	if (m_cpu->cpu_ctx.hflags & HFLG_CPL) {
		RAISEin0_t(EXP_GP);
	}
	else {
		// some apps like test386 expect HLT to raise an exception, but otherwise don't rely on interrupts. So only check the flag after the potential exception
		// some apps like test80186 terminate with a HLT instruction, so do a runtime abort instead of a compile time abort, so that the last code block (which is
		// required to be run by the test) is actually executed
		if (m_cpu->cpu_flags & CPU_ABORT_ON_HLT) {
			static const char *abort_msg = "Encountered HLT instruction, terminating the emulation";
			MOV(RCX, abort_msg);
			MOV(RAX, &cpu_runtime_abort); // won't return
			CALL(RAX);
			INT3();
		}
		else {
			MOV(MEMD32(RCX, CPU_CTX_EIP), m_cpu->instr_eip + m_cpu->instr_bytes);
			if (m_cpu->cpu_ctx.hflags & HFLG_TIMEOUT) {
				Label retry = m_a.newLabel();
				Label no_timeout = m_a.newLabel();
				m_a.bind(retry);
				CALL_F(&cpu_timer_helper);
				PAUSE();
				TEST(EAX, EAX);
				BR_EQ(retry);
				TEST(EAX, CPU_NON_HW_INT);
				BR_NE(retry);
				TEST(EAX, CPU_HW_INT);
				BR_NE(no_timeout);
				MOV(MEMD8(RCX, CPU_CTX_EXIT), 1); // request an exit
				MOV(MEMD8(RCX, CPU_CTX_HALTED), 1); // set halted flag
				m_a.bind(no_timeout);
			}
			else {
				Label retry = m_a.newLabel();
				m_a.bind(retry);
				CALL_F(&hlt_helper);
				PAUSE();
				TEST(EAX, EAX);
				BR_EQ(retry);
			}

			XOR(EAX, EAX);
			gen_epilogue_main<false>();
		}

		m_needs_epilogue = false;
		m_cpu->translate_next = 0;
	}
}

void
lc86_jit::idiv(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xF6:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xF7: {
		assert(instr->i.raw.modrm.reg == 7);

		switch (m_cpu->size_mode)
		{
		case SIZE8:
			get_rm<OPNUM_SINGLE>(instr,
				[this](const op_info rm)
				{
					LD_R8L(DL, rm.val);
				},
				[this](const op_info rm)
				{
					LD_MEM();
					MOV(DL, AL);
				});
			MOV(RAX, &idivb_helper);
			break;

		case SIZE16:
			get_rm<OPNUM_SINGLE>(instr,
				[this](const op_info rm)
				{
					LD_R16(DX, rm.val);
				},
				[this](const op_info rm)
				{
					LD_MEM();
					MOV(DX, AX);
				});
			MOV(RAX, &idivw_helper);
			break;

		case SIZE32:
			get_rm<OPNUM_SINGLE>(instr,
				[this](const op_info rm)
				{
					LD_R32(EDX, rm.val);
				},
				[this](const op_info rm)
				{
					LD_MEM();
					MOV(EDX, EAX);
				});
			MOV(RAX, &idivd_helper);
			break;

		default:
			LIB86CPU_ABORT();
		}

		Label ok = m_a.newLabel();
		MOV(R8D, m_cpu->instr_eip);
		CALL(RAX);
		RELOAD_RCX_CTX();
		TEST(EAX, EAX);
		BR_EQ(ok);
		RAISEin_no_param_f();
		m_a.bind(ok);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::imul(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xF6:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xF7: {
		assert(instr->i.raw.modrm.reg == 5);

		switch (m_cpu->size_mode)
		{
		case SIZE8:
			get_rm<OPNUM_SINGLE>(instr,
				[this](const op_info rm)
				{
					LD_REG_val(BL, rm.val, rm.bits);
					LD_REG_val(AL, CPU_CTX_EAX, SIZE8);
				},
				[this](const op_info rm)
				{
					LD_MEM();
					LD_REG_val(BL, CPU_CTX_EAX, SIZE8);
					XCHG(AL, BL);
				});
			IMUL1(BL);
			ST_R16(CPU_CTX_EAX, AX);
			break;

		case SIZE16:
			get_rm<OPNUM_SINGLE>(instr,
				[this](const op_info rm)
				{
					LD_REG_val(BX, rm.val, rm.bits);
					LD_REG_val(AX, CPU_CTX_EAX, SIZE16);
				},
				[this](const op_info rm)
				{
					LD_MEM();
					LD_REG_val(BX, CPU_CTX_EAX, SIZE16);
					XCHG(AX, BX);
				});
			IMUL1(BX);
			ST_R16(CPU_CTX_EAX, AX);
			ST_R16(CPU_CTX_EDX, DX);
			break;

		case SIZE32:
			get_rm<OPNUM_SINGLE>(instr,
				[this](const op_info rm)
				{
					LD_REG_val(EBX, rm.val, rm.bits);
					LD_REG_val(EAX, CPU_CTX_EAX, SIZE32);
				},
				[this](const op_info rm)
				{
					LD_MEM();
					LD_REG_val(EBX, CPU_CTX_EAX, SIZE32);
					XCHG(EAX, EBX);
				});
			IMUL1(EBX);
			ST_R32(CPU_CTX_EAX, EAX);
			ST_R32(CPU_CTX_EDX, EDX);
			break;

		default:
			LIB86CPU_ABORT();
		}
	}
	break;

	case 0xAF: {
		auto dst = GET_REG(OPNUM_DST);
		auto dst_host_reg = SIZED_REG(x64::rbx, dst.bits);
		auto src_host_reg = get_rm<OPNUM_SRC>(instr,
			[this](const op_info rm)
			{
				auto src_host_reg = SIZED_REG(x64::rax, rm.bits);
				LD_REG_val(src_host_reg, rm.val, rm.bits);
				return src_host_reg;
			},
			[this](const op_info rm)
			{
				auto src_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
				LD_MEM();
				return src_host_reg;
			});
		LD_REG_val(dst_host_reg, dst.val, dst.bits);
		IMUL2(dst_host_reg, src_host_reg);
		ST_REG_val(dst_host_reg, dst.val, dst.bits);
	}
	break;

	case 0x6B:
	case 0x69: {
		auto dst = GET_REG(OPNUM_DST);
		auto dst_host_reg = SIZED_REG(x64::rbx, dst.bits);
		auto src_host_reg = get_rm<OPNUM_SRC>(instr,
			[this](const op_info rm)
			{
				auto src_host_reg = SIZED_REG(x64::rax, rm.bits);
				LD_REG_val(src_host_reg, rm.val, rm.bits);
				return src_host_reg;
			},
			[this](const op_info rm)
			{
				auto src_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
				LD_MEM();
				return src_host_reg;
			});
		if (instr->i.opcode == 0x6B) {
			IMUL3(dst_host_reg, src_host_reg, m_cpu->size_mode == SIZE16 ? static_cast<int16_t>(static_cast<int8_t>(instr->o[OPNUM_THIRD].imm.value.u)) :
				static_cast<int32_t>(static_cast<int8_t>(instr->o[OPNUM_THIRD].imm.value.u)));
		}
		else {
			IMUL3(dst_host_reg, src_host_reg, instr->o[OPNUM_THIRD].imm.value.u);
		}
		ST_REG_val(dst_host_reg, dst.val, dst.bits);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}

	SETC(BL);
	SETO(DL);
	MOVZX(EBX, BL);
	MOVZX(EDX, DL);
	XOR(EDX, EBX);
	ADD(EBX, EBX);
	OR(EBX, EDX);
	SHL(EBX, 0x1E);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EBX);
}

void
lc86_jit::in(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xE4:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xE5: {
		auto val_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
		uint8_t port = GET_IMM();
		gen_check_io_priv(port);
		MOV(EDX, port);
		LD_IO();
		ST_REG_val(val_host_reg, CPU_CTX_EAX, m_cpu->size_mode);
	}
	break;

	case 0xEC:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xED: {
		auto val_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
		MOVZX(EDX, MEMD16(RCX, CPU_CTX_EDX));
		if (gen_check_io_priv(EDX)) {
			MOV(EDX, MEMD32(RSP, LOCAL_VARS_off(0)));
		}
		LD_IO();
		ST_REG_val(val_host_reg, CPU_CTX_EAX, m_cpu->size_mode);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::inc(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xFE:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x40:
	case 0x41:
	case 0x42:
	case 0x43:
	case 0x44:
	case 0x45:
	case 0x46:
	case 0x47:
	case 0xFF: {
		size_t size = get_rm<OPNUM_SINGLE>(instr,
			[this](const op_info rm)
			{
				auto sum_host_reg = SIZED_REG(x64::r8, rm.bits);
				auto a_host_reg = SIZED_REG(x64::rbx, rm.bits);
				LD_REG_val(a_host_reg, rm.val, rm.bits);
				MOV(sum_host_reg, a_host_reg);
				ADD(sum_host_reg, 1);
				ST_REG_val(sum_host_reg, rm.val, rm.bits);
				return rm.bits;
			},
			[this](const op_info rm)
			{
				auto sum_host_reg = SIZED_REG(x64::r8, m_cpu->size_mode);
				auto a_host_reg = SIZED_REG(x64::rbx, m_cpu->size_mode);
				auto rax_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
				MOV(EBX, EDX);
				LD_MEM();
				MOV(EDX, EBX);
				MOV(sum_host_reg, rax_host_reg);
				MOV(a_host_reg, rax_host_reg);
				ADD(sum_host_reg, 1);
				MOV(MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode), sum_host_reg);
				ST_MEM(sum_host_reg);
				MOV(sum_host_reg, MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode));
				return static_cast<size_t>(m_cpu->size_mode);
			});

		LD_CF(R11D);
		set_flags_sum(SIZED_REG(x64::rbx, size), 1, SIZED_REG(x64::r8, size));
		MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EDX, EAX);
		XOR(EDX, R11D);
		SHR(EDX, 1);
		OR(EDX, R11D);
		AND(EAX, 0x3FFFFFFF);
		OR(EDX, EAX);
		MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EDX);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::ins(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x6C:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x6D: {
		// technically, the effect of repnz on instructions that don't support it is officially undefined, but test80186 relies on it
		// https://en.wikipedia.org/wiki/X86_instruction_listings#Undocumented_instructions
		Label start, end = m_a.newLabel();
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPNZ)) {
			start = rep_start(end);
		}

		auto val_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
		MOVZX(EDX, MEMD16(RCX, CPU_CTX_EDX));
		if (gen_check_io_priv(EDX)) {
			MOV(EDX, MEMD32(RSP, LOCAL_VARS_off(0)));
		}
		LD_IO();

		LD_SEG_BASE(R8D, CPU_CTX_ES);
		if (m_cpu->addr_mode == ADDR16) {
			MOVZX(EDX, MEMD16(RCX, CPU_CTX_EDI));
		}
		else {
			LD_R32(EDX, CPU_CTX_EDI);
		}
		MOV(EBX, EDX);
		ADD(EDX, R8D);
		ST_MEM(val_host_reg);

		Label sub = m_a.newLabel();
		uint32_t k = 1 << m_cpu->size_mode;
		LD_R32(EAX, CPU_CTX_EFLAGS);
		AND(EAX, DF_MASK);
		TEST(EAX, EAX);
		BR_NE(sub);

		ADD(EBX, k);
		if (m_cpu->addr_mode == ADDR16) {
			ST_R16(CPU_CTX_EDI, BX);
		}
		else {
			ST_R32(CPU_CTX_EDI, EBX);
		}
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPNZ)) {
			rep<ZYDIS_ATTRIB_HAS_REP>(start, end);
		}
		else {
			BR_UNCOND(end);
		}

		m_a.bind(sub);
		SUB(EBX, k);
		if (m_cpu->addr_mode == ADDR16) {
			ST_R16(CPU_CTX_EDI, BX);
		}
		else {
			ST_R32(CPU_CTX_EDI, EBX);
		}
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPNZ)) {
			rep<ZYDIS_ATTRIB_HAS_REP>(start, end);
		}

		m_a.bind(end);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::int3(decoded_instr *instr)
{
	int_<1>(instr);
}

void
lc86_jit::intn(decoded_instr *instr)
{
	int_<2>(instr);
}

void
lc86_jit::into(decoded_instr *instr)
{
	int_<3>(instr);
}

void
lc86_jit::invlpg(decoded_instr *instr)
{
	if (m_cpu->cpu_ctx.hflags & HFLG_CPL) {
		RAISEin0_t(EXP_GP);
	}
	else {
		get_rm<OPNUM_SINGLE>(instr,
			[](const op_info rm)
			{
				assert(0);
			},
			[this](const op_info rm)
			{
				CALL_F(&tlb_invalidate_);
			});
	}
}

void
lc86_jit::iret(decoded_instr *instr)
{
	assert(instr->i.opcode == 0xCF);

	if (IS_PE()) {
		Label exp = m_a.newLabel();
		MOV(R8D, m_cpu->instr_eip);
		MOV(DL, m_cpu->size_mode);
		CALL_F(&lret_pe_helper<true>);
		TEST(EAX, EAX);
		BR_NE(exp);
		gen_link_ret();
		m_a.bind(exp);
		RAISEin_no_param_f();
	}
	else {
		MOV(R8D, m_cpu->instr_eip);
		MOV(DL, m_cpu->size_mode);
		CALL_F(&iret_real_helper);
		gen_link_ret();
	}

	m_cpu->tc->flags |= TC_FLG_RET;
	m_cpu->translate_next = 0;
}

void
lc86_jit::jcc(decoded_instr *instr)
{
	addr_t next_eip = m_cpu->instr_eip + m_cpu->instr_bytes;
	addr_t jmp_eip = next_eip + instr->o[OPNUM_SINGLE].imm.value.s;
	if (m_cpu->size_mode == SIZE16) {
		jmp_eip &= 0x0000FFFF;
	}
	addr_t next_pc = next_eip + m_cpu->cpu_ctx.regs.cs_hidden.base;
	addr_t dst_pc = jmp_eip + m_cpu->cpu_ctx.regs.cs_hidden.base;

	switch (instr->i.opcode)
	{
	case 0x70:
	case 0x80:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EAX, EDX);
		MOV(R9D, next_eip);
		MOV(EBX, jmp_eip);
		CMP(EAX, 0x80000000);
		CMOV_EQ(R9D, EBX); // OF != 0
		break;

	case 0x71:
	case 0x81:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EAX, EDX);
		MOV(R9D, next_eip);
		MOV(EBX, jmp_eip);
		CMP(EAX, 0);
		CMOV_EQ(R9D, EBX); // OF == 0
		break;

	case 0x72:
	case 0x82:
		LD_CF(EAX);
		MOV(R9D, next_eip);
		MOV(EBX, jmp_eip);
		CMP(EAX, 0x80000000);
		CMOV_EQ(R9D, EBX); // CF != 0
		break;

	case 0x73:
	case 0x83:
		LD_CF(EAX);
		MOV(R9D, next_eip);
		MOV(EBX, jmp_eip);
		CMP(EAX, 0);
		CMOV_EQ(R9D, EBX); // CF == 0
		break;

	case 0x74:
	case 0x84:
		LD_ZF(EAX);
		MOV(R9D, next_eip);
		MOV(EBX, jmp_eip);
		CMP(EAX, 0);
		CMOV_EQ(R9D, EBX); // ZF != 0
		break;

	case 0x75:
	case 0x85:
		LD_ZF(EAX);
		MOV(R9D, next_eip);
		MOV(EBX, jmp_eip);
		CMP(EAX, 0);
		CMOV_NE(R9D, EBX); // ZF == 0
		break;

	case 0x76:
	case 0x86:
		LD_CF(EAX);
		MOV(EDX, 0);
		MOV(EBX, 1);
		CMP(EAX, 0x80000000);
		CMOV_EQ(EDX, EBX);
		LD_ZF(EAX);
		MOV(R8D, 0);
		CMP(EAX, 0);
		CMOV_EQ(R8D, EBX);
		OR(EDX, R8D);
		CMP(EDX, 1);
		MOV(R9D, next_eip);
		MOV(EBX, jmp_eip);
		CMOV_EQ(R9D, EBX); // CF != 0 OR ZF != 0
		break;

	case 0x77:
	case 0x87:
		LD_CF(EAX);
		MOV(EDX, 0);
		MOV(EBX, 1);
		CMP(EAX, 0);
		CMOV_EQ(EDX, EBX);
		MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_ZF(EAX);
		MOV(R8D, 0);
		CMP(EAX, 0);
		CMOV_NE(R8D, EBX);
		AND(EDX, R8D);
		CMP(EDX, 1);
		MOV(R9D, next_eip);
		MOV(EBX, jmp_eip);
		CMOV_EQ(R9D, EBX); // CF == 0 AND ZF == 0
		break;

	case 0x78:
	case 0x88:
		MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_SF(EAX, EDX);
		MOV(R9D, next_eip);
		MOV(EBX, jmp_eip);
		CMP(EAX, 1);
		CMOV_EQ(R9D, EBX); // SF != 0
		break;

	case 0x79:
	case 0x89:
		MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_SF(EAX, EDX);
		MOV(R9D, next_eip);
		MOV(EBX, jmp_eip);
		CMP(EAX, 0);
		CMOV_EQ(R9D, EBX); // SF == 0
		break;

	case 0x7A:
	case 0x8A:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		MOV(EBX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_PF(EAX, EDX, EBX);
		MOV(R9D, next_eip);
		MOV(EBX, jmp_eip);
		CMP(EAX, 0);
		CMOV_EQ(R9D, EBX); // PF != 0
		break;

	case 0x7B:
	case 0x8B:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		MOV(EBX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_PF(EAX, EDX, EBX);
		MOV(R9D, next_eip);
		MOV(EBX, jmp_eip);
		CMP(EAX, 1);
		CMOV_EQ(R9D, EBX); // PF == 0
		break;

	case 0x7C:
	case 0x8C:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EAX, EDX);
		MOV(EBX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		LD_SF(EBX, EDX);
		SHR(EAX, 0x1F);
		XOR(EAX, EBX);
		MOV(R9D, next_eip);
		MOV(EBX, jmp_eip);
		CMP(EAX, 1);
		CMOV_EQ(R9D, EBX); // SF != OF
		break;

	case 0x7D:
	case 0x8D:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EAX, EDX);
		MOV(EBX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		LD_SF(EBX, EDX);
		SHR(EAX, 0x1F);
		XOR(EAX, EBX);
		MOV(R9D, next_eip);
		MOV(EBX, jmp_eip);
		CMP(EAX, 0);
		CMOV_EQ(R9D, EBX); // SF == OF
		break;

	case 0x7E:
	case 0x8E:
		LD_ZF(EAX);
		MOV(R8D, 0);
		MOV(EBX, 1);
		CMP(EAX, 0);
		CMOV_EQ(R8D, EBX);
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EBX, EDX);
		LD_SF(EAX, EDX);
		SHR(EBX, 0x1F);
		XOR(EAX, EBX);
		MOV(R9D, 0);
		MOV(EBX, 1);
		CMP(EAX, 1);
		CMOV_EQ(R9D, EBX);
		OR(R8D, R9D);
		CMP(R8D, 1);
		MOV(R9D, next_eip);
		MOV(EBX, jmp_eip);
		CMOV_EQ(R9D, EBX); // ZF != 0 OR SF != OF
		break;

	case 0x7F:
	case 0x8F:
		LD_ZF(EAX);
		MOV(R8D, 0);
		MOV(EBX, 1);
		CMP(EAX, 0);
		CMOV_NE(R8D, EBX);
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EBX, EDX);
		LD_SF(EAX, EDX);
		SHR(EBX, 0x1F);
		XOR(EAX, EBX);
		MOV(R9D, 0);
		MOV(EBX, 1);
		CMP(EAX, 0);
		CMOV_EQ(R9D, EBX);
		AND(R8D, R9D);
		CMP(R8D, 1);
		MOV(R9D, next_eip);
		MOV(EBX, jmp_eip);
		CMOV_EQ(R9D, EBX); // ZF == 0 AND SF == OF
		break;

	case 0xE3:
		if (m_cpu->addr_mode == ADDR16) {
			MOVZX(EAX, MEMD16(RCX, CPU_CTX_ECX));
		}
		else {
			LD_R32(EAX, CPU_CTX_ECX);
		}
		CMP(EAX, 0);
		MOV(R9D, next_eip);
		MOV(EBX, jmp_eip);
		CMOV_EQ(R9D, EBX); // ECX == 0
		break;

	default:
		LIB86CPU_ABORT();
	}

	MOV(MEMD32(RCX, CPU_CTX_EIP), R9D);
	ADD(R9D, m_cpu->cpu_ctx.regs.cs_hidden.base);
	MOV(EBX, R9D);
	gen_link_direct(dst_pc, &next_pc, EBX);

	m_cpu->tc->flags |= TC_FLG_DIRECT;
	m_cpu->translate_next = 0;
}

void
lc86_jit::jmp(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xE9:
	case 0xEB: {
		addr_t new_eip = (m_cpu->virt_pc - m_cpu->cpu_ctx.regs.cs_hidden.base) + m_cpu->instr_bytes + instr->o[OPNUM_SINGLE].imm.value.s;
		if (m_cpu->size_mode == SIZE16) {
			new_eip &= 0x0000FFFF;
		}
		ST_R32(CPU_CTX_EIP, new_eip);
		gen_link_direct(m_cpu->cpu_ctx.regs.cs_hidden.base + new_eip, nullptr, m_cpu->cpu_ctx.regs.cs_hidden.base + new_eip);
		m_cpu->tc->flags |= TC_FLG_DIRECT;
	}
	break;

	case 0xEA: {
		addr_t new_eip = instr->o[OPNUM_SINGLE].ptr.offset;
		uint16_t new_sel = instr->o[OPNUM_SINGLE].ptr.segment;
		if (IS_PE_NOT_VM86()) {
			Label exp = m_a.newLabel();
			MOV(MEMD32(RSP, STACK_ARGS_off), m_cpu->instr_eip);
			MOV(R9D, new_eip);
			MOV(R8B, m_cpu->size_mode);
			MOV(DX, new_sel);
			CALL_F(&ljmp_pe_helper);
			TEST(EAX, EAX);
			BR_NE(exp);
			gen_link_indirect();
			m_a.bind(exp);
			RAISEin_no_param_f();
			m_cpu->tc->flags |= TC_FLG_INDIRECT;
		}
		else {
			new_eip = m_cpu->size_mode == SIZE16 ? new_eip & 0xFFFF : new_eip;
			ST_R16(CPU_CTX_CS, new_sel);
			ST_R32(CPU_CTX_EIP, new_eip);
			ST_R32(CPU_CTX_CS_BASE, static_cast<uint32_t>(new_sel) << 4);
			gen_link_direct((static_cast<uint32_t>(new_sel) << 4) + new_eip, nullptr, (static_cast<uint32_t>(new_sel) << 4) + new_eip);
			m_cpu->tc->flags |= TC_FLG_DIRECT;
		}
	}
	break;

	case 0xFF: {
		if (instr->i.raw.modrm.reg == 4) {
			get_rm<OPNUM_SINGLE>(instr,
				[this](const op_info rm)
				{
					LD_REG_val(SIZED_REG(x64::rax, m_cpu->size_mode), rm.val, rm.bits);
				},
				[this](const op_info rm)
				{
					LD_MEM();
				});
			if (m_cpu->size_mode == SIZE16) {
				MOVZX(EAX, AX);
			}
			ST_R32(CPU_CTX_EIP, EAX);
			gen_link_indirect();
			m_cpu->tc->flags |= TC_FLG_INDIRECT;
		}
		else if (instr->i.raw.modrm.reg == 5) {
			assert(instr->o[OPNUM_SINGLE].type == ZYDIS_OPERAND_TYPE_MEMORY);

			GET_OP(OPNUM_SINGLE);
			MOV(EBX, EDX);
			LD_MEM();
			if (m_cpu->size_mode == SIZE16) {
				MOVZX(EAX, AX);
				ADD(EBX, 2);
			}
			else {
				ADD(EBX, 4);
			}
			MOV(EDX, EBX);
			MOV(EBX, EAX);
			LD_MEMs(SIZE16);

			if (IS_PE_NOT_VM86()) {
				Label exp = m_a.newLabel();
				MOV(MEMD32(RSP, STACK_ARGS_off), m_cpu->instr_eip);
				MOV(R9D, EBX);
				MOV(R8B, m_cpu->size_mode);
				MOV(DX, AX);
				CALL_F(&ljmp_pe_helper);
				TEST(EAX, EAX);
				BR_NE(exp);
				gen_link_indirect();
				m_a.bind(exp);
				RAISEin_no_param_f();
				m_cpu->tc->flags |= TC_FLG_INDIRECT;
			}
			else {
				ST_R16(CPU_CTX_CS, AX);
				ST_R32(CPU_CTX_EIP, EBX);
				MOVZX(EAX, AX);
				SHL(EAX, 4);
				ST_R32(CPU_CTX_CS_BASE, EAX);
				gen_link_indirect();
				m_cpu->tc->flags |= TC_FLG_INDIRECT;
			}
		}
		else {
			LIB86CPU_ABORT();
		}
	}
	break;

	default:
		LIB86CPU_ABORT();
	}

	m_cpu->translate_next = 0;
}

void
lc86_jit::lahf(decoded_instr *instr)
{
	// NOTE: this is optimized code generated by MSVC from a custom C++ implementation

	MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
	MOVZX(EAX, MEMD8(RCX, CPU_CTX_EFLAGS_AUX + 1));
	MOVZX(EBX, DL);
	XOR(RBX, RAX);
	MOV(RAX, &m_cpu->cpu_ctx.lazy_eflags.parity);
	MOVZX(R8D, MEMS8(RBX, RAX, 0));
	XOR(EAX, EAX);
	XOR(R8D, 1);
	MOV(EBX, 0x10);
	TEST(EDX, EDX);
	MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
	CMOV_EQ(EAX, EBX);
	MOV(EBX, EDX);
	OR(R8D, EAX);
	SHL(EBX, 7);
	MOVZX(EAX, MEMD8(RCX, CPU_CTX_EFLAGS_RES + 3));
	XOR(EAX, EBX);
	SHL(R8D, 2);
	AND(EAX, 0x80);
	MOV(EBX, EDX);
	AND(EBX, 8);
	SHR(EDX, 0x1F);
	OR(R8D, 2);
	ADD(EBX, EBX);
	OR(EAX, R8D);
	OR(EAX, EBX);
	OR(EAX, EDX);

	ST_R8H(CPU_CTX_EAX, AL);
}

void
lc86_jit::lea(decoded_instr *instr)
{
	assert(instr->o[OPNUM_SRC].type == ZYDIS_OPERAND_TYPE_MEMORY);

	get_operand<false>(instr, OPNUM_SRC);
	auto dst = GET_REG(OPNUM_DST);
	if (m_cpu->size_mode == SIZE16) {
		ST_R16(dst.val, DX);
	}
	else {
		ST_R32(dst.val, EDX);
	}
}

void
lc86_jit::leave(decoded_instr *instr)
{
	if (m_cpu->cpu_ctx.hflags & HFLG_SS32) {
		LD_R32(EAX, CPU_CTX_EBP);
		ST_R32(CPU_CTX_ESP, EAX);
	}
	else {
		LD_R16(AX, CPU_CTX_EBP);
		ST_R16(CPU_CTX_ESP, AX);
	}

	gen_stack_pop<1>();

	if (m_cpu->size_mode == SIZE32) {
		ST_R32(CPU_CTX_EBP, R11D);
	}
	else {
		ST_R16(CPU_CTX_EBP, R11W);
	}
}

void
lc86_jit::lgdt(decoded_instr *instr)
{
	load_sys_seg_reg<GDTR_idx>(instr);
}

void
lc86_jit::lidt(decoded_instr *instr)
{
	load_sys_seg_reg<IDTR_idx>(instr);
}

void
lc86_jit::lldt(decoded_instr *instr)
{
	load_sys_seg_reg<LDTR_idx>(instr);
}

void
lc86_jit::lmsw(decoded_instr* instr)
{
	if (m_cpu->cpu_ctx.hflags & HFLG_CPL) {
		RAISEin0_t(EXP_GP);
	}
	else {
		get_rm<OPNUM_SINGLE>(instr,
			[this](const op_info rm)
			{
				LD_R16(AX, rm.val);
			},
			[this](const op_info rm)
			{
				LD_MEMs(SIZE16);
			});

		if (IS_PE()) {
			OR(AX, CR0_PE_MASK);
		}

		MOVZX(EDX, AX);
		MOV(R8D, CR0_idx - CR_offset);
		CALL_F(&update_crN_helper<1>);

		ST_R32(CPU_CTX_EIP, m_cpu->instr_eip + m_cpu->instr_bytes);
		gen_no_link_checks();
		m_cpu->translate_next = 0;
	}
}

void
lc86_jit::lods(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xAC:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xAD: {
		// technically, the effect of repnz on instructions that don't support it is officially undefined, but test80186 relies on it
		// https://en.wikipedia.org/wiki/X86_instruction_listings#Undocumented_instructions
		Label start, end = m_a.newLabel();
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPNZ)) {
			start = rep_start(end);
		}

		LD_SEG_BASE(EAX, get_seg_prfx_offset(instr));
		if (m_cpu->addr_mode == ADDR16) {
			MOVZX(EDX, MEMD16(RCX, CPU_CTX_ESI));
		}
		else {
			LD_R32(EDX, CPU_CTX_ESI);
		}
		MOV(EBX, EDX);
		ADD(EDX, EAX);

		LD_MEM();
		auto eax_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
		ST_REG_val(eax_host_reg, CPU_CTX_EAX, m_cpu->size_mode);

		Label sub = m_a.newLabel();
		uint32_t k = 1 << m_cpu->size_mode;
		LD_R32(EAX, CPU_CTX_EFLAGS);
		AND(EAX, DF_MASK);
		TEST(EAX, EAX);
		BR_NE(sub);

		ADD(EBX, k);
		if (m_cpu->addr_mode == ADDR16) {
			ST_R16(CPU_CTX_ESI, BX);
		}
		else {
			ST_R32(CPU_CTX_ESI, EBX);
		}
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPNZ)) {
			rep<ZYDIS_ATTRIB_HAS_REP>(start, end);
		}
		else {
			BR_UNCOND(end);
		}

		m_a.bind(sub);
		SUB(EBX, k);
		if (m_cpu->addr_mode == ADDR16) {
			ST_R16(CPU_CTX_ESI, BX);
		}
		else {
			ST_R32(CPU_CTX_ESI, EBX);
		}
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPNZ)) {
			rep<ZYDIS_ATTRIB_HAS_REP>(start, end);
		}

		m_a.bind(end);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::loop(decoded_instr *instr)
{
	switch (m_cpu->addr_mode)
	{
	case ADDR16:
		MOVZX(EBX, MEMD16(RCX, CPU_CTX_ECX));
		SUB(EBX, 1);
		ST_R16(CPU_CTX_ECX, BX);
		break;

	case ADDR32:
		LD_R32(EBX, CPU_CTX_ECX);
		SUB(EBX, 1);
		ST_R32(CPU_CTX_ECX, EBX);
		break;

	default:
		LIB86CPU_ABORT();
	}

	Label next = m_a.newLabel();
	Label end = m_a.newLabel();
	TEST(EBX, EBX);
	BR_EQ(next);

	switch (instr->i.opcode)
	{
	case 0xE0:
		LD_ZF(EDX);
		TEST(EDX, EDX);
		BR_EQ(next);
		break;

	case 0xE1:
		LD_ZF(EDX);
		TEST(EDX, EDX);
		BR_NE(next);
		break;

	case 0xE2:
		break;

	default:
		LIB86CPU_ABORT();
	}

	addr_t next_eip = m_cpu->instr_eip + m_cpu->instr_bytes;
	addr_t loop_eip = next_eip + instr->o[OPNUM_SINGLE].imm.value.s;
	if (m_cpu->size_mode == SIZE16) {
		loop_eip &= 0x0000FFFF;
	}
	addr_t next_pc = next_eip + m_cpu->cpu_ctx.regs.cs_hidden.base;
	addr_t dst_pc = loop_eip + m_cpu->cpu_ctx.regs.cs_hidden.base;

	ST_R32(CPU_CTX_EIP, loop_eip);
	MOV(EBX, dst_pc);
	BR_UNCOND(end);
	m_a.bind(next);
	ST_R32(CPU_CTX_EIP, next_eip);
	MOV(EBX, next_pc);
	m_a.bind(end);

	gen_link_direct(dst_pc, &next_pc, EBX);
	m_cpu->tc->flags |= TC_FLG_DIRECT;
	m_cpu->translate_next = 0;
}

void
lc86_jit::lds(decoded_instr *instr)
{
	lxs<DS_idx>(instr);
}

void
lc86_jit::les(decoded_instr *instr)
{
	lxs<ES_idx>(instr);
}

void
lc86_jit::lfs(decoded_instr *instr)
{
	lxs<FS_idx>(instr);
}

void
lc86_jit::lgs(decoded_instr *instr)
{
	lxs<GS_idx>(instr);
}

void
lc86_jit::lss(decoded_instr *instr)
{
	lxs<SS_idx>(instr);
}

void
lc86_jit::ltr(decoded_instr *instr)
{
	load_sys_seg_reg<TR_idx>(instr);
}

void
lc86_jit::mov(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x20: {
		if (m_cpu->cpu_ctx.hflags & HFLG_CPL) {
			RAISEin0_t(EXP_GP);
		}
		else {
			op_info src = GET_REG(OPNUM_SRC);
			auto src_host_reg = SIZED_REG(x64::rax, src.bits);
			LD_REG_val(src_host_reg, src.val, src.bits);
			ST_REG_val(src_host_reg, REG_off(instr->o[OPNUM_DST].reg.value), src.bits);
		}
	}
	break;

	case 0x21: {
		Label ok1 = m_a.newLabel();
		LD_R32(EAX, CPU_CTX_DR7);
		AND(EAX, DR7_GD_MASK);
		BR_EQ(ok1);
		LD_R32(EDX, CPU_CTX_DR6);
		OR(EDX, DR6_BD_MASK);
		ST_R32(CPU_CTX_DR6, EDX);
		RAISEin0_f(EXP_DB);
		m_a.bind(ok1);
		if (m_cpu->cpu_ctx.hflags & HFLG_CPL) {
			RAISEin0_t(EXP_GP);
		}
		else {
			size_t dr_offset = REG_off(instr->o[OPNUM_SRC].reg.value);
			if (((instr->o[OPNUM_SRC].reg.value == ZYDIS_REGISTER_DR4) || (instr->o[OPNUM_SRC].reg.value == ZYDIS_REGISTER_DR5))) {
				Label ok2 = m_a.newLabel();
				LD_R32(EDX, CPU_CTX_CR4);
				AND(EDX, CR4_DE_MASK);
				BR_EQ(ok2);
				RAISEin0_f(EXP_UD);
				m_a.bind(ok2);
				// turns dr4/5 to dr6/7
				dr_offset = REG_off((instr->o[OPNUM_SRC].reg.value == ZYDIS_REGISTER_DR4 ? ZYDIS_REGISTER_DR6 : ZYDIS_REGISTER_DR7));
			}
			LD_R32(EAX, dr_offset);
			ST_R32(REG_off(instr->o[OPNUM_DST].reg.value), EAX);
		}
	}
	break;

	case 0x22: {
		if (m_cpu->cpu_ctx.hflags & HFLG_CPL) {
			RAISEin0_t(EXP_GP);
		}
		else {
			LD_R32(EDX, REG_off(instr->o[OPNUM_SRC].reg.value));
			int cr_idx = REG_idx(instr->o[OPNUM_DST].reg.value);
			switch (cr_idx)
			{
			case CR0_idx:
			case CR4_idx:
				m_cpu->translate_next = 0;
				[[fallthrough]];

			case CR3_idx: {
				Label ok = m_a.newLabel();
				MOV(R8D, cr_idx - CR_offset);
				CALL_F(&update_crN_helper<0>);
				TEST(EAX, EAX);
				BR_EQ(ok);
				RAISEin0_f(EXP_GP);
				m_a.bind(ok);
				if ((cr_idx == CR0_idx) || (cr_idx == CR4_idx)) {
					ST_R32(CPU_CTX_EIP, m_cpu->instr_eip + m_cpu->instr_bytes);
					gen_no_link_checks();
				}
			}
			break;

			case CR2_idx:
				ST_R32(CPU_CTX_CR2, EDX);
				break;

			default:
				LIB86CPU_ABORT();
			}
		}
	}
	break;

	case 0x23: {
		Label ok1 = m_a.newLabel();
		LD_R32(EAX, CPU_CTX_DR7);
		AND(EAX, DR7_GD_MASK);
		BR_EQ(ok1);
		LD_R32(EDX, CPU_CTX_DR6);
		OR(EDX, DR6_BD_MASK);
		ST_R32(CPU_CTX_DR6, EDX);
		RAISEin0_f(EXP_DB);
		m_a.bind(ok1);
		if (m_cpu->cpu_ctx.hflags & HFLG_CPL) {
			RAISEin0_t(EXP_GP);
		}
		else {
			auto dr_pair = REG_pair(instr->o[OPNUM_DST].reg.value);
			int dr_idx = dr_pair.first;
			LD_R32(R8D, REG_off(instr->o[OPNUM_SRC].reg.value));
			switch (dr_idx)
			{
			case DR0_idx:
			case DR1_idx:
			case DR2_idx:
			case DR3_idx:
				MOV(DL, dr_idx - DR_offset);
				CALL_F(&update_drN_helper);
				break;

			case DR4_idx: {
				Label ok = m_a.newLabel();
				LD_R32(EDX, CPU_CTX_CR4);
				AND(EDX, CR4_DE_MASK);
				BR_EQ(ok);
				RAISEin0_f(EXP_UD);
				m_a.bind(ok);
			}
			[[fallthrough]];

			case DR6_idx:
				OR(R8D, DR6_RES_MASK);
				ST_R32(CPU_CTX_DR6, R8D);
				break;

			case DR5_idx: {
				Label ok = m_a.newLabel();
				LD_R32(EDX, CPU_CTX_CR4);
				AND(EDX, CR4_DE_MASK);
				BR_EQ(ok);
				RAISEin0_f(EXP_UD);
				m_a.bind(ok);
			}
			[[fallthrough]];

			case DR7_idx:
				MOV(DL, DR7_idx - DR_offset);
				CALL_F(&update_drN_helper);
				break;

			default:
				LIB86CPU_ABORT();
			}

			ST_R32(CPU_CTX_EIP, m_cpu->instr_eip + m_cpu->instr_bytes);
			// instr breakpoint are checked at compile time, so we cannot jump to the next tc if we are writing to anything but dr6
			if ((((m_cpu->virt_pc + m_cpu->instr_bytes) & ~PAGE_MASK) == (m_cpu->virt_pc & ~PAGE_MASK)) && (dr_idx == DR6_idx)) {
				gen_link_dst_only();
				m_cpu->tc->flags |= TC_FLG_DST_ONLY;
			}
			else {
				gen_no_link_checks();
			}
			m_cpu->translate_next = 0;
		}
	}
	break;

	case 0x88:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x89: {
		auto src = GET_REG(OPNUM_SRC);
		auto src_host_reg = SIZED_REG(x64::rax, src.bits);
		LD_REG_val(src_host_reg, src.val, src.bits);
		get_rm<OPNUM_DST>(instr,
			[this, src, src_host_reg](const op_info rm)
			{
				ST_REG_val(src_host_reg, rm.val, src.bits);
			},
			[this, src_host_reg](const op_info rm)
			{
				ST_MEM(src_host_reg);
			});
	}
	break;

	case 0x8A:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x8B: {
		auto dst = GET_REG(OPNUM_DST);
		get_rm<OPNUM_SRC>(instr,
			[this, dst](const op_info rm)
			{
				auto src_host_reg = SIZED_REG(x64::rax, rm.bits);
				LD_REG_val(src_host_reg, rm.val, rm.bits);
				ST_REG_val(src_host_reg, dst.val, rm.bits);
			},
			[this, dst](const op_info rm)
			{
				LD_MEM();
				ST_REG_val(SIZED_REG(x64::rax, m_cpu->size_mode), dst.val, dst.bits);
			});
	}
	break;

	case 0x8C: {
		LD_SEG(AX, REG_off(instr->o[OPNUM_SRC].reg.value));
		get_rm<OPNUM_DST>(instr,
			[this](const op_info rm)
			{
				MOVZX(EAX, AX);
				ST_REG_val(EAX, rm.val, SIZE32);
			},
			[this](const op_info rm)
			{
				ST_MEMs(AX, SIZE16);
			});
	}
	break;

	case 0x8E: {
		get_rm<OPNUM_SRC>(instr,
			[this](const op_info rm)
			{
				LD_REG_val(SIZED_REG(x64::rax, rm.bits), rm.val, rm.bits);
			},
			[this](const op_info rm)
			{
				LD_MEM();
			});
		if (IS_PE_NOT_VM86()) {
			MOV(R8D, m_cpu->instr_eip);
			MOV(DX, AX);

			switch (REG_idx(instr->o[OPNUM_DST].reg.value))
			{
			case SS_idx:
				CALL_F(&mov_sel_pe_helper<SS_idx>);
				break;

			case DS_idx:
				CALL_F(&mov_sel_pe_helper<DS_idx>);
				break;

			case ES_idx:
				CALL_F(&mov_sel_pe_helper<ES_idx>);
				break;

			case FS_idx:
				CALL_F(&mov_sel_pe_helper<FS_idx>);
				break;

			case GS_idx:
				CALL_F(&mov_sel_pe_helper<GS_idx>);
				break;

			default:
				LIB86CPU_ABORT();
			}

			Label ok = m_a.newLabel();
			TEST(EAX, EAX);
			BR_EQ(ok);
			RAISEin_no_param_f();
			m_a.bind(ok);
		}
		else {
			const size_t seg_offset = REG_off(instr->o[OPNUM_DST].reg.value);
			ST_SEG(seg_offset, AX);
			MOVZX(EAX, AX);
			SHL(EAX, 4);
			ST_SEG_BASE(seg_offset, EAX);
		}

		if (instr->o[OPNUM_DST].reg.value == ZYDIS_REGISTER_SS) {
			MOV(EAX, MEMD32(RCX, CPU_CTX_HFLG));
			OR(EAX, HFLG_INHIBIT_INT);
			MOV(MEMD32(RCX, CPU_CTX_HFLG), EAX);
			ST_R32(CPU_CTX_EIP, m_cpu->instr_eip + m_cpu->instr_bytes);

			gen_link_dst_cond([this] {
				MOV(EBX, MEMD32(RCX, CPU_CTX_HFLG));
				TEST(EBX, HFLG_SS32);
				});
			m_cpu->translate_next = 0;
		}
	}
	break;

	case 0xA0:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xA1: {
		GET_OP(OPNUM_SRC);
		LD_MEM();
		ST_REG_val(SIZED_REG(x64::rax, m_cpu->size_mode), GET_REG(OPNUM_DST).val, m_cpu->size_mode);
	}
	break;

	case 0xA2:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xA3: {
		GET_OP(OPNUM_DST);
		op_info src = GET_OP(OPNUM_SRC);
		auto src_host_reg = SIZED_REG(x64::r8, src.bits);
		LD_REG_val(src_host_reg, src.val, src.bits);
		ST_MEM(src_host_reg);
	}
	break;

	case 0xB0:
	case 0xB1:
	case 0xB2:
	case 0xB3:
	case 0xB4:
	case 0xB5:
	case 0xB6:
	case 0xB7: {
		auto dst = GET_OP(OPNUM_DST);
		ST_REG_val(GET_IMM(), dst.val, dst.bits);
	}
	break;

	case 0xB8:
	case 0xB9:
	case 0xBA:
	case 0xBB:
	case 0xBC:
	case 0xBD:
	case 0xBE:
	case 0xBF: {
		auto dst = GET_OP(OPNUM_DST);
		ST_REG_val(GET_IMM(), dst.val, dst.bits);
	}
	break;

	case 0xC6:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xC7: {
		get_rm<OPNUM_DST>(instr,
			[this, instr](const op_info rm)
			{
				ST_REG_val(GET_IMM(), rm.val, rm.bits);
			},
			[this, instr](const op_info rm)
			{
				ST_MEM(GET_IMM());
			});
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::movaps(decoded_instr *instr)
{
	if (!((m_cpu->cpu_ctx.hflags & (HFLG_CR0_TS | HFLG_CR4_OSFXSR | HFLG_CR0_EM)) == HFLG_CR4_OSFXSR)) {
		RAISEin0_t((m_cpu->cpu_ctx.hflags & HFLG_CR0_TS) ? EXP_NM : EXP_UD);
	}
	else {
		switch (instr->i.opcode)
		{
		case 0x28: {
			const auto dst = GET_REG(OPNUM_DST);
			get_rm<OPNUM_SRC>(instr,
				[this, dst](const op_info rm)
				{
					MOVAPS(XMM0, MEMD128(RCX, rm.val));
					MOVAPS(MEMD128(RCX, dst.val), XMM0);
				},
				[this, dst](const op_info rm)
				{
					gen_simd_mem_align_check();
					LD_MEM128();
					MOVAPS(XMM0, MEM128(RAX));
					MOVAPS(MEMD128(RCX, dst.val), XMM0);
				});
		}
		break;

		case 0x29: {
			const auto src = GET_REG(OPNUM_SRC);
			get_rm<OPNUM_DST>(instr,
				[this, src](const op_info rm)
				{
					MOVAPS(XMM0, MEMD128(RCX, src.val));
					MOVAPS(MEMD128(RCX, rm.val), XMM0);
				},
				[this, src](const op_info rm)
				{
					gen_simd_mem_align_check();
					LEA(R8, MEMD64(RCX, src.val));
					ST_MEM128(R8);
				});
		}
		break;

		default:
			LIB86CPU_ABORT();
		}
	}
}

void
lc86_jit::movntps(decoded_instr *instr)
{
	if (!((m_cpu->cpu_ctx.hflags & (HFLG_CR0_TS | HFLG_CR4_OSFXSR | HFLG_CR0_EM)) == HFLG_CR4_OSFXSR)) {
		RAISEin0_t((m_cpu->cpu_ctx.hflags & HFLG_CR0_TS) ? EXP_NM : EXP_UD);
	}
	else {
		if (instr->i.opcode == 0x2B) {
			const auto src = GET_REG(OPNUM_SRC);
			get_rm<OPNUM_DST>(instr,
				[](const op_info rm)
				{
					assert(0);
				},
				[this, src](const op_info rm)
				{
					// we don't emulate the processor's caches, so we don't care about the write-combine policy that this instruction uses
					gen_simd_mem_align_check();
					LEA(R8, MEMD64(RCX, src.val));
					ST_MEM128(R8);
				});
		}
		else {
			LIB86CPU_ABORT();
		}
	}
}

void
lc86_jit::movs(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xA4:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xA5: {
		// technically, the effect of repnz on instructions that don't support it is officially undefined, but test80186 relies on it
		// https://en.wikipedia.org/wiki/X86_instruction_listings#Undocumented_instructions
		Label start, end = m_a.newLabel();
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPNZ)) {
			start = rep_start(end);
		}

		LD_SEG_BASE(EAX, get_seg_prfx_offset(instr));
		if (m_cpu->addr_mode == ADDR16) {
			MOVZX(EDX, MEMD16(RCX, CPU_CTX_ESI));
		}
		else {
			LD_R32(EDX, CPU_CTX_ESI);
		}
		MOV(MEMD32(RSP, LOCAL_VARS_off(0)), EDX);
		ADD(EDX, EAX);

		LD_MEM();

		LD_SEG_BASE(R8D, CPU_CTX_ES);
		if (m_cpu->addr_mode == ADDR16) {
			MOVZX(EDX, MEMD16(RCX, CPU_CTX_EDI));
		}
		else {
			LD_R32(EDX, CPU_CTX_EDI);
		}
		MOV(EBX, EDX);
		ADD(EDX, R8D);

		auto eax_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
		ST_MEM(eax_host_reg);

		Label sub = m_a.newLabel();
		uint32_t k = 1 << m_cpu->size_mode;
		MOV(EAX, MEMD32(RSP, LOCAL_VARS_off(0)));
		LD_R32(EDX, CPU_CTX_EFLAGS);
		AND(EDX, DF_MASK);
		TEST(EDX, EDX);
		BR_NE(sub);

		ADD(EBX, k);
		ADD(EAX, k);
		if (m_cpu->addr_mode == ADDR16) {
			ST_R16(CPU_CTX_EDI, BX);
			ST_R16(CPU_CTX_ESI, AX);
		}
		else {
			ST_R32(CPU_CTX_EDI, EBX);
			ST_R32(CPU_CTX_ESI, EAX);
		}
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPNZ)) {
			rep<ZYDIS_ATTRIB_HAS_REP>(start, end);
		}
		else {
			BR_UNCOND(end);
		}

		m_a.bind(sub);
		SUB(EBX, k);
		SUB(EAX, k);
		if (m_cpu->addr_mode == ADDR16) {
			ST_R16(CPU_CTX_EDI, BX);
			ST_R16(CPU_CTX_ESI, AX);
		}
		else {
			ST_R32(CPU_CTX_EDI, EBX);
			ST_R32(CPU_CTX_ESI, EAX);
		}
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPNZ)) {
			rep<ZYDIS_ATTRIB_HAS_REP>(start, end);
		}

		m_a.bind(end);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::movsx(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xBE:
	case 0xBF: {
		const auto dst = GET_REG(OPNUM_DST);
		auto dst_host_reg = SIZED_REG(x64::rbx, dst.bits);
		get_rm<OPNUM_SRC>(instr,
			[this, dst_host_reg, dst](const op_info rm)
			{
				auto src_host_reg = SIZED_REG(x64::rax, rm.bits);
				LD_REG_val(src_host_reg, rm.val, rm.bits);
				MOVSX(dst_host_reg, src_host_reg);
				ST_REG_val(dst_host_reg, dst.val, dst.bits);
			},
			[this, dst_host_reg, dst, instr](const op_info rm)
			{
				m_cpu->size_mode = instr->i.opcode == 0xBE ? SIZE8 : SIZE16;
				auto src_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
				LD_MEM();
				MOVSX(dst_host_reg, src_host_reg);
				ST_REG_val(dst_host_reg, dst.val, dst.bits);
			});
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::movzx(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xB6:
	case 0xB7: {
		const auto dst = GET_REG(OPNUM_DST);
		auto dst_host_reg = SIZED_REG(x64::rbx, dst.bits);
		get_rm<OPNUM_SRC>(instr,
			[this, dst_host_reg, dst](const op_info rm)
			{
				auto src_host_reg = SIZED_REG(x64::rax, rm.bits);
				LD_REG_val(src_host_reg, rm.val, rm.bits);
				MOVZX(dst_host_reg, src_host_reg);
				ST_REG_val(dst_host_reg, dst.val, dst.bits);
			},
			[this, dst_host_reg, dst, instr](const op_info rm)
			{
				m_cpu->size_mode = instr->i.opcode == 0xB6 ? SIZE8 : SIZE16;
				auto src_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
				LD_MEM();
				MOVZX(dst_host_reg, src_host_reg);
				ST_REG_val(dst_host_reg, dst.val, dst.bits);
			});
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::mul(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xF6:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xF7: {
		assert(instr->i.raw.modrm.reg == 4);

		switch (m_cpu->size_mode)
		{
		case SIZE8:
			get_rm<OPNUM_SINGLE>(instr,
				[this](const op_info rm)
				{
					LD_REG_val(BL, rm.val, rm.bits);
					LD_REG_val(AL, CPU_CTX_EAX, SIZE8);
				},
				[this](const op_info rm)
				{
					LD_MEM();
					LD_REG_val(BL, CPU_CTX_EAX, SIZE8);
				});
			MUL(BL);
			ST_R16(CPU_CTX_EAX, AX);
			break;

		case SIZE16:
			get_rm<OPNUM_SINGLE>(instr,
				[this](const op_info rm)
				{
					LD_REG_val(BX, rm.val, rm.bits);
					LD_REG_val(AX, CPU_CTX_EAX, SIZE16);
				},
				[this](const op_info rm)
				{
					LD_MEM();
					LD_REG_val(BX, CPU_CTX_EAX, SIZE16);
				});
			MUL(BX);
			ST_R16(CPU_CTX_EAX, AX);
			ST_R16(CPU_CTX_EDX, DX);
			break;

		case SIZE32:
			get_rm<OPNUM_SINGLE>(instr,
				[this](const op_info rm)
				{
					LD_REG_val(EBX, rm.val, rm.bits);
					LD_REG_val(EAX, CPU_CTX_EAX, SIZE32);
				},
				[this](const op_info rm)
				{
					LD_MEM();
					LD_REG_val(EBX, CPU_CTX_EAX, SIZE32);
				});
			MUL(EBX);
			ST_R32(CPU_CTX_EAX, EAX);
			ST_R32(CPU_CTX_EDX, EDX);
			break;

		default:
			LIB86CPU_ABORT();
		}
	}
	break;

	default:
		LIB86CPU_ABORT();
	}

	SETC(BL);
	SETO(DL);
	MOVZX(EBX, BL);
	MOVZX(EDX, DL);
	XOR(EDX, EBX);
	ADD(EBX, EBX);
	OR(EBX, EDX);
	SHL(EBX, 0x1E);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EBX);
}


void
lc86_jit::neg(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xF6:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xF7:
		assert(instr->i.raw.modrm.reg == 3);

		get_rm<OPNUM_SINGLE>(instr,
			[this](const op_info rm)
			{
				auto rbx_host_reg = SIZED_REG(x64::rbx, rm.bits);
				auto res_host_reg = SIZED_REG(x64::r8, rm.bits);
				LD_REG_val(rbx_host_reg, rm.val, rm.bits);
				MOV(res_host_reg, rbx_host_reg);
				NEG(res_host_reg);
				ST_REG_val(res_host_reg, rm.val, rm.bits);
				set_flags_sub(0, rbx_host_reg, res_host_reg);
			},
			[this](const op_info rm)
			{
				auto rax_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
				auto rbx_host_reg = SIZED_REG(x64::rbx, m_cpu->size_mode);
				auto r8_host_reg = SIZED_REG(x64::r8, m_cpu->size_mode);
				MOV(EBX, EDX);
				LD_MEM();
				MOV(EDX, EBX);
				MOV(rbx_host_reg, rax_host_reg);
				NEG(rax_host_reg);
				MOV(MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode), rax_host_reg);
				ST_MEM(rax_host_reg);
				MOV(r8_host_reg, MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode));
				set_flags_sub(0, rbx_host_reg, r8_host_reg);
			});
		break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::not_(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xF6:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xF7:
		assert(instr->i.raw.modrm.reg == 2);

		get_rm<OPNUM_SINGLE>(instr,
			[this](const op_info rm)
			{
				auto rax_host_reg = SIZED_REG(x64::rax, rm.bits);
				LD_REG_val(rax_host_reg, rm.val, rm.bits);
				NOT(rax_host_reg);
				ST_REG_val(rax_host_reg, rm.val, rm.bits);
			},
			[this](const op_info rm)
			{
				auto rax_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
				MOV(EBX, EDX);
				LD_MEM();
				MOV(EDX, EBX);
				NOT(rax_host_reg);
				ST_MEM(rax_host_reg);
			});
		break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::or_(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x08:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x09: {
		r_to_rm(instr,
			[this](x86::Gp res_host_reg, x86::Gp src_host_reg)
			{
				OR(res_host_reg, src_host_reg);
			});
	}
	break;

	case 0x0A:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x0B: {
		rm_to_r(instr,
			[this](x86::Gp res_host_reg, x86::Gp src_host_reg)
			{
				OR(res_host_reg, src_host_reg);
			});
	}
	break;

	case 0x0C:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x0D: {
		imm_to_eax(instr,
			[this](x86::Gp res_host_reg, uint32_t src_imm)
			{
				OR(res_host_reg, src_imm);
			});
	}
	break;

	case 0x80:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x81: {
		assert(instr->i.raw.modrm.reg == 1);

		uint32_t src_imm = GET_IMM();
		imm_to_rm<uint32_t>(instr, src_imm,
			[this](x86::Gp res_host_reg, uint32_t src_imm)
			{
				OR(res_host_reg, src_imm);
			});
	}
	break;

	case 0x83: {
		assert(instr->i.raw.modrm.reg == 1);

		if (m_cpu->size_mode == SIZE16) {
			int16_t src_imm = static_cast<int16_t>(static_cast<int8_t>(GET_IMM()));
			imm_to_rm<int16_t>(instr, src_imm,
				[this](x86::Gp res_host_reg, int16_t src_imm)
				{
					OR(res_host_reg, src_imm);
				});
		}
		else {
			int32_t src_imm = static_cast<int32_t>(static_cast<int8_t>(GET_IMM()));
			imm_to_rm<int32_t>(instr, src_imm,
				[this](x86::Gp res_host_reg, int32_t src_imm)
				{
					OR(res_host_reg, src_imm);
				});
		}
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::out(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xE6:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xE7: {
		uint8_t port = instr->o[OPNUM_DST].imm.value.u;
		gen_check_io_priv(port);
		MOV(EDX, port);
		LD_REG_val(SIZED_REG(x64::r8, m_cpu->size_mode), CPU_CTX_EAX, m_cpu->size_mode);
		ST_IO();
	}
	break;

	case 0xEE:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xEF: {
		MOVZX(EDX, MEMD16(RCX, CPU_CTX_EDX));
		if (gen_check_io_priv(EDX)) {
			MOV(EDX, MEMD32(RSP, LOCAL_VARS_off(0)));
		}
		LD_REG_val(SIZED_REG(x64::r8, m_cpu->size_mode), CPU_CTX_EAX, m_cpu->size_mode);
		ST_IO();
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::outs(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x6E:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x6F: {
		// technically, the effect of repnz on instructions that don't support it is officially undefined, but test80186 relies on it
		// https://en.wikipedia.org/wiki/X86_instruction_listings#Undocumented_instructions
		Label start, end = m_a.newLabel();
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPNZ)) {
			start = rep_start(end);
		}

		auto val_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
		auto r8_host_reg = SIZED_REG(x64::r8, m_cpu->size_mode);
		LD_SEG_BASE(EAX, get_seg_prfx_offset(instr));
		if (m_cpu->addr_mode == ADDR16) {
			MOVZX(EDX, MEMD16(RCX, CPU_CTX_ESI));
		}
		else {
			LD_R32(EDX, CPU_CTX_ESI);
		}
		MOV(EBX, EDX);
		ADD(EDX, EAX);
		LD_MEM();
		MOV(MEMD(RSP, LOCAL_VARS_off(1), m_cpu->size_mode), val_host_reg);

		MOVZX(EDX, MEMD16(RCX, CPU_CTX_EDX));
		if (gen_check_io_priv(EDX)) {
			MOV(EDX, MEMD32(RSP, LOCAL_VARS_off(0)));
		}
		MOV(r8_host_reg, MEMD(RSP, LOCAL_VARS_off(1), m_cpu->size_mode));
		ST_IO();

		Label sub = m_a.newLabel();
		uint32_t k = 1 << m_cpu->size_mode;
		LD_R32(EAX, CPU_CTX_EFLAGS);
		AND(EAX, DF_MASK);
		TEST(EAX, EAX);
		BR_NE(sub);

		ADD(EBX, k);
		if (m_cpu->addr_mode == ADDR16) {
			ST_R16(CPU_CTX_ESI, BX);
		}
		else {
			ST_R32(CPU_CTX_ESI, EBX);
		}
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPNZ)) {
			rep<ZYDIS_ATTRIB_HAS_REP>(start, end);
		}
		else {
			BR_UNCOND(end);
		}

		m_a.bind(sub);
		SUB(EBX, k);
		if (m_cpu->addr_mode == ADDR16) {
			ST_R16(CPU_CTX_ESI, BX);
		}
		else {
			ST_R32(CPU_CTX_ESI, EBX);
		}
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPNZ)) {
			rep<ZYDIS_ATTRIB_HAS_REP>(start, end);
		}

		m_a.bind(end);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::pop(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x58:
	case 0x59:
	case 0x5A:
	case 0x5B:
	case 0x5C:
	case 0x5D:
	case 0x5E:
	case 0x5F:
		assert(instr->o[OPNUM_SINGLE].type == ZYDIS_OPERAND_TYPE_REGISTER);

		if (m_cpu->size_mode == SIZE16) {
			gen_stack_pop<1>();
			ST_R16(get_reg_offset(instr->o[OPNUM_SINGLE].reg.value), R11W);
		}
		else {
			gen_stack_pop<1>();
			ST_R32(get_reg_offset(instr->o[OPNUM_SINGLE].reg.value), R11D);
		}
		break;

	case 0x8F: {
		assert(instr->i.raw.modrm.reg == 0);

		get_rm<OPNUM_SINGLE>(instr,
			[this](const op_info rm)
			{
				gen_stack_pop<1>();
				auto r11_host_reg = SIZED_REG(x64::r11, rm.bits);
				ST_REG_val(r11_host_reg, rm.val, rm.bits);
			},
			[this](const op_info rm)
			{
				MOV(MEMD32(RSP, LOCAL_VARS_off(0)), EDX);
				gen_stack_pop<1, 0, false>();
				MOV(EDX, MEMD32(RSP, LOCAL_VARS_off(0)));
				auto r11_host_reg = SIZED_REG(x64::r11, m_cpu->size_mode);
				ST_MEM(r11_host_reg);
				if (m_cpu->cpu_ctx.hflags & HFLG_SS32) {
					ST_R32(CPU_CTX_ESP, EBX);
				}
				else {
					ST_R16(CPU_CTX_ESP, BX);
				}
			});
	}
	break;

	case 0x1F:
	case 0x07:
	case 0x17:
	case 0xA1:
	case 0xA9: {
		const auto sel = get_reg_pair(instr->o[OPNUM_SINGLE].reg.value);
		gen_stack_pop<1, 0, false>();

		if (IS_PE_NOT_VM86()) {
			MOV(R8D, m_cpu->instr_eip);
			MOV(DX, R11W);

			switch (sel.first)
			{
			case SS_idx:
				CALL_F(&mov_sel_pe_helper<SS_idx>);
				break;

			case FS_idx:
				CALL_F(&mov_sel_pe_helper<FS_idx>);
				break;

			case GS_idx:
				CALL_F(&mov_sel_pe_helper<GS_idx>);
				break;

			case ES_idx:
				CALL_F(&mov_sel_pe_helper<ES_idx>);
				break;

			case DS_idx:
				CALL_F(&mov_sel_pe_helper<DS_idx>);
				break;

			default:
				LIB86CPU_ABORT();
			}

			Label ok = m_a.newLabel();
			TEST(EAX, EAX);
			BR_EQ(ok);
			RAISEin_no_param_f();
			m_a.bind(ok);
			if (m_cpu->cpu_ctx.hflags & HFLG_SS32) {
				ST_R32(CPU_CTX_ESP, EBX);
			}
			else {
				ST_R16(CPU_CTX_ESP, BX);
			}
		}
		else {
			ST_SEG(sel.second, R11W);
			MOVZX(EAX, R11W);
			SHL(EAX, 4);
			ST_SEG_BASE(sel.second, EAX);
			if (m_cpu->cpu_ctx.hflags & HFLG_SS32) {
				ST_R32(CPU_CTX_ESP, EBX);
			}
			else {
				ST_R16(CPU_CTX_ESP, BX);
			}
		}

		if (sel.first == SS_idx) {
			MOV(EAX, MEMD32(RCX, CPU_CTX_HFLG));
			OR(EAX, HFLG_INHIBIT_INT);
			MOV(MEMD32(RCX, CPU_CTX_HFLG), EAX);
			ST_R32(CPU_CTX_EIP, m_cpu->instr_eip + m_cpu->instr_bytes);

			gen_link_dst_cond([this] {
				MOV(EBX, MEMD32(RCX, CPU_CTX_HFLG));
				TEST(EBX, HFLG_SS32);
				});
			m_cpu->translate_next = 0;
		}
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::popa(decoded_instr *instr)
{
	switch ((m_cpu->size_mode << 1) | ((m_cpu->cpu_ctx.hflags & HFLG_SS32) >> SS32_SHIFT))
	{
	case (SIZE32 << 1) | 0: // sp, pop 32
		LD_R16(BX, CPU_CTX_ESP);
		for (int i = 6; i > 3; --i) {
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			MOVZX(EBX, BX);
			ADD(EDX, EBX);
			LD_MEM();
			ST_R32(get_reg_offset(instr->o[i].reg.value), EAX);
			ADD(BX, 4);
		}
		ADD(BX, 4);
		for (int i = 3; i >= 0; --i) {
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			MOVZX(EBX, BX);
			ADD(EDX, EBX);
			LD_MEM();
			ST_R32(get_reg_offset(instr->o[i].reg.value), EAX);
			ADD(BX, 4);
		}
		ST_R16(CPU_CTX_ESP, BX);
		break;

	case (SIZE32 << 1) | 1: // esp, pop 32
		LD_R32(EBX, CPU_CTX_ESP);
		for (int i = 6; i > 3; --i) {
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			ADD(EDX, EBX);
			LD_MEM();
			ST_R32(get_reg_offset(instr->o[i].reg.value), EAX);
			ADD(EBX, 4);
		}
		ADD(EBX, 4);
		for (int i = 3; i >= 0; --i) {
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			ADD(EDX, EBX);
			LD_MEM();
			ST_R32(get_reg_offset(instr->o[i].reg.value), EAX);
			ADD(EBX, 4);
		}
		ST_R32(CPU_CTX_ESP, EBX);
		break;

	case (SIZE16 << 1) | 0: // sp, pop 16
		LD_R16(BX, CPU_CTX_ESP);
		for (int i = 6; i > 3; --i) {
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			MOVZX(EBX, BX);
			ADD(EDX, EBX);
			LD_MEM();
			ST_R16(get_reg_offset(instr->o[i].reg.value), AX);
			ADD(BX, 2);
		}
		ADD(BX, 2);
		for (int i = 3; i >= 0; --i) {
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			MOVZX(EBX, BX);
			ADD(EDX, EBX);
			LD_MEM();
			ST_R16(get_reg_offset(instr->o[i].reg.value), AX);
			ADD(BX, 2);
		}
		ST_R16(CPU_CTX_ESP, BX);
		break;

	case (SIZE16 << 1) | 1: // esp, pop 16
		LD_R32(EBX, CPU_CTX_ESP);
		for (int i = 6; i > 3; --i) {
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			ADD(EDX, EBX);
			LD_MEM();
			ST_R16(get_reg_offset(instr->o[i].reg.value), AX);
			ADD(EBX, 2);
		}
		ADD(EBX, 2);
		for (int i = 3; i >= 0; --i) {
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			ADD(EDX, EBX);
			LD_MEM();
			ST_R16(get_reg_offset(instr->o[i].reg.value), AX);
			ADD(EBX, 2);
		}
		ST_R32(CPU_CTX_ESP, EBX);
		break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::popf(decoded_instr *instr)
{
	// NOTE: this is optimized code generated by MSVC from a custom C++ implementation

	uint32_t mask = TF_MASK | DF_MASK | NT_MASK;
	uint32_t cpl = m_cpu->cpu_ctx.hflags & HFLG_CPL;
	uint32_t iopl = (m_cpu->cpu_ctx.regs.eflags & IOPL_MASK) >> 12;
	if (IS_VM86()) {
		if (iopl == 3) {
			gen_stack_pop<1>();
			if (m_cpu->size_mode == SIZE32) {
				mask |= (IF_MASK | AC_MASK | ID_MASK);
				MOV(EBX, R11D);
			}
			else {
				mask |= IF_MASK;
				MOVZX(EBX, R11W);
			}
		}
		else {
			if ((m_cpu->size_mode | (m_cpu->cpu_ctx.hflags & HFLG_CR4_VME)) == (SIZE16 | HFLG_CR4_VME)) {
				Label ok = m_a.newLabel();
				Label exp = m_a.newLabel();
				gen_stack_pop<1, 0, false>();
				LD_R32(EAX, CPU_CTX_EFLAGS);
				MOVZX(EDX, R11W);
				MOV(R8D, EAX);
				OR(EAX, EDX);
				AND(EAX, IF_MASK | VIP_MASK);
				CMP(EAX, IF_MASK | VIP_MASK);
				BR_EQ(exp);
				TEST(EDX, TF_MASK);
				BR_NE(exp);
				BR_UNCOND(ok);
				m_a.bind(exp);
				RAISEin0_f(EXP_GP);
				m_a.bind(ok);
				if (m_cpu->cpu_ctx.hflags & HFLG_SS32) {
					ST_R32(CPU_CTX_ESP, EBX);
				}
				else {
					ST_R16(CPU_CTX_ESP, BX);
				}
				MOV(EBX, EDX);
				AND(R8D, ~VIF_MASK);
				AND(EDX, IF_MASK);
				SHL(EDX, 10);
				OR(EDX, R8D);
				ST_R32(CPU_CTX_EFLAGS, EDX);
			}
			else {
				RAISEin0_t(EXP_GP);
				return;
			}
		}
	}
	else {
		gen_stack_pop<1>();
		if (cpl == 0) {
			mask |= (IOPL_MASK | IF_MASK);
		}
		else if (iopl >= cpl) {
			mask |= IF_MASK;
		}

		if (m_cpu->size_mode == SIZE32) {
			mask |= (ID_MASK | AC_MASK);
			MOV(EBX, R11D);
		}
		else {
			MOVZX(EBX, R11W);
		}
	}

	MOV(EDX, EBX);
	LD_R32(EAX, CPU_CTX_EFLAGS);
	AND(EAX, ~mask);
	AND(EDX, mask);
	OR(EAX, EDX);
	OR(EAX, 2);
	ST_R32(CPU_CTX_EFLAGS, EAX);

	MOV(R9D, EBX);
	LEA(EAX, MEMSb64(RBX, 2, 0));
	NOT(EAX);
	AND(EAX, 0x100);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), EAX);
	MOV(EDX, EBX);
	SHL(EDX, 0xB);
	MOV(EAX, EBX);
	XOR(EDX, EBX);
	SHL(EAX, 0xC);
	AND(EDX, 0x800);
	SHR(EBX, 6);
	OR(EDX, EAX);
	AND(EBX, 2);
	MOV(EAX, R9D);
	SHL(EDX, 0x13);
	SHL(R9D, 6);
	AND(EAX, 0x10);
	OR(EBX, EAX);
	NOT(R9D);
	SHR(EBX, 1);
	AND(R9D, 0x100);
	OR(EDX, EBX);
	OR(EDX, R9D);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EDX);
	ST_R32(CPU_CTX_EIP, m_cpu->instr_eip + m_cpu->instr_bytes);

	if ((m_cpu->virt_pc & ~PAGE_MASK) == (m_cpu->virt_pc + m_cpu->instr_bytes & ~PAGE_MASK)) {
		gen_link_indirect();
		m_cpu->tc->flags |= TC_FLG_INDIRECT;
	}
	m_cpu->translate_next = 0;
}

void
lc86_jit::push(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x50:
	case 0x51:
	case 0x52:
	case 0x53:
	case 0x54:
	case 0x55:
	case 0x56:
	case 0x57:
		assert(instr->o[OPNUM_SINGLE].type == ZYDIS_OPERAND_TYPE_REGISTER);

		if (m_cpu->size_mode == SIZE16) {
			LD_R16(R8W, get_reg_offset(instr->o[OPNUM_SINGLE].reg.value));
			gen_stack_push(R8W);
		}
		else {
			LD_R32(R8D, get_reg_offset(instr->o[OPNUM_SINGLE].reg.value));
			gen_stack_push(R8D);
		}
		break;

	case 0x68:
		gen_stack_push(instr->o[OPNUM_SINGLE].imm.value.u);
		break;

	case 0x6A:
		if (m_cpu->size_mode == SIZE16) {
			int16_t imm = static_cast<int16_t>(static_cast<int8_t>(instr->o[OPNUM_SINGLE].imm.value.u));
			gen_stack_push(imm);
		}
		else {
			int32_t imm = static_cast<int32_t>(static_cast<int8_t>(instr->o[OPNUM_SINGLE].imm.value.u));
			gen_stack_push(imm);
		}
		break;

	case 0xFF: {
		assert(instr->i.raw.modrm.reg == 6);

		auto r8_host_reg = get_rm<OPNUM_SINGLE>(instr,
			[this](const op_info rm)
			{
				auto r8_host_reg = SIZED_REG(x64::r8, rm.bits);
				LD_REG_val(r8_host_reg, rm.val, rm.bits);
				return r8_host_reg;
			},
			[this](const op_info rm)
			{
				auto rax_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
				auto r8_host_reg = SIZED_REG(x64::r8, m_cpu->size_mode);
				LD_MEM();
				MOV(r8_host_reg, rax_host_reg);
				return r8_host_reg;
			});
		gen_stack_push(r8_host_reg);
	}
	break;

	case 0x06:
	case 0x0E:
	case 0x16:
	case 0x1E:
	case 0xA0:
	case 0xA8:
		assert(instr->o[OPNUM_SINGLE].type == ZYDIS_OPERAND_TYPE_REGISTER);

		if (m_cpu->size_mode == SIZE32) {
			MOVZX(R8D, MEMD16(RCX, get_reg_offset(instr->o[OPNUM_SINGLE].reg.value)));
			gen_stack_push(R8D);
		}
		else {
			LD_R16(R8W, get_reg_offset(instr->o[OPNUM_SINGLE].reg.value));
			gen_stack_push(R8W);
		}
		break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::pusha(decoded_instr *instr)
{
	switch ((m_cpu->size_mode << 1) | ((m_cpu->cpu_ctx.hflags & HFLG_SS32) >> SS32_SHIFT))
	{
	case (SIZE32 << 1) | 0: { // sp, push 32
		LD_R16(BX, CPU_CTX_ESP);
		for (unsigned i = 0; i < 8; ++i) {
			SUB(BX, 4);
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			MOVZX(EBX, BX);
			ADD(EDX, EBX);
			LD_R32(R8D, get_reg_offset(instr->o[i].reg.value));
			ST_MEM(R8D);
		}
		ST_R16(CPU_CTX_ESP, BX);
	}
	break;

	case (SIZE32 << 1) | 1: { // esp, push 32
		LD_R32(EBX, CPU_CTX_ESP);
		for (unsigned i = 0; i < 8; ++i) {
			SUB(EBX, 4);
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			ADD(EDX, EBX);
			LD_R32(R8D, get_reg_offset(instr->o[i].reg.value));
			ST_MEM(R8D);
		}
		ST_R32(CPU_CTX_ESP, EBX);
	}
	break;

	case (SIZE16 << 1) | 0: { // sp, push 16
		LD_R16(BX, CPU_CTX_ESP);
		for (unsigned i = 0; i < 8; ++i) {
			SUB(BX, 2);
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			MOVZX(EBX, BX);
			ADD(EDX, EBX);
			LD_R16(R8W, get_reg_offset(instr->o[i].reg.value));
			ST_MEM(R8W);
		}
		ST_R16(CPU_CTX_ESP, BX);
	}
	break;

	case (SIZE16 << 1) | 1: { // esp, push 16
		LD_R32(EBX, CPU_CTX_ESP);
		for (unsigned i = 0; i < 8; ++i) {
			SUB(EBX, 2);
			LD_SEG_BASE(EDX, CPU_CTX_SS);
			ADD(EDX, EBX);
			LD_R16(R8W, get_reg_offset(instr->o[i].reg.value));
			ST_MEM(R8W);
		}
		ST_R32(CPU_CTX_ESP, EBX);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::pushf(decoded_instr *instr)
{
	// NOTE: this is optimized code generated by MSVC from a custom C++ implementation

	bool vm86_handling = false;
	if ((IS_VM86()) && (((m_cpu->cpu_ctx.regs.eflags & IOPL_MASK) >> 12) < 3)) {
		if ((m_cpu->size_mode | (m_cpu->cpu_ctx.hflags & HFLG_CR4_VME)) == (SIZE16 | HFLG_CR4_VME)) {
			vm86_handling = true;
		}
		else {
			RAISEin0_t(EXP_GP);
			return;
		}
	}

	MOV(R8D, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
	MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
	MOVZX(EAX, MEMD8(RCX, CPU_CTX_EFLAGS_AUX + 1));
	MOVZX(EBX, DL);
	XOR(RBX, RAX);
	MOV(RAX, &m_cpu->cpu_ctx.lazy_eflags.parity);
	MOVZX(R9D, MEMS8(RBX, RAX, 0));
	XOR(EAX, EAX);
	XOR(R9D, 1);
	MOV(EBX, 0x10);
	TEST(EDX, EDX);
	MOV(EDX, R8D);
	CMOV_EQ(EAX, EBX);
	MOV(EBX, R8D);
	OR(R9D, EAX);
	SHR(EBX, 1);
	XOR(EBX, R8D);
	SHL(EDX, 7);
	MOV(EAX, R8D);
	SHL(R9D, 2);
	SHR(EAX, 0xC);
	AND(EBX, 0x40000000);
	OR(EAX, EBX);
	AND(R8D, 8);
	MOVZX(EBX, MEMD8(RCX, CPU_CTX_EFLAGS_RES + 3));
	ADD(R8D, R8D);
	SHR(EAX, 0x13);
	XOR(EDX, EBX);
	OR(EAX, R9D);
	AND(EDX, 0x80);
	OR(EAX, EDX);
	OR(EAX, R8D);

	if (m_cpu->size_mode == SIZE16) {
		if (vm86_handling) {
			LD_R32(R8D, CPU_CTX_EFLAGS);
			MOV(EDX, R8D);
			AND(R8D, VIF_MASK);
			AND(EDX, ~(IF_MASK | IOPL_MASK));
			SHR(R8D, 10);
			OR(R8D, IOPL_MASK);
			OR(R8D, EDX);
		}
		else {
			LD_R16(R8W, CPU_CTX_EFLAGS);
		}
		OR(R8W, AX);
		gen_stack_push(R8W);
	}
	else {
		LD_R32(R8D, CPU_CTX_EFLAGS);
		OR(R8D, EAX);
		AND(R8D, 0xFCFFFF);
		gen_stack_push(R8D);
	}
}

void
lc86_jit::rcl(decoded_instr *instr)
{
	rotate<0>(instr);
}

void
lc86_jit::rcr(decoded_instr *instr)
{
	rotate<1>(instr);
}

void
lc86_jit::rdmsr(decoded_instr *instr)
{
	if (m_cpu->cpu_ctx.hflags & HFLG_CPL) {
		RAISEin0_t(EXP_GP);
	}
	else {
		Label ok = m_a.newLabel();
		CALL_F(&msr_read_helper);
		TEST(EAX, EAX);
		BR_EQ(ok);
		RAISEin0_f(EXP_GP);
		m_a.bind(ok);
	}
}

void
lc86_jit::rdtsc(decoded_instr *instr)
{
	if (m_cpu->cpu_ctx.hflags & HFLG_CPL) {
		Label ok = m_a.newLabel();
		LD_R32(EAX, CPU_CTX_CR4);
		AND(EAX, CR4_TSD_MASK);
		CMP(EAX, 0);
		BR_EQ(ok);
		RAISEin0_f(EXP_GP);
		m_a.bind(ok);
	}

	CALL_F(&cpu_rdtsc_helper);
}

void
lc86_jit::ret(decoded_instr *instr)
{
	bool has_imm_op = false;
	switch (instr->i.opcode)
	{
	case 0xC2:
		has_imm_op = true;
		[[fallthrough]];

	case 0xC3: {
		gen_stack_pop<1>();
		if (m_cpu->size_mode == SIZE16) {
			MOVZX(R11D, R11W);
		}
		ST_R32(CPU_CTX_EIP, R11D);
		if (has_imm_op) {
			if (m_cpu->cpu_ctx.hflags & HFLG_SS32) {
				LD_R32(EAX, CPU_CTX_ESP);
				ADD(EAX, instr->o[OPNUM_SINGLE].imm.value.u);
				ST_R32(CPU_CTX_ESP, EAX);
			}
			else {
				LD_R16(AX, CPU_CTX_ESP);
				ADD(AX, instr->o[OPNUM_SINGLE].imm.value.u);
				ST_R16(CPU_CTX_ESP, AX);
			}
		}
	}
	break;

	case 0xCA:
		has_imm_op = true;
		[[fallthrough]];

	case 0xCB: {
		if (IS_PE_NOT_VM86()) {
			Label ok = m_a.newLabel();
			MOV(R8D, m_cpu->instr_eip);
			MOV(DL, m_cpu->size_mode);
			CALL_F(&lret_pe_helper<false>);
			TEST(EAX, EAX);
			BR_EQ(ok);
			RAISEin_no_param_f();
			m_a.bind(ok);
		}
		else {
			gen_stack_pop<2>();
			if (m_cpu->size_mode == SIZE16) {
				MOVZX(R11D, MEMD16(RSP, LOCAL_VARS_off(0)));
			}
			else {
				MOV(R11D, MEMD32(RSP, LOCAL_VARS_off(0)));
			}
			MOV(R10W, MEMD16(RSP, LOCAL_VARS_off(1)));
			ST_R32(CPU_CTX_EIP, R11D);
			ST_SEG(CPU_CTX_CS, R10W);
			MOVZX(EAX, R10W);
			SHL(EAX, 4);
			ST_SEG_BASE(CPU_CTX_CS, EAX);
		}
		if (has_imm_op) {
			if (m_cpu->cpu_ctx.hflags & HFLG_SS32) {
				LD_R32(EAX, CPU_CTX_ESP);
				ADD(EAX, instr->o[OPNUM_SINGLE].imm.value.u);
				ST_R32(CPU_CTX_ESP, EAX);
			}
			else {
				LD_R16(AX, CPU_CTX_ESP);
				ADD(AX, instr->o[OPNUM_SINGLE].imm.value.u);
				ST_R16(CPU_CTX_ESP, AX);
			}
		}
	}
	break;

	default:
		LIB86CPU_ABORT();
	}

	gen_link_ret();
	m_cpu->tc->flags |= TC_FLG_RET;
	m_cpu->translate_next = 0;
}

void
lc86_jit::rol(decoded_instr *instr)
{
	rotate<2>(instr);
}

void
lc86_jit::ror(decoded_instr *instr)
{
	rotate<3>(instr);
}

void
lc86_jit::sahf(decoded_instr *instr)
{
	// NOTE: this is optimized code generated by MSVC from a custom C++ implementation

	MOVZX(R8D, MEMD8(RCX, CPU_CTX_EAX + 1));
	MOV(EDX, R8D);
	MOV(EBX, R8D);
	AND(EDX, 1);
	AND(EBX, 0x10);
	SHL(EDX, 0x1E);
	LEA(EAX, MEMSb32(R8, 2, 0));
	NOT(EAX);
	AND(EAX, 0x100);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_RES), EAX);
	MOV(R9D, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
	LD_OF(EAX, R9D);
	SHR(EAX, 1);
	XOR(EDX, EAX);
	MOV(EAX, R8D);
	SHR(EAX, 6);
	OR(EBX, EAX);
	MOV(EAX, R8D);
	SHL(EAX, 6);
	NOT(EAX);
	SHR(EBX, 1);
	OR(EDX, EBX);
	SHL(R8D, 0x1F);
	AND(EAX, 0x100);
	OR(EDX, EAX);
	OR(EDX, R8D);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EDX);
}

void
lc86_jit::sar(decoded_instr *instr)
{
	assert(instr->i.raw.modrm.reg == 7);
	shift<2>(instr);
}

void
lc86_jit::sbb(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x18:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x19: {
		r_to_rm_flags<false>(instr,
			[this](x86::Gp sub_host_reg, x86::Gp src_host_reg)
			{
				auto cf_host_reg = SIZED_REG(x64::r9, m_cpu->size_mode);
				LD_CF(R9D);
				SHR(R9D, 31);
				ADD(cf_host_reg, src_host_reg);
				SUB(sub_host_reg, cf_host_reg);
			});
	}
	break;

	case 0x1A:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x1B: {
		rm_to_r_flags<false>(instr,
			[this](x86::Gp sub_host_reg, x86::Gp src_host_reg)
			{
				auto cf_host_reg = SIZED_REG(x64::r9, m_cpu->size_mode);
				LD_CF(R9D);
				SHR(R9D, 31);
				ADD(cf_host_reg, src_host_reg);
				SUB(sub_host_reg, cf_host_reg);
			});
	}
	break;

	case 0x1C:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x1D: {
		imm_to_eax_flags<false>(instr,
			[this](x86::Gp sub_host_reg, uint32_t src_imm)
			{
				auto cf_host_reg = SIZED_REG(x64::r9, m_cpu->size_mode);
				LD_CF(R9D);
				SHR(R9D, 31);
				ADD(cf_host_reg, src_imm);
				SUB(sub_host_reg, cf_host_reg);
			});
	}
	break;

	case 0x80:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x81: {
		assert(instr->i.raw.modrm.reg == 3);

		uint32_t src_imm = GET_IMM();
		imm_to_rm_flags<false, uint32_t>(instr, src_imm,
			[this](x86::Gp sub_host_reg, uint32_t src_imm)
			{
				auto cf_host_reg = SIZED_REG(x64::r9, m_cpu->size_mode);
				LD_CF(R9D);
				SHR(R9D, 31);
				ADD(cf_host_reg, src_imm);
				SUB(sub_host_reg, cf_host_reg);
			});
	}
	break;

	case 0x83: {
		assert(instr->i.raw.modrm.reg == 3);

		if (m_cpu->size_mode == SIZE16) {
			int16_t src_imm = static_cast<int16_t>(static_cast<int8_t>(GET_IMM()));
			imm_to_rm_flags<false, int16_t>(instr, src_imm,
				[this](x86::Gp sub_host_reg, int16_t src_imm)
				{
					auto cf_host_reg = SIZED_REG(x64::r9, m_cpu->size_mode);
					LD_CF(R9D);
					SHR(R9D, 31);
					ADD(cf_host_reg, src_imm);
					SUB(sub_host_reg, cf_host_reg);
				});
		}
		else {
			int32_t src_imm = static_cast<int32_t>(static_cast<int8_t>(GET_IMM()));
			imm_to_rm_flags<false, int32_t>(instr, src_imm,
				[this](x86::Gp sub_host_reg, int32_t src_imm)
				{
					auto cf_host_reg = SIZED_REG(x64::r9, m_cpu->size_mode);
					LD_CF(R9D);
					SHR(R9D, 31);
					ADD(cf_host_reg, src_imm);
					SUB(sub_host_reg, cf_host_reg);
				});
		}
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::scas(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xAE:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xAF: {
		Label start, end = m_a.newLabel();
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REPNZ | ZYDIS_ATTRIB_HAS_REPZ)) {
			start = rep_start(end);
		}

		LD_SEG_BASE(EAX, CPU_CTX_ES);
		if (m_cpu->addr_mode == ADDR16) {
			MOVZX(EDX, MEMD16(RCX, CPU_CTX_EDI));
		}
		else {
			LD_R32(EDX, CPU_CTX_EDI);
		}
		MOV(EBX, EDX);
		ADD(EDX, EAX);

		auto eax_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
		auto edx_host_reg = SIZED_REG(x64::rdx, m_cpu->size_mode);
		auto r8_host_reg = SIZED_REG(x64::r8, m_cpu->size_mode);
		LD_MEM();
		MOV(edx_host_reg, eax_host_reg);
		LD_REG_val(eax_host_reg, CPU_CTX_EAX, m_cpu->size_mode);
		MOV(r8_host_reg, eax_host_reg);
		SUB(r8_host_reg, edx_host_reg);
		set_flags_sub(eax_host_reg, edx_host_reg, r8_host_reg);

		Label sub = m_a.newLabel();
		uint32_t k = 1 << m_cpu->size_mode;
		LD_R32(EAX, CPU_CTX_EFLAGS);
		AND(EAX, DF_MASK);
		TEST(EAX, EAX);
		BR_NE(sub);

		ADD(EBX, k);
		if (m_cpu->addr_mode == ADDR16) {
			ST_R16(CPU_CTX_EDI, BX);
		}
		else {
			ST_R32(CPU_CTX_EDI, EBX);
		}
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REPNZ | ZYDIS_ATTRIB_HAS_REPZ)) {
			if (instr->i.attributes & ZYDIS_ATTRIB_HAS_REPNZ) {
				rep<ZYDIS_ATTRIB_HAS_REPNZ>(start, end);
			}
			else {
				rep<ZYDIS_ATTRIB_HAS_REPZ>(start, end);
			}
		}
		else {
			BR_UNCOND(end);
		}

		m_a.bind(sub);
		SUB(EBX, k);
		if (m_cpu->addr_mode == ADDR16) {
			ST_R16(CPU_CTX_EDI, BX);
		}
		else {
			ST_R32(CPU_CTX_EDI, EBX);
		}
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REPNZ | ZYDIS_ATTRIB_HAS_REPZ)) {
			if (instr->i.attributes & ZYDIS_ATTRIB_HAS_REPNZ) {
				rep<ZYDIS_ATTRIB_HAS_REPNZ>(start, end);
			}
			else {
				rep<ZYDIS_ATTRIB_HAS_REPZ>(start, end);
			}
		}

		m_a.bind(end);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::setcc(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x90:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EAX, EDX);
		CMP(EAX, 0x80000000);
		SET_EQ(R8B); // OF != 0
		break;

	case 0x91:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EAX, EDX);
		CMP(EAX, 0);
		SET_EQ(R8B); // OF == 0
		break;

	case 0x92:
		LD_CF(EAX);
		CMP(EAX, 0x80000000);
		SET_EQ(R8B); // CF != 0
		break;

	case 0x93:
		LD_CF(EAX);
		CMP(EAX, 0);
		SET_EQ(R8B); // CF == 0
		break;

	case 0x94:
		LD_ZF(EAX);
		CMP(EAX, 0);
		SET_EQ(R8B); // ZF != 0
		break;

	case 0x95:
		LD_ZF(EAX);
		CMP(EAX, 0);
		SET_NE(R8B); // ZF == 0
		break;

	case 0x96:
		LD_CF(EAX);
		CMP(EAX, 0x80000000);
		SET_EQ(DL);
		LD_ZF(EAX);
		CMP(EAX, 0);
		SET_EQ(R8B);
		OR(DL, R8B);
		CMP(DL, 1);
		SET_EQ(R8B); // CF != 0 OR ZF != 0
		break;

	case 0x97:
		LD_CF(EAX);
		CMP(EAX, 0);
		SET_EQ(DL);
		LD_ZF(EAX);
		CMP(EAX, 0);
		SET_NE(R8B);
		AND(DL, R8B);
		CMP(DL, 1);
		SET_EQ(R8B); // CF == 0 AND ZF == 0
		break;

	case 0x98:
		MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_SF(EAX, EDX);
		CMP(EAX, 1);
		SET_EQ(R8B); // SF != 0
		break;

	case 0x99:
		MOV(EAX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_SF(EAX, EDX);
		CMP(EAX, 0);
		SET_EQ(R8B); // SF == 0
		break;

	case 0x9A:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		MOV(EBX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_PF(EAX, EDX, EBX);
		CMP(EAX, 0);
		SET_EQ(R8B); // PF != 0
		break;

	case 0x9B:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		MOV(EBX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_PF(EAX, EDX, EBX);
		CMP(EAX, 1);
		SET_EQ(R8B); // PF == 0
		break;

	case 0x9C:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EAX, EDX);
		MOV(EBX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		LD_SF(EBX, EDX);
		SHR(EAX, 0x1F);
		XOR(EAX, EBX);
		CMP(EAX, 1);
		SET_EQ(R8B); // SF != OF
		break;

	case 0x9D:
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EAX, EDX);
		MOV(EBX, MEMD32(RCX, CPU_CTX_EFLAGS_RES));
		LD_SF(EBX, EDX);
		SHR(EAX, 0x1F);
		XOR(EAX, EBX);
		CMP(EAX, 0);
		SET_EQ(R8B); // SF == OF
		break;

	case 0x9E:
		LD_ZF(EAX);
		CMP(EAX, 0);
		SET_EQ(R8B);
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EBX, EDX);
		LD_SF(EAX, EDX);
		SHR(EBX, 0x1F);
		XOR(EAX, EBX);
		CMP(EAX, 1);
		SET_EQ(R9B);
		OR(R8B, R9B);
		CMP(R8B, 1);
		SET_EQ(R8B); // ZF != 0 OR SF != OF
		break;

	case 0x9F:
		LD_ZF(EAX);
		CMP(EAX, 0);
		SET_NE(R8B);
		MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
		LD_OF(EBX, EDX);
		LD_SF(EAX, EDX);
		SHR(EBX, 0x1F);
		XOR(EAX, EBX);
		CMP(EAX, 0);
		SET_EQ(R9B);
		AND(R8B, R9B);
		CMP(R8B, 1);
		SET_EQ(R8B); // ZF == 0 AND SF == OF
		break;

	default:
		LIB86CPU_ABORT();
	}

	get_rm<OPNUM_SINGLE>(instr,
		[this](const op_info rm)
		{
			ST_R8L(rm.val, R8B);
		},
		[this](const op_info rm)
		{
			ST_MEMs(R8B, SIZE8);
		});
}

void
lc86_jit::sgdt(decoded_instr *instr)
{
	store_sys_seg_reg<GDTR_idx>(instr);
}

void
lc86_jit::shl(decoded_instr *instr)
{
	assert(instr->i.raw.modrm.reg == 4);
	shift<0>(instr);
}

void
lc86_jit::shld(decoded_instr *instr)
{
	double_shift<0>(instr);
}

void
lc86_jit::shr(decoded_instr *instr)
{
	assert(instr->i.raw.modrm.reg == 5);
	shift<1>(instr);
}

void
lc86_jit::shrd(decoded_instr *instr)
{
	double_shift<1>(instr);
}

void
lc86_jit::sidt(decoded_instr *instr)
{
	store_sys_seg_reg<IDTR_idx>(instr);
}

void
lc86_jit::sldt(decoded_instr *instr)
{
	store_sys_seg_reg<LDTR_idx>(instr);
}

void
lc86_jit::stc(decoded_instr *instr)
{
	assert(instr->i.opcode == 0xF9);

	MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS_AUX));
	LD_OF(EAX, EDX);
	AND(EDX, 0x3FFFFFFF);
	SHR(EAX, 1);
	XOR(EAX, 0xC0000000);
	OR(EAX, EDX);
	MOV(MEMD32(RCX, CPU_CTX_EFLAGS_AUX), EAX);
}

void
lc86_jit::std(decoded_instr *instr)
{
	assert(instr->i.opcode == 0xFD);

	LD_R32(EDX, CPU_CTX_EFLAGS);
	OR(EDX, DF_MASK);
	ST_R32(CPU_CTX_EFLAGS, EDX);
}

void
lc86_jit::sti(decoded_instr *instr)
{
	assert(instr->i.opcode == 0xFB);

	LD_R32(EAX, CPU_CTX_EFLAGS);
	MOV(EDX, EAX);
	if (IS_PE()) {
		if (((m_cpu->cpu_ctx.regs.eflags & IOPL_MASK) >> 12) >= (m_cpu->cpu_ctx.hflags & HFLG_CPL)) {
			OR(EAX, IF_MASK);
			ST_R32(CPU_CTX_EFLAGS, EAX);
		}
		else {
			if (m_cpu->cpu_ctx.hflags & (HFLG_CR4_VME | HFLG_CR4_PVI)) {
				Label ok = m_a.newLabel();
				TEST(EAX, VIP_MASK);
				BR_EQ(ok);
				RAISEin0_f(EXP_GP);
				m_a.bind(ok);
				OR(EAX, VIF_MASK);
				ST_R32(CPU_CTX_EFLAGS, EAX);
			}
			else {
				RAISEin0_t(EXP_GP);
				return;
			}
		}
	}
	else {
		OR(EAX, IF_MASK);
		ST_R32(CPU_CTX_EFLAGS, EAX);
	}
	Label no_inhibition = m_a.newLabel();
	TEST(EDX, IF_MASK);
	BR_NE(no_inhibition);
	MOV(EAX, MEMD32(RCX, CPU_CTX_HFLG));
	OR(EAX, HFLG_INHIBIT_INT);
	MOV(MEMD32(RCX, CPU_CTX_HFLG), EAX);
	m_a.bind(no_inhibition);
	ST_R32(CPU_CTX_EIP, m_cpu->instr_eip + m_cpu->instr_bytes);

	gen_link_dst_cond([this] {
		MOV(EBX, MEMD32(RCX, CPU_CTX_HFLG));
		TEST(EBX, HFLG_INHIBIT_INT);
		});
	m_cpu->translate_next = 0;
}

void
lc86_jit::stos(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xAA:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xAB: {
		// technically, the effect of repnz on instructions that don't support it is officially undefined, but test80186 relies on it
		// https://en.wikipedia.org/wiki/X86_instruction_listings#Undocumented_instructions
		Label start, end = m_a.newLabel();
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPNZ)) {
			start = rep_start(end);
		}

		LD_SEG_BASE(EAX, CPU_CTX_ES);
		if (m_cpu->addr_mode == ADDR16) {
			MOVZX(EDX, MEMD16(RCX, CPU_CTX_EDI));
		}
		else {
			LD_R32(EDX, CPU_CTX_EDI);
		}
		MOV(EBX, EDX);
		ADD(EDX, EAX);

		uint32_t k;
		switch (m_cpu->size_mode)
		{
		case SIZE8:
			k = 1;
			LD_R8L(R8B, CPU_CTX_EAX);
			ST_MEM(R8B);
			break;

		case SIZE16:
			k = 2;
			LD_R16(R8W, CPU_CTX_EAX);
			ST_MEM(R8W);
			break;

		case SIZE32:
			k = 4;
			LD_R32(R8D, CPU_CTX_EAX);
			ST_MEM(R8D);
			break;

		default:
			LIB86CPU_ABORT();
		}

		Label sub = m_a.newLabel();
		LD_R32(EAX, CPU_CTX_EFLAGS);
		AND(EAX, DF_MASK);
		TEST(EAX, EAX);
		BR_NE(sub);

		ADD(EBX, k);
		if (m_cpu->addr_mode == ADDR16) {
			ST_R16(CPU_CTX_EDI, BX);
		}
		else {
			ST_R32(CPU_CTX_EDI, EBX);
		}
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPNZ)) {
			rep<ZYDIS_ATTRIB_HAS_REP>(start, end);
		}
		else {
			BR_UNCOND(end);
		}

		m_a.bind(sub);
		SUB(EBX, k);
		if (m_cpu->addr_mode == ADDR16) {
			ST_R16(CPU_CTX_EDI, BX);
		}
		else {
			ST_R32(CPU_CTX_EDI, EBX);
		}
		if (instr->i.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPNZ)) {
			rep<ZYDIS_ATTRIB_HAS_REP>(start, end);
		}

		m_a.bind(end);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::str(decoded_instr *instr)
{
	store_sys_seg_reg<TR_idx>(instr);
}

void
lc86_jit::sub(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x28:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x29: {
		r_to_rm_flags<false>(instr,
			[this](x86::Gp sub_host_reg, x86::Gp src_host_reg)
			{
				SUB(sub_host_reg, src_host_reg);
			});
	}
	break;

	case 0x2A:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x2B: {
		rm_to_r_flags<false>(instr,
			[this](x86::Gp sub_host_reg, x86::Gp src_host_reg)
			{
				SUB(sub_host_reg, src_host_reg);
			});
	}
	break;

	case 0x2C:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x2D: {
		imm_to_eax_flags<false>(instr,
			[this](x86::Gp sub_host_reg, uint32_t src_imm)
			{
				SUB(sub_host_reg, src_imm);
			});
	}
	break;

	case 0x80:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x81: {
		assert(instr->i.raw.modrm.reg == 5);

		uint32_t src_imm = GET_IMM();
		imm_to_rm_flags<false, uint32_t>(instr, src_imm,
			[this](x86::Gp sub_host_reg, uint32_t src_imm)
			{
				SUB(sub_host_reg, src_imm);
			});
	}
	break;

	case 0x83: {
		assert(instr->i.raw.modrm.reg == 5);

		if (m_cpu->size_mode == SIZE16) {
			int16_t src_imm = static_cast<int16_t>(static_cast<int8_t>(GET_IMM()));
			imm_to_rm_flags<false, int16_t>(instr, src_imm,
				[this](x86::Gp sub_host_reg, int16_t src_imm)
				{
					SUB(sub_host_reg, src_imm);
				});
		}
		else {
			int32_t src_imm = static_cast<int32_t>(static_cast<int8_t>(GET_IMM()));
			imm_to_rm_flags<false, int32_t>(instr, src_imm,
				[this](x86::Gp sub_host_reg, int32_t src_imm)
				{
					SUB(sub_host_reg, src_imm);
				});
		}
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::test(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x84:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x85: {
		r_to_rm<false>(instr,
			[this](x86::Gp res_host_reg, x86::Gp src_host_reg)
			{
				AND(res_host_reg, src_host_reg);
			});
	}
	break;

	case 0xA8:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xA9: {
		imm_to_eax<false>(instr,
			[this](x86::Gp res_host_reg, uint32_t src_imm)
			{
				AND(res_host_reg, src_imm);
			});
	}
	break;

	case 0xF6:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xF7: {
		uint32_t src_imm = GET_IMM();
		imm_to_rm<uint32_t, false>(instr, src_imm,
			[this](x86::Gp res_host_reg, uint32_t src_imm)
			{
				AND(res_host_reg, src_imm);
			});
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::verr(decoded_instr *instr)
{
	verx<true>(instr);
}

void
lc86_jit::verw(decoded_instr *instr)
{
	verx<false>(instr);
}

void
lc86_jit::wbinvd(decoded_instr *instr)
{
	if (m_cpu->cpu_ctx.hflags & HFLG_CPL) {
		RAISEin0_t(EXP_GP);
	}

	// don't bother, we don't emulate the processor's caches. So, other than checking for a possible exception, this is a nop
}

void
lc86_jit::wrmsr(decoded_instr *instr)
{
	if (m_cpu->cpu_ctx.hflags & HFLG_CPL) {
		RAISEin0_t(EXP_GP);
	}
	else {
		Label ok = m_a.newLabel();
		CALL_F(&msr_write_helper);
		TEST(EAX, EAX);
		BR_EQ(ok);
		RAISEin0_f(EXP_GP);
		m_a.bind(ok);
	}
}

void
lc86_jit::xadd(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0xC0:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0xC1: {
		auto src = GET_REG(OPNUM_SRC);
		auto src_host_reg = SIZED_REG(x64::rbx, src.bits);
		LD_REG_val(src_host_reg, src.val, src.bits);
		get_rm<OPNUM_DST>(instr,
			[this, src, src_host_reg](const op_info rm)
			{
				auto dst_host_reg = SIZED_REG(x64::rax, rm.bits);
				auto res_host_reg = SIZED_REG(x64::r8, rm.bits);
				LD_REG_val(dst_host_reg, rm.val, rm.bits);
				ST_REG_val(dst_host_reg, src.val, src.bits);
				MOV(res_host_reg, dst_host_reg);
				ADD(res_host_reg, src_host_reg);
				ST_REG_val(res_host_reg, rm.val, rm.bits);
				set_flags_sum(dst_host_reg, src_host_reg, res_host_reg);
			},
			[this, src, src_host_reg](const op_info rm)
			{
				auto dst_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
				auto res_host_reg = SIZED_REG(x64::r8, m_cpu->size_mode);
				MOV(MEMD32(RSP, LOCAL_VARS_off(0)), EDX);
				LD_MEM();
				MOV(res_host_reg, dst_host_reg);
				ADD(res_host_reg, src_host_reg);
				MOV(EDX, MEMD32(RSP, LOCAL_VARS_off(0)));
				MOV(MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode), dst_host_reg);
				MOV(MEMD(RSP, LOCAL_VARS_off(1), m_cpu->size_mode), res_host_reg);
				ST_MEM(res_host_reg);
				MOV(dst_host_reg, MEMD(RSP, LOCAL_VARS_off(0), m_cpu->size_mode));
				MOV(res_host_reg, MEMD(RSP, LOCAL_VARS_off(1), m_cpu->size_mode));
				ST_REG_val(dst_host_reg, src.val, src.bits);
				set_flags_sum(dst_host_reg, src_host_reg, res_host_reg);
			});
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::xchg(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x86:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x87: {
		auto src = GET_REG(OPNUM_SRC);
		auto src_host_reg = SIZED_REG(x64::rbx, src.bits);
		LD_REG_val(src_host_reg, src.val, src.bits);
		get_rm<OPNUM_DST>(instr,
			[this, src, src_host_reg](const op_info rm)
			{
				auto dst_host_reg = SIZED_REG(x64::rax, rm.bits);
				LD_REG_val(dst_host_reg, rm.val, rm.bits);
				ST_REG_val(dst_host_reg, src.val, src.bits);
				ST_REG_val(src_host_reg, rm.val, rm.bits);
			},
			[this, src, src_host_reg](const op_info rm)
			{
				auto dst_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
				MOV(MEMD32(RSP, LOCAL_VARS_off(0)), EDX);
				LD_MEM();
				MOV(EDX, MEMD32(RSP, LOCAL_VARS_off(0)));
				ST_REG_val(dst_host_reg, src.val, src.bits);
				ST_MEM(src_host_reg);
			});
	}
	break;

	case 0x90:
	case 0x91:
	case 0x92:
	case 0x93:
	case 0x94:
	case 0x95:
	case 0x96:
	case 0x97: {
		auto dst = GET_REG(OPNUM_DST);
		auto dst_host_reg = SIZED_REG(x64::rax, m_cpu->size_mode);
		auto src_host_reg = SIZED_REG(x64::rdx, m_cpu->size_mode);
		LD_REG_val(dst_host_reg, dst.val, dst.bits);
		LD_REG_val(src_host_reg, CPU_CTX_EAX, m_cpu->size_mode);
		ST_REG_val(dst_host_reg, CPU_CTX_EAX, m_cpu->size_mode);
		ST_REG_val(src_host_reg, dst.val, dst.bits);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::xlat(decoded_instr *instr)
{
	LD_SEG_BASE(EAX, get_seg_prfx_offset(instr));
	if (m_cpu->addr_mode == ADDR16) {
		MOVZX(EDX, MEMD16(RCX, CPU_CTX_EBX));
	}
	else {
		LD_R32(EDX, CPU_CTX_EBX);
	}
	MOVZX(EBX, MEMD8(RCX, CPU_CTX_EAX));
	LEA(EAX, MEMS32(EAX, EBX, 0));
	ADD(EDX, EAX);
	LD_MEMs(SIZE8);
	ST_R8L(CPU_CTX_EAX, AL);
}

void
lc86_jit::xor_(decoded_instr *instr)
{
	switch (instr->i.opcode)
	{
	case 0x30:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x31: {
		r_to_rm(instr,
			[this](x86::Gp res_host_reg, x86::Gp src_host_reg)
			{
				XOR(res_host_reg, src_host_reg);
			});
	}
	break;

	case 0x32:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x33: {
		rm_to_r(instr,
			[this](x86::Gp res_host_reg, x86::Gp src_host_reg)
			{
				XOR(res_host_reg, src_host_reg);
			});
	}
	break;

	case 0x34:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x35: {
		imm_to_eax(instr,
			[this](x86::Gp res_host_reg, uint32_t src_imm)
			{
				XOR(res_host_reg, src_imm);
			});
	}
	break;

	case 0x80:
		m_cpu->size_mode = SIZE8;
		[[fallthrough]];

	case 0x81: {
		uint32_t src_imm = GET_IMM();
		imm_to_rm<uint32_t>(instr, src_imm,
			[this](x86::Gp res_host_reg, uint32_t src_imm)
			{
				XOR(res_host_reg, src_imm);
			});
	}
	break;

	case 0x83: {
		if (m_cpu->size_mode == SIZE16) {
			int16_t src_imm = static_cast<int16_t>(static_cast<int8_t>(GET_IMM()));
			imm_to_rm<int16_t>(instr, src_imm,
				[this](x86::Gp res_host_reg, int16_t src_imm)
				{
					XOR(res_host_reg, src_imm);
				});
		}
		else {
			int32_t src_imm = static_cast<int32_t>(static_cast<int8_t>(GET_IMM()));
			imm_to_rm<int32_t>(instr, src_imm,
				[this](x86::Gp res_host_reg, int32_t src_imm)
				{
					XOR(res_host_reg, src_imm);
				});
		}
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::xorps(decoded_instr *instr)
{
	if (!((m_cpu->cpu_ctx.hflags & (HFLG_CR0_TS | HFLG_CR4_OSFXSR | HFLG_CR0_EM)) == HFLG_CR4_OSFXSR)) {
		RAISEin0_t((m_cpu->cpu_ctx.hflags & HFLG_CR0_TS) ? EXP_NM : EXP_UD);
	}
	else {
		if (instr->i.opcode == 0x57) {
			const auto dst = GET_REG(OPNUM_DST);
			get_rm<OPNUM_SRC>(instr,
				[this, dst](const op_info rm)
				{
					MOVAPS(XMM0, MEMD128(RCX, dst.val));
					XORPS(XMM0, MEMD128(RCX, rm.val));
					MOVAPS(MEMD128(RCX, dst.val), XMM0);
				},
				[this, dst](const op_info rm)
				{
					gen_simd_mem_align_check();
					LD_MEM128();
					MOVAPS(XMM0, MEMD128(RCX, dst.val));
					XORPS(XMM0, MEM128(RAX));
					MOVAPS(MEMD128(RCX, dst.val), XMM0);
				});
		}
		else {
			LIB86CPU_ABORT();
		}
	}
}

#endif
