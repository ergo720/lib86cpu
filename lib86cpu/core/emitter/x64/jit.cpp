/*
 * x86-64 emitter
 *
 * ergo720                Copyright (c) 2022
 */

#include "jit.h"
#include "support.h"
#include "instructions.h"
#include <assert.h>

#ifdef LIB86CPU_X64_EMITTER

// The emitted code assumes that host pointers are 8 bytes
static_assert(sizeof(uint8_t *) == 8, "Pointers must be 8 bytes");

#define BAD LIB86CPU_ABORT_msg("Encountered unimplemented instruction %s", log_instr(m_cpu->virt_pc, instr).c_str())

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

// [reg]
#define MEM8(reg)  x86::byte_ptr(reg)
#define MEM16(reg) x86::word_ptr(reg)
#define MEM32(reg) x86::dword_ptr(reg)
#define MEM64(reg) x86::qword_ptr(reg)
// [reg + disp]
#define MEMD8(reg, disp)  x86::byte_ptr(reg, disp)
#define MEMD16(reg, disp) x86::word_ptr(reg, disp)
#define MEMD32(reg, disp) x86::dword_ptr(reg, disp)
#define MEMD64(reg, disp) x86::qword_ptr(reg, disp)
// [reg + idx * scale], scale specified as 1 << n; e.g. scale = 8 -> n = 3
#define MEMS8(reg, idx, scale)  x86::byte_ptr(reg, idx, scale)
#define MEMS16(reg, idx, scale) x86::word_ptr(reg, idx, scale)
#define MEMS32(reg, idx, scale) x86::dword_ptr(reg, idx, scale)
#define MEMS64(reg, idx, scale) x86::qword_ptr(reg, idx, scale)
// [reg + idx * scale + disp], scale specified as 1 << n; e.g. scale = 8 -> n = 3
#define MEMSD8(reg, idx, scale, disp)  x86::byte_ptr(reg, idx, scale, disp)
#define MEMSD16(reg, idx, scale, disp) x86::word_ptr(reg, idx, scale, disp)
#define MEMSD32(reg, idx, scale, disp) x86::dword_ptr(reg, idx, scale, disp)
#define MEMSD64(reg, idx, scale, disp) x86::qword_ptr(reg, idx, scale, disp)

#define MOV(dst, src) m_a.mov(dst, src)
#define MOVZX(dst, src) m_a.movzx(dst, src)
#define MOVSX(dst, src) m_a.movsx(dst, src)
#define LEA(dst, src) m_a.lea(dst, src)
#define AND(dst, src) m_a.and_(dst, src)
#define OR(dst, src) m_a.or_(dst, src)
#define XOR(dst, src) m_a.xor_(dst, src)
#define SHL(dst, src) m_a.shl(dst, src)
#define ADD(dst, src) m_a.add(dst, src)
#define SUB(dst, src) m_a.sub(dst, src)
#define CALL(addr) m_a.call(addr)
#define RET() m_a.ret()

#define PUSH(dst) m_a.push(dst)
#define POP(dst) m_a.pop(dst)

#define BR_UNCOND(dst) m_a.jmp(dst)
#define BR_NE(label, l, r) Label label ## _taken = m_a.newLabel(); m_a.cmp(l, r); m_a.jne(label ## _taken)

#define LD_R16(dst, reg_offset) MOV(dst, MEMD16(RCX, reg_offset))
#define LD_R32(dst, reg_offset) MOV(dst, MEMD32(RCX, reg_offset))
#define LD_REG_val(info) load_reg(info)
#define LD_SEG_BASE(dst, seg_offset) MOV(dst, MEMD32(RCX, seg_offset + seg_base_offset))

#define LD_MEM() load_mem(0)

#define GET_OP(op) get_operand(instr, op)
#define GET_RM(idx, r, m) 	op_info rm = GET_OP(idx); \
switch (instr->operands[idx].type) \
{ \
case ZYDIS_OPERAND_TYPE_REGISTER: \
	r \
	break; \
\
case ZYDIS_OPERAND_TYPE_MEMORY: \
	m \
	break; \
\
default: \
	LIB86CPU_ABORT_msg("Invalid operand type used in GET_RM macro!"); \
}


lc86_jit::lc86_jit(cpu_t *cpu)
{
	m_cpu = cpu;
	_environment = Environment::host();
	_environment.setObjectFormat(ObjectFormat::kJIT);
	gen_int_fn();
}

void
lc86_jit::start_new_session()
{
	m_code.reset();
	m_code.init(_environment);
	m_code.attach(m_a.as<BaseEmitter>());
}

void
lc86_jit::gen_code_block(translated_code_t *tc)
{
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
	// Increase estimated_code_size by 12 + 12, to accomodate the .pdata and .xdata sections required to unwind the function
	// when an exception is thrown. Note that the sections need to be DWORD aligned
	estimated_code_size += 24;
	estimated_code_size = (estimated_code_size + 3) & ~3;
#endif

	// Increase estimated_code_size by 11, to accomodate the exit function that terminates the execution of this tc.
	// Note that this function should be 16 byte aligned
	estimated_code_size += 11;
	estimated_code_size = (estimated_code_size + 15) & ~15;

	auto block = m_mem.allocate_sys_mem(estimated_code_size);
	if (!block.addr) {
		throw lc86_exp_abort("Failed to allocate memory for the generated code", lc86_status::no_memory);
	}

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
	uint8_t *main_offset = static_cast<uint8_t *>(block.addr) + offset;
	std::memcpy(main_offset, section->data(), buff_size);

#if defined(_WIN64)
	// According to asmjit's source code, the code size can decrease after the relocation above, so we need to query it again
	uint8_t *exit_offset = gen_exception_info(main_offset, m_code.codeSize());
#else
	uint8_t *exit_offset = static_cast<uint8_t *>(block.addr) + offset + buff_size;
#endif

	exit_offset = reinterpret_cast<uint8_t *>((reinterpret_cast<uintptr_t>(exit_offset) + 15) & ~15);


	// Now generate the exit() function. Since it's a leaf function, it doesn't need an exception table on WIN64

	static constexpr uint8_t exit_buff[] = {
		0x48, // rex prefix
		0xB8, // movabs rax, imm64
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0xC3, // ret
	};

	std::memcpy(exit_offset, exit_buff, sizeof(exit_buff));
	*reinterpret_cast<uint64_t *>(exit_offset + 2) = reinterpret_cast<uintptr_t>(tc);

	// This code block is complete, so protect and flush the instruction cache now
	m_mem.protect_sys_mem(block, MEM_READ | MEM_EXEC);

	tc->ptr_code = reinterpret_cast<entry_t>(main_offset);
	tc->jmp_offset[0] = tc->jmp_offset[1] = tc->jmp_offset[2] = reinterpret_cast<entry_t>(exit_offset);
}

void
lc86_jit::gen_int_fn()
{
	// The interrupt function is a leaf function, so it doesn't need an exception table on WIN64

	start_new_session();

	MOV(MEMD8(RCX, CPU_CTX_INT()), DL);
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

	auto block = m_mem.allocate_sys_mem(estimated_code_size);
	if (!block.addr) {
		throw lc86_exp_abort("Failed to allocate memory for the generated code", lc86_status::no_memory);
	}

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

	m_cpu->int_fn = reinterpret_cast<raise_int_t>(static_cast<uint8_t *>(block.addr) + offset);
}

void
lc86_jit::gen_prologue_main()
{
	// Prolog of our main() function:
	// push rdi
	// sub rsp, 0x20 + sizeof(stack args) + sizeof(local vars)
	//
	// NOTE1: we don't know yet how much stack we'll need for the function, so we need to patch the correct amount later
	// NOTE2: for sub, always use the 0x81 opcode, since the opcode 0x83 only accepts imm8, and thus can only represents sizes up to 127
	// 48 83 ec 7f             sub    rsp,0x7f
	// 48 81 ec 80 00 00 00    sub    rsp,0x80
	//
	// RCX always holds the cpu_ctx arg, and should never be changed. Prologue and epilog always push and pop RDI, so it's volatile too.
	// Prefer using RAX, RDX, RDI over R8, R9, R10 and R11 to reduce the code size. Offsets from cpu_ctx can be calculated with displacements,
	// to avoid having to use additional add instructions. Local variables on the stack are currently not supported, but the shadow area to spill
	// registers is (always allocated by the caller of the jitted function)

	PUSH(RDI);
	m_prolog_patch_offset = m_a.offset();
	m_a.long_().sub(RSP, 0);

	m_stack_args_size = 0;
	m_needs_epilogue = true;
}

void
lc86_jit::gen_epilogue_main()
{
	size_t tot_stack_used = 0x20 + m_stack_args_size;
	ADD(RSP, tot_stack_used);
	POP(RDI);
	RET();
	m_a.setOffset(m_prolog_patch_offset);
	m_a.long_().sub(RSP, tot_stack_used);
}

void
lc86_jit::gen_tail_call(x86::Gp addr)
{
	size_t tot_stack_used = 0x20 + m_stack_args_size;
	ADD(RSP, tot_stack_used);
	POP(RDI);
	BR_UNCOND(addr);
}

void
lc86_jit::gen_tc_epilogue()
{
	// update the eip if we stopped decoding without a terminating instr
	if (m_cpu->translate_next == 1) {
		assert((DISAS_FLG_PAGE_CROSS | DISAS_FLG_ONE_INSTR) != 0);
		MOV(MEMD32(RCX, CPU_CTX_EIP()), m_cpu->virt_pc - m_cpu->cpu_ctx.regs.cs_hidden.base);
	}

	// TC_FLG_INDIRECT, TC_FLG_DIRECT and TC_FLG_DST_ONLY already check for rf/single step, so we only need to check them here with
	// TC_FLG_COND_DST_ONLY or if no linking code was emitted
	if ((m_cpu->tc->flags & TC_FLG_COND_DST_ONLY) || ((m_cpu->tc->flags & TC_FLG_LINK_MASK) == 0)) {
		check_rf_single_step_emit();
	}

	if (m_needs_epilogue) {
		gen_epilogue_main();
	}
}

template<typename T1, typename T2, typename T3, typename T4>
void lc86_jit::raise_exp_inline_emit(T1 fault_addr, T2 code, T3 idx, T4 eip)
{
	m_needs_epilogue = false;

	MOV(MEMD32(RCX, CPU_EXP_ADDR()), fault_addr);
	MOV(MEMD16(RCX, CPU_EXP_CODE()), code);
	MOV(MEMD16(RCX, CPU_EXP_IDX()), idx);
	MOV(MEMD32(RCX, CPU_EXP_EIP()), eip);
	MOV(RAX, &cpu_raise_exception<false>);
	CALL(RAX);
	gen_epilogue_main();
}

void
lc86_jit::check_int_emit()
{
	MOV(DL, MEMD8(RCX, CPU_CTX_INT()));
	MOVZX(EAX, DL);
	MOV(RDI, &m_cpu->tc->jmp_offset[TC_JMP_INT_OFFSET]);
	LEA(RDX, MEMS64(RDI, RAX, 3));
	MOV(RAX, MEM64(RDX));
	CALL(RAX);
}

bool
lc86_jit::check_rf_single_step_emit()
{
	if ((m_cpu->cpu_ctx.regs.eflags & (RF_MASK | TF_MASK)) | (m_cpu->cpu_flags & CPU_SINGLE_STEP)) {

		if (m_cpu->cpu_ctx.regs.eflags & (RF_MASK | TF_MASK)) {
			m_cpu->cpu_flags |= CPU_FORCE_INSERT;
		}

		if (m_cpu->cpu_ctx.regs.eflags & RF_MASK) {
			// clear rf if it is set. This happens in the one-instr tc that contains the instr that originally caused the instr breakpoint. This must be done at runtime
			// because otherwise tc_cache_insert will register rf as clear, when it was set at the beginning of this tc
			MOV(EDX, MEMD32(RCX, CPU_CTX_EFLAGS()));
			AND(EDX, ~RF_MASK);
			MOV(MEMD32(RCX, CPU_CTX_EFLAGS()), EDX);
		}

		if ((m_cpu->cpu_ctx.regs.eflags & TF_MASK) | (m_cpu->cpu_flags & CPU_SINGLE_STEP)) {
			// NOTE: if this instr also has a watchpoint, the other DB exp won't be generated
			MOV(EDX, MEMD32(RCX, CPU_CTX_DR6()));
			OR(EDX, DR6_BS_MASK);
			MOV(MEMD32(RCX, CPU_CTX_DR6()), EDX);
			MOV(EDX, MEMD32(RCX, CPU_CTX_EIP()));
			raise_exp_inline_emit(0, 0, EXP_DB, EDX);
			return true;
		}
	}

	return false;
}

template<typename T>
void lc86_jit::link_direct_emit(addr_t dst_pc, addr_t *next_pc, T target_pc)
{
	// dst_pc: destination pc, next_pc: pc of next instr, target_addr: pc where instr jumps to at runtime
	// If target_pc is an integral type, then we know already where the instr will jump, and so we can perform the comparisons at compile time
	// and only emit the taken code path

	m_needs_epilogue = false;

	if (check_rf_single_step_emit()) {
		return;
	}

	// make sure we check for interrupts before jumping to the next tc
	check_int_emit();

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
				MOV(EDI, MEM32(RDX));
				MOV(EAX, ~TC_FLG_JMP_TAKEN);
				AND(EAX, EDI);
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
					BR_NE(ret, target_pc, dst_pc);
					MOV(MEM32(RDX), EAX);
					MOV(RDX, &m_cpu->tc->jmp_offset[0]);
					MOV(RAX, MEM64(RDX));
					gen_tail_call(RAX);
					m_a.bind(ret_taken);
					OR(EAX, TC_JMP_RET << 4);
					MOV(MEM32(RDX), EAX);
					gen_epilogue_main();
				}
			}
			else {
				MOV(RDX, &m_cpu->tc->flags);
				MOV(EDI, MEM32(RDX));
				MOV(EAX, ~TC_FLG_JMP_TAKEN);
				AND(EAX, EDI);
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
					BR_NE(ret, target_pc, *next_pc);
					OR(EAX, TC_JMP_NEXT_PC << 4);
					MOV(MEM32(RDX), EAX);
					MOV(RDX, &m_cpu->tc->jmp_offset[1]);
					MOV(RAX, MEM64(RDX));
					gen_tail_call(RAX);
					m_a.bind(ret_taken);
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
		MOV(EDI, MEM32(RDX));
		MOV(EAX, ~TC_FLG_JMP_TAKEN);
		AND(EAX, EDI);
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
			BR_NE(ret, target_pc, *next_pc);
			OR(EAX, TC_JMP_NEXT_PC << 4);
			MOV(MEM32(RDX), EAX);
			MOV(RDX, &m_cpu->tc->jmp_offset[1]);
			MOV(RAX, MEM64(RDX));
			gen_tail_call(RAX);
			m_a.bind(ret_taken);
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
lc86_jit::link_indirect_emit()
{
	m_needs_epilogue = false;

	if (check_rf_single_step_emit()) {
		return;
	}

	// make sure we check for interrupts before jumping to the next tc
	check_int_emit();

	MOV(RDX, m_cpu->tc);
	MOV(RAX, &link_indirect_handler);
	CALL(RAX);
	gen_tail_call(RAX);
}

op_info
lc86_jit::get_operand(ZydisDecodedInstruction *instr, const unsigned opnum)
{
	ZydisDecodedOperand *operand = &instr->operands[opnum];

	switch (operand->type)
	{
	case ZYDIS_OPERAND_TYPE_MEMORY: // final 32 bit addr in edx
	{
		switch (operand->encoding)
		{
		case ZYDIS_OPERAND_ENCODING_DISP16_32_64:
			LD_SEG_BASE(EDX, GET_REG_idx(operand->mem.segment));
			ADD(EDX, operand->mem.disp.value);
			return {};

		case ZYDIS_OPERAND_ENCODING_MODRM_RM: {
			Value *base, *temp, *disp;
			if (instr->address_width == 32) {
				if (operand->mem.base != ZYDIS_REGISTER_NONE) {
					LD_R32(EAX, GET_REG_idx(operand->mem.base));
				}
				else {
					XOR(EAX, EAX);
				}

				if (operand->mem.scale != 0) {
					LD_R32(EDI, GET_REG_idx(operand->mem.index));
					LEA(EAX, MEMS32(EAX, EDI, operand->mem.scale));
				}

				if (operand->mem.disp.has_displacement) {
					if (instr->raw.modrm.mod == 1) {
						MOV(EDX, static_cast<int32_t>(static_cast<int8_t>(operand->mem.disp.value)));
					}
					else {
						MOV(EDX, operand->mem.disp.value);
					}

					LD_SEG_BASE(EDI, GET_REG_idx(operand->mem.segment));
					LEA(EDX, MEMS32(EDX, EAX, 0));
					ADD(EDX, EDI);
					return {};
				}

				LD_SEG_BASE(EDX, GET_REG_idx(operand->mem.segment));
				ADD(EDX, EAX);
				return {};
			}
			else {
				XOR(EAX, EAX);
				if (operand->mem.base != ZYDIS_REGISTER_NONE) {
					LD_R16(AX, GET_REG_idx(operand->mem.base));
				}

				if (operand->mem.scale != 0) {
					XOR(EDI, EDI);
					LD_R16(DI, GET_REG_idx(operand->mem.index));
					LEA(AX, MEMS16(EAX, EDI, operand->mem.scale));
				}

				if (operand->mem.disp.has_displacement) {
					if (instr->raw.modrm.mod == 1) {
						MOV(EDX, static_cast<int16_t>(static_cast<int8_t>(operand->mem.disp.value)));
					}
					else {
						MOV(EDX, operand->mem.disp.value);
					}

					LD_SEG_BASE(EDI, GET_REG_idx(operand->mem.segment));
					LEA(EDX, MEMS32(EDX, EAX, 0));
					ADD(EDX, EDI);
					return {};
				}

				LD_SEG_BASE(EDX, GET_REG_idx(operand->mem.segment));
				ADD(EDX, EAX);
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
		size_t offset = GET_REG_idx(operand->reg.value);
		switch (operand->size)
		{
		case 8:
			return { offset, 8 };

		case 16:
			return { offset, 16 };

		case 32:
			return { offset, 32 };

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
			return { operand->imm.value.u, 16 };

		case ZYDIS_OPERAND_ENCODING_UIMM8:
		case ZYDIS_OPERAND_ENCODING_JIMM8:
			return { operand->imm.value.u, 8 };

		case ZYDIS_OPERAND_ENCODING_JIMM16_32_32:
			if (operand->size == 32) {
				return { operand->imm.value.u, 32 };
			}
			else {
				return { operand->imm.value.u, 16 };
			}

		default:
			LIB86CPU_ABORT_msg("Unhandled imm operand encoding %d in %s", operand->encoding, __func__);
		}
	}

	default:
		LIB86CPU_ABORT_msg("Unhandled operand type specified");
	}
}

void
lc86_jit::jmp(ZydisDecodedInstruction *instr)
{
	switch (instr->opcode)
	{
	case 0xE9:
	case 0xEB: {
		addr_t new_eip = (m_cpu->virt_pc - m_cpu->cpu_ctx.regs.cs_hidden.base) + m_cpu->instr_bytes + instr->operands[OPNUM_SINGLE].imm.value.s;
		if (m_cpu->size_mode == SIZE16) {
			new_eip &= 0x0000FFFF;
		}
		MOV(MEMD32(RCX, CPU_CTX_EIP()), new_eip);
		link_direct_emit(m_cpu->cpu_ctx.regs.cs_hidden.base + new_eip, nullptr, m_cpu->cpu_ctx.regs.cs_hidden.base + new_eip);
		m_cpu->tc->flags |= TC_FLG_DIRECT;
	}
	break;

	case 0xEA: {
		addr_t new_eip = instr->operands[OPNUM_SINGLE].ptr.offset;
		uint16_t new_sel = instr->operands[OPNUM_SINGLE].ptr.segment;
		if (m_cpu->cpu_ctx.hflags & HFLG_PE_MODE) {
			m_stack_args_size = std::max(m_stack_args_size, 16ULL);
			MOV(MEMD32(RSP, 0x20), m_cpu->instr_eip);
			MOV(R9D, new_eip);
			MOV(R8B, m_cpu->size_mode);
			MOV(EDX, new_sel);
			MOV(RAX, &ljmp_pe_helper);
			CALL(RAX);
			BR_NE(exp, RAX, 0);
			link_indirect_emit();
			m_a.bind(exp_taken);
			MOV(RAX, &cpu_raise_exception<false>);
			CALL(RAX);
			gen_epilogue_main();
			m_cpu->tc->flags |= TC_FLG_INDIRECT;
		}
		else {
			new_eip = m_cpu->size_mode == SIZE16 ? new_eip & 0xFFFF : new_eip;
			MOV(MEMD16(RCX, CPU_CTX_CS()), new_sel);
			MOV(MEMD32(RCX, CPU_CTX_EIP()), new_eip);
			MOV(MEMD32(RCX, CPU_CTX_CS_BASE()), static_cast<uint32_t>(new_sel) << 4);
			link_direct_emit((static_cast<uint32_t>(new_sel) << 4) + new_eip, nullptr, (static_cast<uint32_t>(new_sel) << 4) + new_eip);
			m_cpu->tc->flags |= TC_FLG_DIRECT;
		}
	}
	break;

	case 0xFF: {
		if (instr->raw.modrm.reg == 4) {
			GET_RM(OPNUM_SINGLE, LD_REG_val(rm);, LD_MEM(););
			if (m_cpu->size_mode == SIZE16) {
				MOVZX(EAX, AX);
				MOV(MEMD32(RCX, CPU_CTX_EIP()), EAX);
			}
			else {
				MOV(MEMD32(RCX, CPU_CTX_EIP()), EAX);
			}
			link_indirect_emit();
			m_cpu->tc->flags |= TC_FLG_INDIRECT;
		}
		else if (instr->raw.modrm.reg == 5) {
			BAD;
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
lc86_jit::load_reg(op_info info)
{
	switch (info.bits)
	{
	case 8:
		MOV(AL, MEMD8(RCX, info.val));
		break;

	case 16:
		MOV(AX, MEMD16(RCX, info.val));
		break;

	case 32:
		MOV(EAX, MEMD32(RCX, info.val));
		break;

	default:
		LIB86CPU_ABORT();
	}
}

void
lc86_jit::load_mem(uint8_t is_priv)
{
	// RCX: cpu_ctx, EDX: addr, R8: instr_eip, R9B: is_priv

	MOV(R9B, is_priv);
	MOV(R8, m_cpu->instr_eip);

	switch (m_cpu->size_mode)
	{
	case SIZE32:
		MOV(RAX, &mem_read_helper<uint8_t>);
		break;

	case SIZE16:
		MOV(RAX, &mem_read_helper<uint16_t>);
		break;

	case SIZE8:
		MOV(RAX, &mem_read_helper<uint32_t>);
		break;

	default:
		LIB86CPU_ABORT();
	}

	CALL(RAX);
}

template void lc86_jit::raise_exp_inline_emit(uint32_t fault_addr, uint16_t code, uint16_t idx, uint32_t eip);
template void lc86_jit::raise_exp_inline_emit(int fault_addr, int code, int idx, unsigned eip);

#endif
