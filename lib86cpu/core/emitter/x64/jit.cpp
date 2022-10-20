/*
 * x86-64 emitter
 *
 * ergo720                Copyright (c) 2022
 */

#include "jit.h"
#include "support.h"
#include <assert.h>

#ifdef LIB86CPU_X64_EMITTER

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
#define R8  x86::r8
#define R9  x86::r9
#define R10 x86::r10
#define R11 x86::r11
#define R12 x86::r12
#define R13 x86::r13
#define R14 x86::r14
#define R15 x86::r15

#define MEM8(reg)  x86::byte_ptr(reg)
#define MEM16(reg) x86::word_ptr(reg)
#define MEM32(reg) x86::dword_ptr(reg)
#define MEM64(reg) x86::qword_ptr(reg)

#define SET_REG(reg, imm64) m_a.mov(reg, imm64)
#define CALL(addr) SET_REG(RAX, reinterpret_cast<uintptr_t>(addr)); m_a.call(RAX)


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

	SET_REG(RDX, CPU_CTX_INT());
	m_a.mov(MEM8(RDX), CL);
	m_a.ret();

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

	m_a.push(RDI);
	m_prolog_patch_offset = m_a.offset();
	m_a.long_().sub(RSP, 0);

	m_stack_args_size = 0;
	m_local_vars_size = 0;
	m_update_guest_eip = true;
}

void
lc86_jit::raise_exp_inline_emit(uint32_t fault_addr, uint16_t code, uint16_t idx, uint32_t eip)
{
	SET_REG(RCX, CPU_EXP_ADDR());
	m_a.mov(MEM32(RCX), fault_addr);
	m_a.add(RCX, OFFSET_DIFF(exp_data_t, code, fault_addr));
	m_a.mov(MEM16(RCX), code);
	m_a.add(RCX, OFFSET_DIFF(exp_data_t, idx, code));
	m_a.mov(MEM16(RCX), idx);
	m_a.add(RCX, OFFSET_DIFF(exp_data_t, eip, idx));
	m_a.mov(MEM32(RCX), eip);
	CALL(&cpu_raise_exception<false>);
	m_a.ret();
}

#endif
