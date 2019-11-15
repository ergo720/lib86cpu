/*
 * x86 translation code
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#include "x86_internal.h"
#include "x86_isa.h"
#include "x86_frontend.h"
#include "x86_memory.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/ExecutionEngine/Orc/LLJIT.h"

#define BAD fprintf(stderr, "%s: unimplemented instruction encountered at line %d\n", __func__, __LINE__); return LIB86CPU_OP_NOT_IMPLEMENTED

typedef void (*entry_t)(uint8_t *ram, regs_t *regs);


static lib86cpu_status
cpu_translate(cpu_t *cpu, addr_t pc, BasicBlock *bb, disas_ctx_t *disas_ctx)
{
	bool translate_next = true;
	disas_ctx->emit_pc_code = true;
	disas_ctx->next_pc = nullptr;
	size_t tc_instr_size = 0;

	do {

		x86_instr instr = { 0 };
		int bytes;

#ifdef DEBUG_LOG

		// print the disassembled instructions only in debug builds
		char disassembly_line[80];
		int i;

		bytes = disasm_instr(cpu, pc, &instr, disassembly_line, sizeof(disassembly_line));
		if (bytes < 0) {
			fprintf(stderr, "error: unable to decode opcode %x\n", instr.opcode_byte);
			return LIB86CPU_UNKNOWN_INSTR;
		}

		printf(".,%08lx ", static_cast<unsigned long>(pc));
		for (i = 0; i < bytes; i++) {
			printf("%02X ", cpu->ram[pc + i]);
		}
		printf("%*s", (24 - 3 * bytes) + 1, "");
		printf("%-23s\n", disassembly_line);

#else

		bytes = decode_instr(cpu, &instr, pc);
		if (bytes < 0) {
			printf("error: unable to decode opcode %x\n", instr.opcode_byte);
			return LIB86CPU_UNKNOWN_INSTR;
		}

#endif

		tc_instr_size += bytes;

		switch (instr.opcode) {
		case X86_OPC_AAA:         BAD;
		case X86_OPC_AAD:         BAD;
		case X86_OPC_AAM:         BAD;
		case X86_OPC_AAS:         BAD;
		case X86_OPC_ADC:         BAD;
		case X86_OPC_ADD:         BAD;
		case X86_OPC_AND:         BAD;
		case X86_OPC_ARPL:        BAD;
		case X86_OPC_BOUND:       BAD;
		case X86_OPC_BSF:         BAD;
		case X86_OPC_BSR:         BAD;
		case X86_OPC_BSWAP:       BAD;
		case X86_OPC_BT:          BAD;
		case X86_OPC_BTC:         BAD;
		case X86_OPC_BTR:         BAD;
		case X86_OPC_BTS:         BAD;
		case X86_OPC_CALL:        BAD;
		case X86_OPC_CBW:         BAD;
		case X86_OPC_CBTV:        BAD;
		case X86_OPC_CDQ:         BAD;
		case X86_OPC_CLC:         BAD;
		case X86_OPC_CLD:         BAD;
		case X86_OPC_CLI:         BAD;
		case X86_OPC_CLTD:        BAD;
		case X86_OPC_CLTS:        BAD;
		case X86_OPC_CMC:         BAD;
		case X86_OPC_CMOVA:       BAD;
		case X86_OPC_CMOVB:       BAD;
		case X86_OPC_CMOVBE:      BAD;
		case X86_OPC_CMOVG:       BAD;
		case X86_OPC_CMOVGE:      BAD;
		case X86_OPC_CMOVL:       BAD;
		case X86_OPC_CMOVLE:      BAD;
		case X86_OPC_CMOVNB:      BAD;
		case X86_OPC_CMOVNE:      BAD;
		case X86_OPC_CMOVNO:      BAD;
		case X86_OPC_CMOVNS:      BAD;
		case X86_OPC_CMOVO:       BAD;
		case X86_OPC_CMOVPE:      BAD;
		case X86_OPC_CMOVPO:      BAD;
		case X86_OPC_CMOVS:       BAD;
		case X86_OPC_CMOVZ:       BAD;
		case X86_OPC_CMP:         BAD;
		case X86_OPC_CMPS:        BAD;
		case X86_OPC_CMPXCHG8B:   BAD;
		case X86_OPC_CMPXCHG:     BAD;
		case X86_OPC_CPUID:       BAD;
		case X86_OPC_CWD:         BAD;
		case X86_OPC_CWDE:        BAD;
		case X86_OPC_CWTD:        BAD;
		case X86_OPC_CWTL:        BAD;
		case X86_OPC_DAA:         BAD;
		case X86_OPC_DAS:         BAD;
		case X86_OPC_DEC:         BAD;
		case X86_OPC_DIV:         BAD;
		case X86_OPC_ENTER:       BAD;
		case X86_OPC_HLT:         BAD;
		case X86_OPC_IDIV:        BAD;
		case X86_OPC_IMUL:        BAD;
		case X86_OPC_IN:          BAD;
		case X86_OPC_INC:         BAD;
		case X86_OPC_INS:         BAD;
		case X86_OPC_INT3:        BAD;
		case X86_OPC_INT:         BAD;
		case X86_OPC_INTO:        BAD;
		case X86_OPC_INVD:        BAD;
		case X86_OPC_INVLPG:      BAD;
		case X86_OPC_IRET:        BAD;
		case X86_OPC_JA:          BAD;
		case X86_OPC_JAE:         BAD;
		case X86_OPC_JB:          BAD;
		case X86_OPC_JBE:         BAD;
		case X86_OPC_JC:          BAD;
		case X86_OPC_JCXZ:        BAD;
		case X86_OPC_JE:          BAD;
		case X86_OPC_JECXZ:       BAD;
		case X86_OPC_JG:          BAD;
		case X86_OPC_JGE:         BAD;
		case X86_OPC_JL:          BAD;
		case X86_OPC_JLE:         BAD;
		case X86_OPC_JMP:         BAD;
		case X86_OPC_JNA:         BAD;
		case X86_OPC_JNAE:        BAD;
		case X86_OPC_JNB:         BAD;
		case X86_OPC_JNBE:        BAD;
		case X86_OPC_JNC:         BAD;
		case X86_OPC_JNE:         BAD;
		case X86_OPC_JNG:         BAD;
		case X86_OPC_JNGE:        BAD;
		case X86_OPC_JNL:         BAD;
		case X86_OPC_JNLE:        BAD;
		case X86_OPC_JNO:         BAD;
		case X86_OPC_JNP:         BAD;
		case X86_OPC_JNS:         BAD;
		case X86_OPC_JNZ:         BAD;
		case X86_OPC_JO:          BAD;
		case X86_OPC_JP:          BAD;
		case X86_OPC_JPE:         BAD;
		case X86_OPC_JPO:         BAD;
		case X86_OPC_JS:          BAD;
		case X86_OPC_JZ:          BAD;
		case X86_OPC_LAHF:        BAD;
		case X86_OPC_LAR:         BAD;
		case X86_OPC_LCALL:       BAD;
		case X86_OPC_LDS:         BAD;
		case X86_OPC_LEA:         BAD;
		case X86_OPC_LEAVE:       BAD;
		case X86_OPC_LES:         BAD;
		case X86_OPC_LFS:         BAD;
		case X86_OPC_LGDTD:       BAD;
		case X86_OPC_LGDTL:       BAD;
		case X86_OPC_LGDTW:       BAD;
		case X86_OPC_LGS:         BAD;
		case X86_OPC_LIDTD:       BAD;
		case X86_OPC_LIDTL:       BAD;
		case X86_OPC_LIDTW:       BAD;
		case X86_OPC_LJMP:        BAD;
		case X86_OPC_LLDT:        BAD;
		case X86_OPC_LMSW:        BAD;
		case X86_OPC_LODS:        BAD;
		case X86_OPC_LOOP:        BAD;
		case X86_OPC_LOOPE:       BAD;
		case X86_OPC_LOOPNE:      BAD;
		case X86_OPC_LOOPNZ:      BAD;
		case X86_OPC_LOOPZ:       BAD;
		case X86_OPC_LRET:        BAD;
		case X86_OPC_LSL:         BAD;
		case X86_OPC_LSS:         BAD;
		case X86_OPC_LTR:         BAD;
		case X86_OPC_MOV:         BAD;
		case X86_OPC_MOVS:        BAD;
		case X86_OPC_MOVSX:       BAD;
		case X86_OPC_MOVSXB:      BAD;
		case X86_OPC_MOVSXW:      BAD;
		case X86_OPC_MOVZX:       BAD;
		case X86_OPC_MOVZXB:      BAD;
		case X86_OPC_MOVZXW:      BAD;
		case X86_OPC_MUL:         BAD;
		case X86_OPC_NEG:         BAD;
		case X86_OPC_NOP:         BAD;
		case X86_OPC_NOT:         BAD;
		case X86_OPC_OR:          BAD;
		case X86_OPC_OUT:         BAD;
		case X86_OPC_OUTS:        BAD;
		case X86_OPC_POP:         BAD;
		case X86_OPC_POPA:        BAD;
		case X86_OPC_POPF:        BAD;
		case X86_OPC_PUSH:        BAD;
		case X86_OPC_PUSHA:       BAD;
		case X86_OPC_PUSHF:       BAD;
		case X86_OPC_RCL:         BAD;
		case X86_OPC_RCR:         BAD;
		case X86_OPC_RDMSR:       BAD;
		case X86_OPC_RDPMC:       BAD;
		case X86_OPC_RDTSC:       BAD;
		case X86_OPC_REP:         BAD;
		case X86_OPC_REPE:        BAD;
		case X86_OPC_REPNE:       BAD;
		case X86_OPC_REPNZ:       BAD;
		case X86_OPC_REPZ:        BAD;
		case X86_OPC_RET:         BAD;
		case X86_OPC_RETF:        BAD;
		case X86_OPC_ROL:         BAD;
		case X86_OPC_ROR:         BAD;
		case X86_OPC_RSM:         BAD;
		case X86_OPC_SAHF:        BAD;
		case X86_OPC_SAL:         BAD;
		case X86_OPC_SAR:         BAD;
		case X86_OPC_SBB:         BAD;
		case X86_OPC_SCAS:        BAD;
		case X86_OPC_SETA:        BAD;
		case X86_OPC_SETB:        BAD;
		case X86_OPC_SETBE:       BAD;
		case X86_OPC_SETG:        BAD;
		case X86_OPC_SETGE:       BAD;
		case X86_OPC_SETL:        BAD;
		case X86_OPC_SETLE:       BAD;
		case X86_OPC_SETNB:       BAD;
		case X86_OPC_SETNE:       BAD;
		case X86_OPC_SETNO:       BAD;
		case X86_OPC_SETNS:       BAD;
		case X86_OPC_SETO:        BAD;
		case X86_OPC_SETPE:       BAD;
		case X86_OPC_SETPO:       BAD;
		case X86_OPC_SETS:        BAD;
		case X86_OPC_SETZ:        BAD;
		case X86_OPC_SGDTD:       BAD;
		case X86_OPC_SGDTL:       BAD;
		case X86_OPC_SGDTW:       BAD;
		case X86_OPC_SHL:         BAD;
		case X86_OPC_SHLD:        BAD;
		case X86_OPC_SHR:         BAD;
		case X86_OPC_SHRD:        BAD;
		case X86_OPC_SIDTD:       BAD;
		case X86_OPC_SIDTL:       BAD;
		case X86_OPC_SIDTW:       BAD;
		case X86_OPC_SLDT:        BAD;
		case X86_OPC_SMSW:        BAD;
		case X86_OPC_STC:         BAD;
		case X86_OPC_STD:         BAD;
		case X86_OPC_STI:         BAD;
		case X86_OPC_STOS:        BAD;
		case X86_OPC_STR:         BAD;
		case X86_OPC_SUB:         BAD;
		case X86_OPC_SYSENTER:    BAD;
		case X86_OPC_SYSEXIT:     BAD;
		case X86_OPC_TEST:        BAD;
		case X86_OPC_UD1:         BAD;
		case X86_OPC_UD2:         BAD;
		case X86_OPC_VERR:        BAD;
		case X86_OPC_VERW:        BAD;
		case X86_OPC_WBINVD:      BAD;
		case X86_OPC_WRMSR:       BAD;
		case X86_OPC_XADD:        BAD;
		case X86_OPC_XCHG:        BAD;
		case X86_OPC_XLATB:       BAD;
		case X86_OPC_XOR:         BAD;
		default:
			fprintf(stderr, "INVALID %s:%d\n", __func__, __LINE__);
			return LIB86CPU_OP_NOT_IMPLEMENTED;
		}
	} while (translate_next);

	disas_ctx->tc_instr_size = tc_instr_size;

	return LIB86CPU_SUCCESS;
}

static addr_t
get_pc(cpu_t *cpu)
{
	return cpu->regs.cs_hidden.base + cpu->regs.eip;
}

lib86cpu_status
cpu_exec_tc(cpu_t *cpu)
{
	lib86cpu_status status = LIB86CPU_SUCCESS;
	translated_code_t *prev_tc = nullptr, *ptr_tc = nullptr;
	entry_t entry = nullptr;

	// this will exit only in the case of errors
	while (true) {

		addr_t pc = get_ram_addr(cpu, get_pc(cpu));
		auto it = cpu->code_cache.find(pc);

		if (it == cpu->code_cache.end()) {

			// code block for this pc not present, we need to translate new code
			std::unique_ptr<translated_code_t> tc(new translated_code_t);
			tc->ctx = new LLVMContext();
			if (tc->ctx == nullptr) {
				status = LIB86CPU_NO_MEMORY;
				return status;
			}
			tc->mod = new Module(cpu->cpu_name, _CTX());
			if (tc->mod == nullptr) {
				delete tc->ctx;
				status = LIB86CPU_NO_MEMORY;
				return status;
			}

			Function *func = create_tc_prologue(cpu, tc.get());

			// create the bb for the function, it will hold all the tranlsated code tor this code block
			BasicBlock *bb = BasicBlock::Create(_CTX(), "", func, 0);

			// start guest code translation
			disas_ctx_t disas_ctx;
			status = cpu_translate(cpu, pc, bb, &disas_ctx);
			if (!LIB86CPU_CHECK_SUCCESS(status)) {
				delete tc->mod;
				delete tc->ctx;
				return status;
			}

			Function *tail = create_tc_epilogue(cpu, tc.get(), func, &disas_ctx);

			if (cpu->cpu_flags & CPU_PRINT_IR) {
				tc->mod->print(errs(), nullptr);
			}

			if (cpu->cpu_flags & CPU_CODEGEN_OPTIMIZE) {
				optimize(tc.get(), func);
				if (cpu->cpu_flags & CPU_PRINT_IR_OPTIMIZED) {
					tc->mod->print(errs(), nullptr);
				}
			}

			orc::ThreadSafeContext tsc(std::unique_ptr<LLVMContext>(tc->ctx));
			orc::ThreadSafeModule tsm(std::unique_ptr<Module>(tc->mod), tsc);
			if (cpu->jit->addIRModule(std::move(tsm))) {
				status = LIB86CPU_LLVM_ERROR;
				delete tc->mod;
				delete tc->ctx;
				return status;
			}

			tc->ptr_code = (void *)(cpu->jit->lookup(func->getName())->getAddress());
			assert(tc->ptr_code);
			tc->jmp_offset[0] = (void *)(cpu->jit->lookupLinkerMangled("_tail")->getAddress()); // TODO: how to retrieve the mangled name?
			tc->jmp_offset[1] = nullptr;
			assert(tc->jmp_offset);

			// llvm will delete the context and the module by itself, so we just null both the pointers now to prevent accidental usage
			tc->ctx = nullptr;
			tc->mod = nullptr;

			ptr_tc = tc.get();
			cpu->code_cache.insert(std::make_pair(pc, std::move(tc)));
		}
		else {
			ptr_tc = it->second.get();
		}

		// see if we can link the previous tc with the current one
		if (prev_tc != nullptr) {

#if defined __i386 || defined _M_IX86

			// TODO: endianness?
			static uint32_t cmp_instr = 0x81f9;
			static uint32_t je_instr = 0x0f84;
			static uint32_t jmp_instr = 0xe9;
			static uint32_t nop_instr = 0x90;
			if (prev_tc->jmp_offset[1] == nullptr) {
				int32_t tc_offset = reinterpret_cast<uintptr_t>(ptr_tc->ptr_code) - reinterpret_cast<uintptr_t>((static_cast<uint8_t *>(prev_tc->jmp_offset[0]) + 6)) - 6;
				memcpy(prev_tc->jmp_offset[0], &cmp_instr, 2);
				memcpy(static_cast<uint8_t *>(prev_tc->jmp_offset[0]) + 2, &pc, 4);                  // cmp ecx, pc
				memcpy(static_cast<uint8_t *>(prev_tc->jmp_offset[0]) + 6, &je_instr, 2);			 
				memcpy(static_cast<uint8_t *>(prev_tc->jmp_offset[0]) + 8, &tc_offset, 4);           // je tc_offset
				for (uint8_t i = 0; i < 3; i++) {														 
					memcpy(static_cast<uint8_t *>(prev_tc->jmp_offset[0]) + 12 + i, &nop_instr, 1);  // nop
				}
				prev_tc->jmp_offset[1] = static_cast<uint8_t *>(prev_tc->jmp_offset[0]) + 15;
			}
			else {
				int32_t tc_offset = reinterpret_cast<uintptr_t>(ptr_tc->ptr_code) - reinterpret_cast<uintptr_t>(prev_tc->jmp_offset[1]) - 5;
				memcpy(prev_tc->jmp_offset[1], &jmp_instr, 1);
				memcpy(static_cast<uint8_t *>(prev_tc->jmp_offset[1]) + 1, &tc_offset, 4);  // jmp tc_offset
			}

#else
#error don't know how to patch tc on this platform
#endif

		}

		prev_tc = ptr_tc;

		// run the translated code
		entry = static_cast<entry_t>(ptr_tc->ptr_code);
		entry(cpu->ram, &cpu->regs);
	}
}
