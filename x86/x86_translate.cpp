/*
 * x86 translation code
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/ExecutionEngine/Orc/LLJIT.h"
#include "llvm/IR/Instructions.h"
#include "x86_internal.h"
#include "x86_isa.h"
#include "x86_frontend.h"
#include "x86_memory.h"

#define BAD       printf("%s: encountered unimplemented instruction %s\n", __func__, get_instr_name(instr.opcode)); return LIB86CPU_OP_NOT_IMPLEMENTED
#define BAD_MODE  printf("%s: instruction %s not implemented in %s mode\n", __func__, get_instr_name(instr.opcode), disas_ctx->pe_mode ? "protected" : "real"); return LIB86CPU_OP_NOT_IMPLEMENTED
#define UNREACHABLE printf("%s: unreachable line %d reached!\n", __func__, __LINE__); return LIB86CPU_UNREACHABLE

typedef void (*entry_t)(uint8_t *cpu, regs_t *regs, lazy_eflags_t *lazy_eflags);


const char *
get_instr_name(unsigned num)
{
	return mnemo[num];
}

static lib86cpu_status
cpu_translate(cpu_t *cpu, addr_t pc, BasicBlock *bb, disas_ctx_t *disas_ctx, translated_code_t *tc)
{
	bool translate_next = true;
	disas_ctx->emit_pc_code = true;
	disas_ctx->next_pc = nullptr;
	size_t tc_instr_size = 0;
	uint8_t size_mode;
	uint8_t addr_mode;
	// we can use the same indexes for both loads and stores because they have the same order in cpu->ptr_mem_xxfn
	static uint8_t fn_idx[3] = { MEM_LD32_idx, MEM_LD16_idx, MEM_LD8_idx };

	do {

		x86_instr instr = { 0 };
		int bytes;

#ifdef DEBUG_LOG

		// print the disassembled instructions only in debug builds
		char disassembly_line[80];
		int i;

		bytes = disasm_instr(cpu, pc, &instr, disassembly_line, sizeof(disassembly_line));
		if (bytes < 0) {
			printf("error: unable to decode opcode %x\n", instr.opcode_byte);
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

		if (disas_ctx->pe_mode ^ instr.op_size_override) {
			size_mode = SIZE32;
		}
		else {
			size_mode = SIZE16;
		}

		if (disas_ctx->pe_mode ^ instr.addr_size_override) {
			addr_mode = ADDR32;
		}
		else {
			addr_mode = ADDR16;
		}

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
		case X86_OPC_CLI:
			if (disas_ctx->pe_mode) {
				BAD_MODE;
			}
			else {
				Value *eflags = LD_REG(EFLAGS_idx);
				eflags = AND(eflags, CONST32(~(1 << IF_shift)));
				ST_REG(eflags, EFLAGS_idx);
			}
			break;

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
		case X86_OPC_LJMP: // AT&T
		case X86_OPC_JMP: {
			Value *new_eip, *new_sel;
			switch (instr.opcode_byte)
			{
			case 0xE9:
			case 0xEB:
				BAD;
			case 0xEA: {
				new_eip = CONST32(instr.operand[OPNUM_SRC].imm);
				new_sel = CONST16(instr.operand[OPNUM_SRC].seg_sel);
			}
			break;

			case 0xFF: {
				if (instr.reg_opc == 5) {
					assert(instr.operand[OPNUM_SRC].type == OPTYPE_MEM ||
						instr.operand[OPNUM_SRC].type == OPTYPE_MEM_DISP ||
						instr.operand[OPNUM_SRC].type == OPTYPE_SIB_MEM ||
						instr.operand[OPNUM_SRC].type == OPTYPE_SIB_DISP);
					Value *sel_addr, *offset_addr = GET_OP(OPNUM_SRC);
					if (size_mode == SIZE16) {
						new_eip = ZEXT32(LD_MEM(MEM_LD16_idx, offset_addr));
						sel_addr = ADD(offset_addr, CONST32(2));
					}
					else {
						new_eip = LD_MEM(MEM_LD32_idx, offset_addr);
						sel_addr = ADD(offset_addr, CONST32(4));
					}
					new_sel = LD_MEM(MEM_LD16_idx, sel_addr);
				}
				else if(instr.reg_opc == 4) {
					BAD;
				}
				else {
					UNREACHABLE;
				}
			}
			break;

			default:
				UNREACHABLE;
			}

			if (disas_ctx->pe_mode) {
				BAD_MODE;
			}
			else {
				ST_REG(new_eip, EIP_idx);
				ST_SEG(new_sel, CS_idx);
				ST_SEG_HIDDEN(SHL(ZEXT32(new_sel), CONST32(4)), CS_idx, SEG_BASE_idx);
				disas_ctx->next_pc = ADD(LD_SEG_HIDDEN(CS_idx, SEG_BASE_idx), new_eip);
				disas_ctx->emit_pc_code = false;
				translate_next = false;
			}
		}
		break;

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
		case X86_OPC_MOV:
			switch (instr.opcode_byte)
			{
			case 0xB0:
			case 0xB1:
			case 0xB2:
			case 0xB3:
			case 0xB4:
			case 0xB5:
			case 0xB6:
			case 0xB7: {
				Value *reg8 = GET_OP(OPNUM_DST);
				ST_REG_val(CONST8(instr.operand[OPNUM_SRC].imm), reg8);
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
				Value *reg = GET_OP(OPNUM_DST);
				ST_REG_val(size_mode == SIZE16 ? CONST16(instr.operand[OPNUM_SRC].imm) : CONST32(instr.operand[OPNUM_SRC].imm), reg);
			}
			break;

			case 0x8E: {
				if (disas_ctx->pe_mode) {
					BAD_MODE;
				}
				// assert that we are not loading the CS or a reserved register. TODO: this should raise an exception
				assert(instr.operand[OPNUM_DST].reg != 1 && instr.operand[OPNUM_DST].reg < 6);
				Value *rm = GET_OP(OPNUM_SRC);
				Value *val;
				switch (instr.operand[OPNUM_SRC].type)
				{
				case OPTYPE_REG:
					val = LD_REG_val(rm);
					break;

				case OPTYPE_MEM:
				case OPTYPE_MEM_DISP:
				case OPTYPE_SIB_MEM:
				case OPTYPE_SIB_DISP:
					val = LD_MEM(MEM_LD16_idx, rm);
					break;

				default:
					UNREACHABLE;
				}

				ST_SEG(val, instr.operand[OPNUM_DST].reg + SEG_offset);
				ST_SEG_HIDDEN(SHL(ZEXT32(val), CONST32(4)), instr.operand[OPNUM_DST].reg + SEG_offset, SEG_BASE_idx);
			}
			break;

			default:
				BAD;
			}
			break;

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
		case X86_OPC_OUT:
			switch (instr.opcode_byte)
			{
			case 0xEE: {
				ST_MEM(IO_ST8_idx, LD_R16(EDX_idx), LD_R8L(EAX_idx));
			}
			break;

			default:
				BAD;
			}
			break;

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
		case X86_OPC_XOR:
			switch (instr.opcode_byte)
			{
			case 0x30:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x31: {
				Value *reg = GET_OP(OPNUM_SRC);
				Value *rm = GET_OP(OPNUM_DST);
				Value *val;
				uint8_t idx = fn_idx[size_mode];
				switch (instr.operand[OPNUM_DST].type)
				{
				case OPTYPE_REG:
					val = LD_REG_val(rm);
					val = XOR(val, LD_REG_val(reg));
					ST_REG_val(val, rm);
					break;

				case OPTYPE_MEM:
				case OPTYPE_MEM_DISP:
				case OPTYPE_SIB_MEM:
				case OPTYPE_SIB_DISP:
					val = LD_MEM(idx, rm);
					val = XOR(val, LD_REG_val(reg));
					ST_MEM(idx, rm, val);
					break;

				default:
					UNREACHABLE;
				}

				ST_FLG_RES(size_mode == SIZE32 ? val : SEXT32(val));
				ST_FLG_AUX(CONST32(0));
			}
			break;

			default:
				BAD;
			}
			break;

		default:
			UNREACHABLE;
		}

		pc += bytes;

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
	static uint64_t func_idx = 0ULL;

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

			// add to the module the memory functions that will be called when the guest needs to access the memory
			get_mem_fn(cpu, tc.get());

			Function *func = create_tc_prologue(cpu, tc.get(), func_idx);

			// create the bb for the function, it will hold all the tranlsated code tor this code block
			BasicBlock *bb = BasicBlock::Create(_CTX(), "", func, 0);

			// start guest code translation
			disas_ctx_t disas_ctx;
			disas_ctx.pe_mode = CPU_PE_MODE;
			status = cpu_translate(cpu, pc, bb, &disas_ctx, tc.get());
			if (!LIB86CPU_CHECK_SUCCESS(status)) {
				delete tc->mod;
				delete tc->ctx;
				return status;
			}

			Function *tail = create_tc_epilogue(cpu, tc.get(), func, &disas_ctx, func_idx);

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
			tc->jmp_offset[0] = (void *)(cpu->jit->lookupLinkerMangled("_tail_" + std::to_string(func_idx))->getAddress()); // TODO: how to retrieve the mangled name?
			tc->jmp_offset[1] = nullptr;
			assert(tc->jmp_offset);

			// llvm will delete the context and the module by itself, so we just null both the pointers now to prevent accidental usage
			tc->ctx = nullptr;
			tc->mod = nullptr;

			ptr_tc = tc.get();
			cpu->code_cache.insert(std::make_pair(pc, std::move(tc)));
			func_idx++;
		}
		else {
			ptr_tc = it->second.get();
		}

		// see if we can link the previous tc with the current one
		if (prev_tc != nullptr) {

		// llvm marks the generated code memory as read/execute (it's done by Memory::protectMappedMemory), which triggers an access violation when
		// we try to write to it during the tc linking phase. So, we temporarily mark it as writable and then restore the write protection.
		// NOTE: perhaps we can use the llvm SectionMemoryManager to do this somehow...

		tc_protect(prev_tc->jmp_offset[0], prev_tc->jmp_code_size, false);

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

		tc_protect(prev_tc->jmp_offset[0], prev_tc->jmp_code_size, true);
		}

		prev_tc = ptr_tc;

		// run the translated code
		entry = static_cast<entry_t>(ptr_tc->ptr_code);
		entry(reinterpret_cast<uint8_t *>(cpu), &cpu->regs, &cpu->lazy_eflags);
	}
}
