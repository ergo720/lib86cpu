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

typedef void (*entry_t)(uint32_t dummy, uint8_t *cpu, regs_t *regs, lazy_eflags_t *lazy_eflags);


const char *
get_instr_name(unsigned num)
{
	return mnemo[num];
}

static lib86cpu_status
cpu_translate(cpu_t *cpu, addr_t pc, disas_ctx_t *disas_ctx, translated_code_t *tc)
{
	bool translate_next = true;
	size_t instr_size = 0;
	uint8_t size_mode;
	uint8_t addr_mode;
	BasicBlock *bb = disas_ctx->bb;
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

		instr_size += bytes;

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
		case X86_OPC_INC: {
			switch (instr.opcode_byte)
			{
			case 0x40:
			case 0x41:
			case 0x42:
			case 0x43:
			case 0x44:
			case 0x45:
			case 0x46:
			case 0x47: {
				Value *sum, *val, *cf_old, *reg = GET_OP(OPNUM_SRC);
				switch (size_mode)
				{
				case SIZE16:
					val = LD_R16_val(reg);
					sum = ADD(val, CONST16(1));
					cf_old = LD_CF();
					ST_R16_val(sum, reg);
					ST_FLG_RES_ext(sum);
					ST_FLG_SUM_AUX16(val, CONST16(1), sum);
					break;

				case SIZE32:
					val = LD_REG_val(reg);
					sum = ADD(sum, CONST32(1));
					cf_old = LD_CF();
					ST_REG_val(sum, reg);
					ST_FLG_RES(sum);
					ST_FLG_SUM_AUX32(val, CONST32(1), sum);
					break;

				default:
					UNREACHABLE;
				}

				ST_FLG_AUX(OR(OR(cf_old, SHR(XOR(cf_old, LD_OF()), CONST32(1))), AND(LD_FLG_AUX(), CONST32(0x3FFFFFFF))));
			}
			break;

			default:
				BAD;
			}
		}
		break;

		case X86_OPC_INS:         BAD;
		case X86_OPC_INT3:        BAD;
		case X86_OPC_INT:         BAD;
		case X86_OPC_INTO:        BAD;
		case X86_OPC_INVD:        BAD;
		case X86_OPC_INVLPG:      BAD;
		case X86_OPC_IRET:        BAD;
		case X86_OPC_JCXZ:        BAD;
		case X86_OPC_JECXZ:       BAD;
		case X86_OPC_JO:
		case X86_OPC_JNO:
		case X86_OPC_JC:
		case X86_OPC_JNC:
		case X86_OPC_JZ:
		case X86_OPC_JNZ:
		case X86_OPC_JBE:
		case X86_OPC_JNBE:
		case X86_OPC_JS:
		case X86_OPC_JNS:
		case X86_OPC_JP:
		case X86_OPC_JNP:
		case X86_OPC_JL:
		case X86_OPC_JNL:
		case X86_OPC_JLE:
		case X86_OPC_JNLE: {
			Value *val;
			switch (instr.opcode_byte)
			{
			case 0x70:
				val = ICMP_NE(LD_OF(), CONST32(0)); // OF != 0
				break;

			case 0x71:
				val = ICMP_EQ(LD_OF(), CONST32(0)); // OF == 0
				break;

			case 0x72:
				val = ICMP_NE(LD_CF(), CONST32(2)); // CF != 0
				break;

			case 0x73:
				val = ICMP_EQ(LD_CF(), CONST32(0)); // CF == 0
				break;

			case 0x74:
				val = ICMP_EQ(LD_ZF(), CONST32(0)); // ZF != 0
				break;

			case 0x75:
				val = ICMP_NE(LD_ZF(), CONST32(0)); // ZF == 0
				break;

			case 0x76:
				val = OR(ICMP_NE(LD_CF(), CONST32(0)), ICMP_EQ(LD_ZF(), CONST32(0))); // CF != 0 OR ZF != 0
				break;

			case 0x77:
				val = AND(ICMP_EQ(LD_CF(), CONST32(0)), ICMP_NE(LD_ZF(), CONST32(0))); // CF == 0 AND ZF == 0
				break;

			case 0x78:
				val = ICMP_NE(LD_SF(), CONST32(0)); // SF != 0
				break;

			case 0x79:
				val = ICMP_EQ(LD_SF(), CONST32(0)); // SF == 0
				break;

			case 0x7A:
				val = ICMP_EQ(LD_PARITY(LD_PF()), CONST8(0)); // PF != 0
				break;

			case 0x7B:
				val = ICMP_NE(LD_PARITY(LD_PF()), CONST8(0)); // PF == 0
				break;

			case 0x7C:
				val = ICMP_NE(LD_SF(), SHR(LD_OF(), CONST32(0x80000000))); // SF != OF
				break;

			case 0x7D:
				val = ICMP_EQ(LD_SF(), SHR(LD_OF(), CONST32(0x80000000))); // SF == OF
				break;

			case 0x7E:
				val = OR(ICMP_EQ(LD_ZF(), CONST32(0)), ICMP_NE(LD_SF(), SHR(LD_OF(), CONST32(0x80000000)))); // ZF != 0 OR SF != OF
				break;

			case 0x7F:
				val = AND(ICMP_NE(LD_ZF(), CONST32(0)), ICMP_EQ(LD_SF(), SHR(LD_OF(), CONST32(0x80000000)))); // ZF == 0 AND SF == OF
				break;

			default:
				BAD;
			}

			Value *dst_pc = new AllocaInst(getIntegerType(32), 0, "", bb);
			BasicBlock *bb_jmp = BasicBlock::Create(_CTX(), "", disas_ctx->func, 0);
			BasicBlock *bb_next = BasicBlock::Create(_CTX(), "", disas_ctx->func, 0);
			BR_COND(bb_jmp, bb_next, val, bb);
			disas_ctx->bb = BasicBlock::Create(_CTX(), "", disas_ctx->func, 0);

			Value *next_pc = calc_next_pc_emit(cpu, tc, bb_next, instr_size);
			new StoreInst(next_pc, dst_pc, bb_next);
			BR_UNCOND(disas_ctx->bb, bb_next);

			addr_t jump_eip = (pc - cpu->regs.cs_hidden.base) + bytes + instr.operand[OPNUM_SRC].rel;
			if (size_mode == SIZE16) {
				jump_eip &= 0x0000FFFF;
			}
			bb = bb_jmp;
			new StoreInst(CONST32(jump_eip), GEP_EIP(), bb_jmp);
			new StoreInst(CONST32(jump_eip + cpu->regs.cs_hidden.base), dst_pc, bb_jmp);
			BR_UNCOND(disas_ctx->bb, bb_jmp);

			disas_ctx->next_pc = new LoadInst(dst_pc, "", false, disas_ctx->bb);

			translate_next = false;
		}
		break;

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
			switch (instr.opcode_byte)
			{
			case 0xE9:
			case 0xEB: {
				addr_t new_eip = (pc - cpu->regs.cs_hidden.base) + bytes + instr.operand[OPNUM_SRC].rel;
				if (size_mode == SIZE16) {
					new_eip &= 0x0000FFFF;
				}
				ST_REG(CONST32(new_eip), EIP_idx);
				disas_ctx->next_pc = CONST32(cpu->regs.cs_hidden.base + new_eip);
			}
			break;

			case 0xEA: {
				if (disas_ctx->pe_mode) {
					BAD_MODE;
				}
				addr_t new_eip = instr.operand[OPNUM_SRC].imm;
				uint16_t new_sel = instr.operand[OPNUM_SRC].seg_sel;
				if (size_mode == SIZE16) {
					new_eip &= 0x0000FFFF;
				}
				ST_REG(CONST32(new_eip), EIP_idx);
				ST_SEG(CONST16(new_sel), CS_idx);
				ST_SEG_HIDDEN(CONST32(static_cast<uint32_t>(new_sel) << 4), CS_idx, SEG_BASE_idx);
				disas_ctx->next_pc = CONST32((static_cast<uint32_t>(new_sel) << 4) + new_eip);
			}
			break;

			case 0xFF: {
				if (instr.reg_opc == 5) {
					if (disas_ctx->pe_mode) {
						BAD_MODE;
					}
					assert(instr.operand[OPNUM_SRC].type == OPTYPE_MEM ||
						instr.operand[OPNUM_SRC].type == OPTYPE_MEM_DISP ||
						instr.operand[OPNUM_SRC].type == OPTYPE_SIB_MEM ||
						instr.operand[OPNUM_SRC].type == OPTYPE_SIB_DISP);
					Value *new_eip, *new_sel;
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

					ST_REG(new_eip, EIP_idx);
					ST_SEG(new_sel, CS_idx);
					ST_SEG_HIDDEN(SHL(ZEXT32(new_sel), CONST32(4)), CS_idx, SEG_BASE_idx);
					disas_ctx->next_pc = ADD(LD_SEG_HIDDEN(CS_idx, SEG_BASE_idx), new_eip);
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

			translate_next = false;
		}
		break;

		case X86_OPC_LLDT:        BAD;
		case X86_OPC_LMSW:        BAD;
		case X86_OPC_LODS:        BAD;
		case X86_OPC_LOOP: {
			assert(instr.opcode_byte == 0xE2);

			Value *val, *zero;
			switch (addr_mode)
			{
			case ADDR16:
				val = SUB(LD_R16(ECX_idx), CONST16(1));
				ST_R16(val, ECX_idx);
				zero = CONST16(0);
				break;

			case ADDR32:
				val = SUB(LD_REG(ECX_idx), CONST32(1));
				ST_REG(val, ECX_idx);
				zero = CONST32(0);
				break;

			default:
				UNREACHABLE;
			}

			Value *dst_pc = new AllocaInst(getIntegerType(32), 0, "", bb);
			BasicBlock *bb_loop = BasicBlock::Create(_CTX(), "", disas_ctx->func, 0);
			BasicBlock *bb_exit = BasicBlock::Create(_CTX(), "", disas_ctx->func, 0);
			BR_COND(bb_exit, bb_loop, ICMP_EQ(val, zero), bb);
			disas_ctx->bb = BasicBlock::Create(_CTX(), "", disas_ctx->func, 0);

			Value *exit_pc = calc_next_pc_emit(cpu, tc, bb_exit, instr_size);
			new StoreInst(exit_pc, dst_pc, bb_exit);
			BR_UNCOND(disas_ctx->bb, bb_exit);

			addr_t loop_eip = (pc - cpu->regs.cs_hidden.base) + bytes + instr.operand[OPNUM_SRC].rel;
			if (size_mode == SIZE16) {
				loop_eip &= 0x0000FFFF;
			}
			bb = bb_loop;
			new StoreInst(CONST32(loop_eip), GEP_EIP(), bb_loop);
			new StoreInst(CONST32(loop_eip + cpu->regs.cs_hidden.base), dst_pc, bb_loop);
			BR_UNCOND(disas_ctx->bb, bb_loop);

			disas_ctx->next_pc = new LoadInst(dst_pc, "", false, disas_ctx->bb);

			translate_next = false;
		}
		break;

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

			case 0xC6:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xC7: {
				Value *rm = GET_OP(OPNUM_DST);
				Value *val;
				switch (size_mode)
				{
				case SIZE8:
					val = CONST8(instr.operand[OPNUM_SRC].imm);
					break;

				case SIZE16:
					val = CONST16(instr.operand[OPNUM_SRC].imm);
					break;

				case SIZE32:
					val = CONST32(instr.operand[OPNUM_SRC].imm);
					break;

				default:
					UNREACHABLE;
				}

				switch (instr.operand[OPNUM_DST].type)
				{
				case OPTYPE_REG:
					ST_REG_val(val, rm);
					break;

				case OPTYPE_MEM:
				case OPTYPE_MEM_DISP:
				case OPTYPE_SIB_MEM:
				case OPTYPE_SIB_DISP:
					ST_MEM(fn_idx[size_mode], rm, val);
					break;

				default:
					UNREACHABLE;
				}
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
		case X86_OPC_SAHF: {
			assert(instr.opcode_byte == 0x9E);

			Value *ah = ZEXT32(LD_R8H(EAX_idx));
			Value *sfd = SHR(AND(ah, CONST32(128)), CONST32(7));
			Value *pdb = SHL(XOR(CONST32(4), AND(ah, CONST32(4))), CONST32(6));
			Value *of_new = SHR(XOR(SHL(AND(ah, CONST32(1)), CONST32(31)), LD_OF()), CONST32(1));
			ST_FLG_RES(SHL(XOR(AND(ah, CONST32(64)), CONST32(64)), CONST32(2)));
			ST_FLG_AUX(OR(OR(OR(OR(SHL(AND(ah, CONST32(1)), CONST32(31)), SHR(AND(ah, CONST32(16)), CONST32(1))), of_new, CONST8(1)), sfd), pdb));
		}
		break;

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
					val = LD_MEM(fn_idx[size_mode], rm);
					val = XOR(val, LD_REG_val(reg));
					ST_MEM(fn_idx[size_mode], rm, val);
					break;

				default:
					UNREACHABLE;
				}

				size_mode == SIZE32 ? ST_FLG_RES(val) : ST_FLG_RES_ext(val);
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

			FunctionType *fntype = create_tc_fntype(cpu, tc.get());
			Function *func = create_tc_prologue(cpu, tc.get(), fntype, func_idx);

			// prepare the disas ctx
			disas_ctx_t disas_ctx;
			disas_ctx.pe_mode = CPU_PE_MODE;
			disas_ctx.func = func;
			disas_ctx.bb = BasicBlock::Create(_CTX(), "", func, 0);

			// start guest code translation
			status = cpu_translate(cpu, pc, &disas_ctx, tc.get());
			if (!LIB86CPU_CHECK_SUCCESS(status)) {
				delete tc->mod;
				delete tc->ctx;
				return status;
			}

			Function *tail = create_tc_epilogue(cpu, tc.get(), fntype, &disas_ctx, func_idx);

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

			tc->ptr_code = (void *)(cpu->jit->lookup("start_" + std::to_string(func_idx))->getAddress());
			assert(tc->ptr_code);
			tc->jmp_offset[0] = (void *)(cpu->jit->lookupLinkerMangled("_tail_" + std::to_string(func_idx))->getAddress()); // TODO: how to retrieve the mangled name?
			tc->jmp_offset[1] = nullptr;
			tc->jmp_offset[2] = (void *)(cpu->jit->lookupLinkerMangled("_main_" + std::to_string(func_idx))->getAddress());
			assert(tc->jmp_offset[0] && tc->jmp_offset[2]);

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

			static uint16_t cmp_instr = 0xf981;
			static uint16_t je_instr = 0x840f;
			static uint8_t jmp_instr = 0xe9;
			static uint8_t nop_instr = 0x90;
			if (prev_tc->jmp_offset[1] == nullptr) {
				int32_t tc_offset = reinterpret_cast<uintptr_t>(prev_tc->jmp_offset[2]) -
					reinterpret_cast<uintptr_t>(static_cast<uint8_t *>(ptr_tc->jmp_offset[0]) + 6 /*sizeof(cmp)*/ + 6 /*sizeof(je)*/);
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
				int32_t tc_offset = reinterpret_cast<uintptr_t>(prev_tc->jmp_offset[2]) -
					reinterpret_cast<uintptr_t>(static_cast<uint8_t *>(ptr_tc->jmp_offset[1]) + 5 /*sizeof(jmp)*/);
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
		entry(0, reinterpret_cast<uint8_t *>(cpu), &cpu->regs, &cpu->lazy_eflags);
	}
}
