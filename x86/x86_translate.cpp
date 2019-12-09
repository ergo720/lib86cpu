/*
 * x86 translation code
 *
 * ergo720                Copyright (c) 2019
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

[[noreturn]] void
cpu_raise_exception(uint8_t *cpu2, uint8_t expno, uint32_t eip)
{
	cpu_t *cpu = reinterpret_cast<cpu_t *>(cpu2);

	if (CPU_PE_MODE) {
		printf("Exceptions are unsupported in protected mode (for now)\n");
		exit(1);
	}

	// write to the stack eflags, cs and eip
	addr_t stack_base = cpu->regs.ss_hidden.base + (cpu->regs.esp & 0x0000FFFF);
	ram_write<uint16_t>(cpu, &stack_base, cpu->regs.eflags |
		((cpu->lazy_eflags.auxbits & 0x80000000) >> 31) |
		((cpu->lazy_eflags.parity[(cpu->lazy_eflags.result & 0xFF) ^ ((cpu->lazy_eflags.auxbits & 0xFF00) >> 8)] ^ 1) << 2) |
		((cpu->lazy_eflags.auxbits & 8) << 1) |
		((cpu->lazy_eflags.result == 0) << 6) |
		(((cpu->lazy_eflags.result & 0x80000000) >> 31) ^ (cpu->lazy_eflags.auxbits & 1) << 7) |
		(((cpu->lazy_eflags.auxbits & 0x80000000) ^ ((cpu->lazy_eflags.auxbits & 0x40000000) << 1)) >> 20)
		);
	ram_write<uint16_t>(cpu, &stack_base, cpu->regs.cs);
	ram_write<uint16_t>(cpu, &stack_base, eip);
	cpu->regs.esp -= 6;

	// clear IF, TF, RF and AC flags
	cpu->regs.eflags &= ~(TF_MASK | IF_MASK | RF_MASK | AC_MASK);

	// transfer program control to the exception handler specified in the idt
	addr_t vec_addr = cpu->regs.idtr_base + expno * 4;
	uint32_t vec_entry = ram_read<uint32_t>(cpu, &vec_addr);
	cpu->regs.cs = (vec_entry & 0xFFFF0000) >> 16;
	cpu->regs.cs_hidden.base = cpu->regs.cs << 4;
	cpu->regs.eip = vec_entry & 0x0000FFFF;

	// throw an exception to forcefully exit from the current code block
	throw cpu;
}

static lib86cpu_status
cpu_translate(cpu_t *cpu, addr_t pc, disas_ctx_t *disas_ctx, translated_code_t *tc, bool *exp_active)
{
	bool translate_next = true;
	size_t instr_size = 0;
	uint8_t size_mode;
	uint8_t addr_mode;
	BasicBlock *bb = disas_ctx->bb;
	// we can use the same indexes for both loads and stores because they have the same order in cpu->ptr_mem_xxfn
	static const uint8_t fn_idx[3] = { MEM_LD32_idx, MEM_LD16_idx, MEM_LD8_idx };

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
				Value *eflags = LD_R32(EFLAGS_idx);
				eflags = AND(eflags, CONST32(~(1 << IF_shift)));
				ST_R32(eflags, EFLAGS_idx);
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
		case X86_OPC_CMP: {
			Value *val, *cmp, *sub, *rm;
			switch (instr.opcode_byte)
			{
			case 0x38:
				size_mode = SIZE8;
				if (instr.operand[OPNUM_SRC].reg < 4) {
					val = LD_R8L(instr.operand[OPNUM_SRC].reg);
				}
				else {
					val = LD_R8H(instr.operand[OPNUM_SRC].reg);
				}
				GET_RM(OPNUM_DST, cmp = LD_REG_val(rm);, cmp = LD_MEM(fn_idx[size_mode], rm););
				break;

			case 0x39:
				if (size_mode == SIZE16) {
					val = LD_R16(instr.operand[OPNUM_SRC].reg);
				}
				else {
					val = LD_R32(instr.operand[OPNUM_SRC].reg);
				}
				GET_RM(OPNUM_DST, cmp = LD_REG_val(rm);, cmp = LD_MEM(fn_idx[size_mode], rm););
				break;

			case 0x3C:
				size_mode = SIZE8;
				val = LD_R8L(EAX_idx);
				cmp = CONST8(instr.operand[OPNUM_SRC].imm);
				break;

			case 0x3D:
				if (size_mode == SIZE16) {
					val = LD_R16(EAX_idx);
					cmp = CONST16(instr.operand[OPNUM_SRC].imm);
				}
				else {
					val = LD_R32(EAX_idx);
					cmp = CONST32(instr.operand[OPNUM_SRC].imm);
				}
				break;

			case 0x80:
			case 0x82:
				assert(instr.reg_opc == 7);
				size_mode = SIZE8;
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				cmp = CONST8(instr.operand[OPNUM_SRC].imm);
				break;

			case 0x81:
				assert(instr.reg_opc == 7);
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				cmp = size_mode == SIZE16 ? CONST16(instr.operand[OPNUM_SRC].imm) : CONST32(instr.operand[OPNUM_SRC].imm);
				break;

			case 0x83:
				assert(instr.reg_opc == 7);
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				cmp = SEXT(size_mode == SIZE16 ? 16 : 32, CONST8(instr.operand[OPNUM_SRC].imm));
				break;

			default:
				BAD;
			}

			sub = SUB(val, cmp);

			switch (size_mode)
			{
			case SIZE8:
				ST_FLG_RES_ext(sub);
				ST_FLG_SUB_AUX8(val, cmp, sub);
				break;

			case SIZE16:
				ST_FLG_RES_ext(sub);
				ST_FLG_SUB_AUX16(val, cmp, sub);
				break;

			case SIZE32:
				ST_FLG_RES(sub);
				ST_FLG_SUB_AUX32(val, cmp, sub);
				break;

			default:
				UNREACHABLE;
			}
		}
		break;

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
		case X86_OPC_DIV: {
			switch (instr.opcode_byte)
			{
			case 0xF6:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xF7: {
				assert(instr.reg_opc == 6);

				// TODO: division exceptions. This will happily try to divide by zero and doesn't care about overflows
				Value *val, *reg, *rm;
				switch (size_mode)
				{
				case SIZE8:
					reg = LD_R16(EAX_idx);
					GET_RM(OPNUM_SRC, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					ST_REG_val(TRUNC8(UDIV(reg, ZEXT16(val))), GEP_R8L(EAX_idx));
					ST_REG_val(TRUNC8(UREM(reg, ZEXT16(val))), GEP_R8H(EAX_idx));
					break;

				case SIZE16:
					reg = OR(SHL(ZEXT32(LD_R16(EDX_idx)), CONST32(16)), ZEXT32(LD_R16(EAX_idx)));
					GET_RM(OPNUM_SRC, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					ST_REG_val(TRUNC16(UDIV(reg, ZEXT32(val))), GEP_R16(EAX_idx));
					ST_REG_val(TRUNC16(UREM(reg, ZEXT32(val))), GEP_R16(EDX_idx));
					break;

				case SIZE32:
					reg = OR(SHL(ZEXT64(LD_R32(EDX_idx)), CONST64(32)), ZEXT64(LD_R32(EAX_idx)));
					GET_RM(OPNUM_SRC, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					ST_REG_val(TRUNC32(UDIV(reg, ZEXT64(val))), GEP_R32(EAX_idx));
					ST_REG_val(TRUNC32(UREM(reg, ZEXT64(val))), GEP_R32(EDX_idx));
					break;

				default:
					UNREACHABLE;
				}
			}
			break;

			default:
				UNREACHABLE;
			}
		}
		break;

		case X86_OPC_ENTER:       BAD;
		case X86_OPC_HLT:         BAD;
		case X86_OPC_IDIV:        BAD;
		case X86_OPC_IMUL: {
			switch (instr.opcode_byte)
			{
			case 0xF6:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xF7: {
				assert(instr.reg_opc == 5);

				Value *val, *reg, *rm, *out;
				switch (size_mode)
				{
				case SIZE8:
					reg = LD_R8L(EAX_idx);
					GET_RM(OPNUM_SRC, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(SEXT16(reg), SEXT16(val));
					ST_REG_val(out, GEP_R16(EAX_idx));
					ST_FLG_AUX(SHL(ZEXT32(NOT_ZERO(16, XOR(out, LD_R8L(EAX_idx)))), CONST32(31)));
					break;

				case SIZE16:
					reg = LD_R16(EAX_idx);
					GET_RM(OPNUM_SRC, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(SEXT32(reg), SEXT32(val));
					ST_REG_val(TRUNC16(SHR(out, CONST32(16))), GEP_R16(EDX_idx));
					ST_REG_val(TRUNC16(out), GEP_R16(EAX_idx));
					ST_FLG_AUX(SHL(NOT_ZERO(32, XOR(SEXT32(LD_R16(EAX_idx)), out)), CONST32(31)));
					break;

				case SIZE32:
					reg = LD_R32(EAX_idx);
					GET_RM(OPNUM_SRC, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(SEXT64(reg), SEXT64(val));
					ST_REG_val(TRUNC32(SHR(out, CONST64(32))), GEP_R32(EDX_idx));
					ST_REG_val(TRUNC32(out), GEP_R32(EAX_idx));
					ST_FLG_AUX(SHL(TRUNC32(NOT_ZERO(64, XOR(ZEXT64(LD_R32(EAX_idx)), out))), CONST32(31)));
					break;

				default:
					UNREACHABLE;
				}
			}
			break;

			default:
				BAD;
			}
		}
		break;

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
					val = LD_REG_val(reg);
					sum = ADD(val, CONST16(1));
					cf_old = LD_CF();
					ST_REG_val(sum, reg);
					ST_FLG_RES_ext(sum);
					ST_FLG_SUM_AUX16(val, CONST16(1), sum);
					break;

				case SIZE32:
					val = LD_REG_val(reg);
					sum = ADD(val, CONST32(1));
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
		case X86_OPC_JECXZ:
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
			case 0x80:
				val = ICMP_NE(LD_OF(), CONST32(0)); // OF != 0
				break;

			case 0x71:
			case 0x81:
				val = ICMP_EQ(LD_OF(), CONST32(0)); // OF == 0
				break;

			case 0x72:
			case 0x82:
				val = ICMP_NE(LD_CF(), CONST32(2)); // CF != 0
				break;

			case 0x73:
			case 0x83:
				val = ICMP_EQ(LD_CF(), CONST32(0)); // CF == 0
				break;

			case 0x74:
			case 0x84:
				val = ICMP_EQ(LD_ZF(), CONST32(0)); // ZF != 0
				break;

			case 0x75:
			case 0x85:
				val = ICMP_NE(LD_ZF(), CONST32(0)); // ZF == 0
				break;

			case 0x76:
			case 0x86:
				val = OR(ICMP_NE(LD_CF(), CONST32(0)), ICMP_EQ(LD_ZF(), CONST32(0))); // CF != 0 OR ZF != 0
				break;

			case 0x77:
			case 0x87:
				val = AND(ICMP_EQ(LD_CF(), CONST32(0)), ICMP_NE(LD_ZF(), CONST32(0))); // CF == 0 AND ZF == 0
				break;

			case 0x78:
			case 0x88:
				val = ICMP_NE(LD_SF(), CONST32(0)); // SF != 0
				break;

			case 0x79:
			case 0x89:
				val = ICMP_EQ(LD_SF(), CONST32(0)); // SF == 0
				break;

			case 0x7A:
			case 0x8A:
				val = ICMP_EQ(LD_PARITY(LD_PF()), CONST8(0)); // PF != 0
				break;

			case 0x7B:
			case 0x8B:
				val = ICMP_NE(LD_PARITY(LD_PF()), CONST8(0)); // PF == 0
				break;

			case 0x7C:
			case 0x8C:
				val = ICMP_NE(LD_SF(), SHR(LD_OF(), CONST32(31))); // SF != OF
				break;

			case 0x7D:
			case 0x8D:
				val = ICMP_EQ(LD_SF(), SHR(LD_OF(), CONST32(31))); // SF == OF
				break;

			case 0x7E:
			case 0x8E:
				val = OR(ICMP_EQ(LD_ZF(), CONST32(0)), ICMP_NE(LD_SF(), SHR(LD_OF(), CONST32(31)))); // ZF != 0 OR SF != OF
				break;

			case 0x7F:
			case 0x8F:
				val = AND(ICMP_NE(LD_ZF(), CONST32(0)), ICMP_EQ(LD_SF(), SHR(LD_OF(), CONST32(31)))); // ZF == 0 AND SF == OF
				break;

			case 0xE3:
				val = addr_mode == ADDR16 ? ICMP_EQ(LD_R16(ECX_idx), CONST16(0)) : ICMP_EQ(LD_R32(ECX_idx), CONST32(0)); // ECX == 0
				break;

			default:
				UNREACHABLE;
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
				ST_R32(CONST32(new_eip), EIP_idx);
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
				ST_R32(CONST32(new_eip), EIP_idx);
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

					ST_R32(new_eip, EIP_idx);
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
		case X86_OPC_LOOP:
		case X86_OPC_LOOPE:
		case X86_OPC_LOOPNE: {
			Value *val, *zero, *zf;
			switch (instr.opcode_byte)
			{
			case 0xE0:
				zf = ICMP_NE(LD_ZF(), CONST32(0));
				break;

			case 0xE1:
				zf = ICMP_EQ(LD_ZF(), CONST32(0));
				break;

			case 0xE2:
				zf = CONSTs(1, 1);
				break;

			default:
				UNREACHABLE;
			}

			switch (addr_mode)
			{
			case ADDR16:
				val = SUB(LD_R16(ECX_idx), CONST16(1));
				ST_R16(val, ECX_idx);
				zero = CONST16(0);
				break;

			case ADDR32:
				val = SUB(LD_R32(ECX_idx), CONST32(1));
				ST_R32(val, ECX_idx);
				zero = CONST32(0);
				break;

			default:
				UNREACHABLE;
			}

			Value *dst_pc = new AllocaInst(getIntegerType(32), 0, "", bb);
			BasicBlock *bb_loop = BasicBlock::Create(_CTX(), "", disas_ctx->func, 0);
			BasicBlock *bb_exit = BasicBlock::Create(_CTX(), "", disas_ctx->func, 0);
			BR_COND(bb_loop, bb_exit, AND(ICMP_NE(val, zero), zf), bb);
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

		case X86_OPC_LRET:        BAD;
		case X86_OPC_LSL:         BAD;
		case X86_OPC_LSS:         BAD;
		case X86_OPC_LTR:         BAD;
		case X86_OPC_MOV:
			switch (instr.opcode_byte)
			{
			case 0x88:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x89: {
				Value *reg, *rm;
				switch (size_mode)
				{
				case SIZE8:
					if (instr.operand[OPNUM_SRC].reg < 4) {
						reg = LD_R8L(instr.operand[OPNUM_SRC].reg);
					}
					else {
						reg = LD_R8H(instr.operand[OPNUM_SRC].reg);
					}
					break;

				case SIZE16:
					reg = LD_R16(instr.operand[OPNUM_SRC].reg);
					break;

				case SIZE32:
					reg = LD_R32(instr.operand[OPNUM_SRC].reg);
					break;

				default:
					UNREACHABLE;
				}

				GET_RM(OPNUM_DST, ST_REG_val(reg, rm);, ST_MEM(fn_idx[size_mode], rm, reg););
			}
			break;

			case 0x8C: {
				if (disas_ctx->pe_mode) {
					BAD_MODE;
				}
				Value *val, *rm;
				val = LD_SEG(instr.operand[OPNUM_SRC].reg + SEG_offset);
				GET_RM(OPNUM_DST, ST_REG_val(ZEXT32(val), IBITCAST32(rm));, ST_MEM(MEM_LD16_idx, rm, val););
			}
			break;

			case 0x8E: {
				if (disas_ctx->pe_mode) {
					BAD_MODE;
				}
				if (instr.operand[OPNUM_DST].reg == 1 || instr.operand[OPNUM_DST].reg > 5) {
					RAISE(EXP_UD, pc - cpu->regs.cs_hidden.base);
				}
				Value *val, *rm;
				GET_RM(OPNUM_SRC, val = LD_REG_val(rm);, val = LD_MEM(MEM_LD16_idx, rm););
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
				Value *val, *rm;
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

				GET_RM(OPNUM_DST, ST_REG_val(val, rm);, ST_MEM(fn_idx[size_mode], rm, val););
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
		case X86_OPC_MUL: {
			switch (instr.opcode_byte)
			{
			case 0xF6:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xF7: {
				assert(instr.reg_opc == 4);

				Value *val, *reg, *rm, *out;
				switch (size_mode)
				{
				case SIZE8:
					reg = LD_R8L(EAX_idx);
					GET_RM(OPNUM_SRC, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(ZEXT16(reg), ZEXT16(val));
					ST_REG_val(out, GEP_R16(EAX_idx));
					ST_FLG_AUX(SHL(ZEXT32(NOT_ZERO(16, SHR(out, CONST16(8)))), CONST32(31)));
					break;

				case SIZE16:
					reg = LD_R16(EAX_idx);
					GET_RM(OPNUM_SRC, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(ZEXT32(reg), ZEXT32(val));
					ST_REG_val(TRUNC16(SHR(out, CONST32(16))), GEP_R16(EDX_idx));
					ST_REG_val(TRUNC16(out), GEP_R16(EAX_idx));
					ST_FLG_AUX(SHL(NOT_ZERO(32, SHR(out, CONST32(16))), CONST32(31)));
					break;

				case SIZE32:
					reg = LD_R32(EAX_idx);
					GET_RM(OPNUM_SRC, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(ZEXT64(reg), ZEXT64(val));
					ST_REG_val(TRUNC32(SHR(out, CONST64(32))), GEP_R32(EDX_idx));
					ST_REG_val(TRUNC32(out), GEP_R32(EAX_idx));
					ST_FLG_AUX(SHL(TRUNC32(NOT_ZERO(64, SHR(out, CONST64(32)))), CONST32(31)));
					break;

				default:
					UNREACHABLE;
				}
			}
			break;

			default:
				UNREACHABLE;
			}
		}
		break;

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
			ST_FLG_AUX(OR(OR(OR(OR(SHL(AND(ah, CONST32(1)), CONST32(31)), SHR(AND(ah, CONST32(16)), CONST32(1))), of_new), sfd), pdb));
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
		case X86_OPC_SHL: {
			switch (instr.opcode_byte)
			{
			case 0xD0: {
				assert(instr.reg_opc == 4);

				Value *val, *rm, *cf;
				GET_RM(OPNUM_SRC, val = LD_REG_val(rm); cf = AND(val, CONST8(0xC0)); val = SHL(val, CONST8(1)); ST_REG_val(val, rm);,
					val = LD_MEM(MEM_LD8_idx, rm); cf = AND(val, CONST8(0xC0)); val = SHL(val, CONST8(1)); ST_MEM(MEM_ST8_idx, rm, val););
				ST_FLG_RES_ext(val);
				ST_FLG_AUX(SHL(ZEXT32(cf), CONST32(24)));
			}
			break;

			default:
				BAD;
			}
		}
		break;

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
		case X86_OPC_TEST: {
			switch (instr.opcode_byte)
			{
			case 0xA8:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xA9: {
				Value *val, *eax;
				switch (size_mode)
				{
				case SIZE8:
					eax = LD_R8L(EAX_idx);
					val = CONST8(instr.operand[OPNUM_SRC].imm);
					break;

				case SIZE16:
					eax = LD_R16(EAX_idx);
					val = CONST16(instr.operand[OPNUM_SRC].imm);
					break;

				case SIZE32:
					eax = LD_R32(EAX_idx);
					val = CONST32(instr.operand[OPNUM_SRC].imm);
					break;

				default:
					UNREACHABLE;
				}

				val = AND(eax, val);

				size_mode == SIZE32 ? ST_FLG_RES(val) : ST_FLG_RES_ext(val);
				ST_FLG_AUX(CONST32(0));
			}
			break;

			default:
				BAD;
			}
		}
		break;

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
				Value *val, *rm;
				GET_RM(OPNUM_DST, val = LD_REG_val(rm); val = XOR(val, LD_REG_val(reg)); ST_REG_val(val, rm);,
					val = LD_MEM(fn_idx[size_mode], rm); val = XOR(val, LD_REG_val(reg)); ST_MEM(fn_idx[size_mode], rm, val););
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
cpu_exec_tc(cpu_t *cpu, bool exp)
{
	lib86cpu_status status = LIB86CPU_SUCCESS;
	translated_code_t *prev_tc = nullptr, *ptr_tc = nullptr;
	entry_t entry = nullptr;
	static uint64_t func_idx = 0ULL;
	bool exp_block = exp;

	// this will exit only in the case of errors or exceptions
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

			tc->exp_block = exp_block;

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
			status = cpu_translate(cpu, pc, &disas_ctx, tc.get(), &exp_block);
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
			tc->jmp_offset[0] = (void *)(cpu->jit->lookup("tail_" + std::to_string(func_idx))->getAddress());
			tc->jmp_offset[1] = nullptr;
			tc->jmp_offset[2] = (void *)(cpu->jit->lookup("main_" + std::to_string(func_idx))->getAddress());
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
		if (prev_tc != nullptr &&
			((ptr_tc->exp_block == false && prev_tc->exp_block == false) ||
			(ptr_tc->exp_block == true && prev_tc->exp_block == true))
			) {

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

		try {
			// run the translated code
			entry = static_cast<entry_t>(ptr_tc->ptr_code);
			entry(0, reinterpret_cast<uint8_t *>(cpu), &cpu->regs, &cpu->lazy_eflags);
		}
		catch (cpu_t *cpu) {
			// don't link the exception code with the other code blocks
			return LIB86CPU_EXCEPTION;
		}
	}
}
