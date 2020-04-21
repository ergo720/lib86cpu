/*
 * disassembler (Intel syntax)
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "isa.h"
#include "internal.h"

static const char *to_mnemonic(struct x86_instr *instr)
{
	return mnemo[instr->opcode];
}

static const char *byte_reg_names[] = {
	"al",
	"cl",
	"dl",
	"bl",
	"ah",
	"ch",
	"dh",
	"bh",
};

static const char *word_reg_names[] = {
	"ax",
	"cx",
	"dx",
	"bx",
	"sp",
	"bp",
	"si",
	"di",
};

static const char *full_reg_names[] = {
	"eax",
	"ecx",
	"edx",
	"ebx",
	"esp",
	"ebp",
	"esi",
	"edi",
};

static const char *seg_reg_names[] = {
	"es",
	"cs",
	"ss",
	"ds",
	"fs",
	"gs",
};

static const char *cr_reg_names[] = {
	"cr0",
	"",
	"cr2",
	"cr3",
	"cr4",
	"",
	"",
	"",
};

static const char *dbg_reg_names[] = {
	"db0",
	"db1",
	"db2",
	"db3",
	"",
	"",
	"db6",
	"db7",
};

static const char *mem_reg_names_16[] = {
	"bx+si",
	"bx+di",
	"bp+si",
	"bp+di",
	"si",
	"di",
	"bp",
	"bx",
};

static const char *mem_reg_names_32[] = {
	"eax",
	"ecx",
	"edx",
	"ebx",
	"",
	"ebp",
	"esi",
	"edi",
};

static const char *sib_reg_base_names[] = {
	"eax+",
	"ecx+",
	"edx+",
	"ebx+",
	"esp+",
	"",
	"esi+",
	"edi+",
};

static const char *sib_reg_idx_names[] = {
	"eax*",
	"ecx*",
	"edx*",
	"ebx*",
	"eiz*",
	"ebp*",
	"esi*",
	"edi*",
};

static const char *sib_scale_names[] = {
	"1",
	"2",
	"4",
	"8",
};

static const char *seg_override_names[] = {
	"es:",
	"cs:",
	"ss:",
	"ds:",
	"fs:",
	"gs:",
	"",
};

static const char *lock_names[] = {
	"",
	"lock ",
};

static const char *prefix_names[] = {
	"",
	"repnz ",
	"rep ",
};

static const char *sign_to_str(int n, const char *ret)
{
	if (n >= 0)
		return ret;

	return "-";
}

static const char *to_reg_name(struct x86_instr *instr, unsigned int reg_num)
{
	if (instr->flags & WIDTH_BYTE)
		return byte_reg_names[reg_num];

	if (instr->flags & WIDTH_WORD)
		return word_reg_names[reg_num];

	return full_reg_names[reg_num];
}

static const char *to_mem_reg_name(struct x86_instr *instr, unsigned int reg_num, uint8_t cs32)
{
	if (instr->addr_size_override ^ cs32)
		return mem_reg_names_32[reg_num];

	return mem_reg_names_16[reg_num];
}

static const char *to_sib_base_name(struct x86_instr *instr)
{
	if (instr->mod == 0 && instr->base == 5)
		return "";

	return sib_reg_base_names[instr->base];
}

static const char *to_seg_reg_name(struct x86_instr *instr, unsigned int reg_num)
{
	return seg_reg_names[reg_num];
}

static const char *to_cr_reg_name(struct x86_instr *instr, unsigned int reg_num)
{
	return cr_reg_names[reg_num];
}

static const char *to_dbg_reg_name(struct x86_instr *instr, unsigned int reg_num)
{
	return dbg_reg_names[reg_num];
}

static const char *check_prefix_override(struct x86_instr *instr)
{
	switch (instr->opcode) {
	case X86_OPC_CMPXCHG8B:
		if (instr->is_two_byte_instr == 1)
			return "QWORD PTR ";
		break;
	case X86_OPC_LES:
	case X86_OPC_LDS:
		if (instr->is_two_byte_instr == 0)
			return "FWORD PTR ";
		break;
	case X86_OPC_LSS:
	case X86_OPC_LFS:
	case X86_OPC_LGS:
	case X86_OPC_SGDTD:
	case X86_OPC_SIDTD:
	case X86_OPC_LGDTD:
	case X86_OPC_LIDTD:
	case X86_OPC_SGDTW:
	case X86_OPC_SIDTW:
	case X86_OPC_LGDTW:
	case X86_OPC_LIDTW:
		if (instr->is_two_byte_instr == 1)
			return "";
		break;
	case X86_OPC_LAR:
	case X86_OPC_LSL:
		if (instr->is_two_byte_instr == 1)
			return "WORD PTR ";
		break;
	default:
		switch (instr->opcode_byte) {
		case 0xFF: // call, jmp
			if (instr->is_two_byte_instr == 0 && (instr->reg_opc == 3 || instr->reg_opc == 5))
				return "FWORD PTR ";
			break;
		case 0xB6: // movzx
		case 0xBE: // movsx
			if (instr->is_two_byte_instr == 1)
				return "BYTE PTR ";
			break;
		case 0xB7: // movzx
		case 0xBF: // movsx
			if (instr->is_two_byte_instr == 1)
				return "WORD PTR ";
			break;
		default:
			break;
		}
	}

	return nullptr;
}

static const char *add_operand_prefix(struct x86_instr *instr)
{
	const char *prefix = check_prefix_override(instr);

	if (prefix != nullptr)
		return prefix;

	if (instr->flags & WIDTH_BYTE)
		return "BYTE PTR ";

	if (instr->flags & WIDTH_WORD)
		return "WORD PTR ";

	if (instr->flags & WIDTH_DWORD)
		return "DWORD PTR ";

	return "QWORD PTR ";
}

static int
print_operand(addr_t pc, char *operands, size_t size, struct x86_instr *instr, struct x86_operand *operand, uint8_t cs32)
{
	int ret = 0;

	switch (operand->type) {
	case OPTYPE_IMM:
		ret = snprintf(operands, size, "0x%x", operand->imm);
		break;
	case OPTYPE_FAR_PTR:
		ret = snprintf(operands, size, "0x%x:0x%x", operand->seg_sel, operand->imm);
		break;
	case OPTYPE_REL:
		ret = snprintf(operands, size, "0x%x", (unsigned int)((long)pc + instr->nr_bytes + operand->rel));
		break;
	case OPTYPE_REG:
		ret = snprintf(operands, size, "%s", to_reg_name(instr, operand->reg));
		break;
	case OPTYPE_REG8:
		ret = snprintf(operands, size, "%s", byte_reg_names[operand->reg]);
		break;
	case OPTYPE_SEG_REG:
		ret = snprintf(operands, size, "%s", to_seg_reg_name(instr, operand->reg));
		break;
	case OPTYPE_CR_REG:
		ret = snprintf(operands, size, "%s", to_cr_reg_name(instr, operand->reg));
		break;
	case OPTYPE_DBG_REG:
		ret = snprintf(operands, size, "%s", to_dbg_reg_name(instr, operand->reg));
		break;
	case OPTYPE_MOFFSET:
		ret = snprintf(operands, size, "%s%s0x%x", instr->seg_override ? seg_override_names[instr->seg_override] : "ds:", sign_to_str(operand->disp, ""), abs(operand->disp));
		break;
	case OPTYPE_MEM:
		ret = snprintf(operands, size, "%s%s[%s]", add_operand_prefix(instr), seg_override_names[instr->seg_override], to_mem_reg_name(instr, operand->reg, cs32));
		break;
	case OPTYPE_MEM_DISP:
		switch (((instr->addr_size_override ^ cs32) << 16) | (instr->mod << 8) | instr->rm) {
		case 65541: // 1, 0, 5
		case 6:     // 0, 0, 6
			ret = snprintf(operands, size, "%s%s%s0x%x", add_operand_prefix(instr), instr->seg_override ? seg_override_names[instr->seg_override] : "ds:", sign_to_str(operand->disp, ""), abs(operand->disp));
			break;
		default:
			ret = snprintf(operands, size, "%s%s[%s%s0x%x]", add_operand_prefix(instr), seg_override_names[instr->seg_override], to_mem_reg_name(instr, operand->reg, cs32), sign_to_str(operand->disp, "+"), abs(operand->disp));
		}
		break;
	case OPTYPE_SIB_MEM:
		ret = snprintf(operands, size, "%s%s[%s%s%s]", add_operand_prefix(instr), seg_override_names[instr->seg_override], sib_reg_base_names[instr->base], sib_reg_idx_names[instr->idx], sib_scale_names[instr->scale]);
		break;
	case OPTYPE_SIB_DISP:
		ret = snprintf(operands, size, "%s%s[%s%s%s%s0x%x]", add_operand_prefix(instr), seg_override_names[instr->seg_override], to_sib_base_name(instr), sib_reg_idx_names[instr->idx], sib_scale_names[instr->scale], sign_to_str(operand->disp, "+"), abs(operand->disp));
		break;
	default:
		break;
	}
	return ret;
}

size_t
disasm_instr_intel(cpu_t *cpu, x86_instr *instr, char *line, unsigned int max_line, disas_ctx_t *disas_ctx)
{
	char operands[32];
	int len = 0;
	addr_t pc = disas_ctx->virt_pc;

	assert(((cpu->cpu_flags & CPU_INTEL_SYNTAX) >> CPU_INTEL_SYNTAX_SHIFT) == 1);
	decode_instr(cpu, instr, disas_ctx);

	operands[0] = '\0';

	/* Intel syntax operands */
	if (!(instr->flags & DST_NONE))
		len += print_operand(pc, operands + len, sizeof(operands) - len, instr, &instr->operand[OPNUM_DST], disas_ctx->flags & DISAS_FLG_CS32);

	if (!(instr->flags & SRC_NONE) && !(instr->flags & DST_NONE))
		len += snprintf(operands + len, sizeof(operands) - len, ",");

	if (!(instr->flags & SRC_NONE))
		len += print_operand(pc, operands + len, sizeof(operands) - len, instr, &instr->operand[OPNUM_SRC], disas_ctx->flags & DISAS_FLG_CS32);

	if (!(instr->flags & SRC_NONE) && !(instr->flags & OP3_NONE))
		len += snprintf(operands + len, sizeof(operands) - len, ",");

	if (!(instr->flags & OP3_NONE))
		len += print_operand(pc, operands + len, sizeof(operands) - len, instr, &instr->operand[OPNUM_THIRD], disas_ctx->flags & DISAS_FLG_CS32);

	snprintf(line, max_line, "%s%s%-s %s", lock_names[instr->lock_prefix], prefix_names[instr->rep_prefix], to_mnemonic(instr), operands);

	return get_instr_length(instr);
}
