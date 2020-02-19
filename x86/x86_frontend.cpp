/*
 * x86 llvm frontend
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/LinkAllPasses.h"
#include "llvm/ExecutionEngine/Orc/LLJIT.h"
#include "lib86cpu.h"
#include "x86_internal.h"
#include "x86_frontend.h"
#include "x86_memory.h"

#define PROFILE_NUM_TIMES 30
using entry_t = translated_code_t * (*)(uint32_t dummy, cpu_ctx_t * cpu_ctx);

Value *
get_struct_member_pointer(Value *gep_start, const unsigned gep_index, translated_code_t *tc, BasicBlock *bb)
{
	std::vector<Value *> ptr_11_indices;
	ptr_11_indices.push_back(CONST32(0));
	ptr_11_indices.push_back(CONST32(gep_index));
	return GetElementPtrInst::CreateInBounds(gep_start, ptr_11_indices, "", bb);
}

Value *
get_r8h_pointer(Value *gep_start, translated_code_t *tc, BasicBlock *bb)
{
	std::vector<Value *> ptr_11_indices;
	ptr_11_indices.push_back(CONST8(1));
	return GetElementPtrInst::CreateInBounds(getIntegerType(8) , gep_start, ptr_11_indices, "", bb);
}

static StructType *
get_struct_reg(cpu_t *cpu, translated_code_t *tc)
{
	std::vector<Type *>type_struct_reg_t_fields;
	std::vector<Type *>type_struct_seg_t_fields;
	std::vector<Type *>type_struct_hiddenseg_t_fields;

	type_struct_hiddenseg_t_fields.push_back(getIntegerType(32));
	type_struct_hiddenseg_t_fields.push_back(getIntegerType(32));
	type_struct_hiddenseg_t_fields.push_back(getIntegerType(32));
	StructType *type_struct_hiddenseg_t = StructType::create(CTX(), type_struct_hiddenseg_t_fields, "struct.hiddenseg_t", false);

	type_struct_seg_t_fields.push_back(getIntegerType(16));
	type_struct_seg_t_fields.push_back(type_struct_hiddenseg_t);
	StructType *type_struct_seg_t = StructType::create(CTX(), type_struct_seg_t_fields, "struct.seg_t", false);

	for (uint8_t n = 0; n < CPU_NUM_REGS; n++) {
		switch (n)
		{
		case ES_idx:
		case CS_idx:
		case SS_idx:
		case DS_idx:
		case FS_idx:
		case GS_idx:
		case IDTR_idx:
		case GDTR_idx:
		case LDTR_idx:
		case TR_idx: {
			type_struct_reg_t_fields.push_back(type_struct_seg_t);
		}
		break;

		default:
			type_struct_reg_t_fields.push_back(getIntegerType(cpu->regs_layout[n].bits_size));
		}
	}

	return StructType::create(CTX(), type_struct_reg_t_fields, "struct.regs_t", false);
}

static StructType *
get_struct_eflags(translated_code_t *tc)
{
	std::vector<Type *>type_struct_eflags_t_fields;

	type_struct_eflags_t_fields.push_back(getIntegerType(32));
	type_struct_eflags_t_fields.push_back(getIntegerType(32));
	type_struct_eflags_t_fields.push_back(getArrayIntegerType(8, 256));

	return StructType::create(CTX(), type_struct_eflags_t_fields, "struct.eflags_t", false);
}

Value *
calc_next_pc_emit(cpu_t *cpu, translated_code_t *tc, BasicBlock *bb, Value *ptr_eip, size_t instr_size)
{
	Value *next_eip = BinaryOperator::Create(Instruction::Add, ptr_eip, CONST32(instr_size), "", bb);
	ST(GEP_EIP(), next_eip);
	return BinaryOperator::Create(Instruction::Add, CONST32(cpu->cpu_ctx.regs.cs_hidden.base), next_eip, "", bb);
}

BasicBlock *
raise_exception_emit(cpu_t *cpu, translated_code_t *tc, BasicBlock *bb2, uint8_t expno, Value *ptr_eip)
{
	BasicBlock *bb = BasicBlock::Create(CTX(), "", bb2->getParent(), 0);
	RAISE(expno);
	UNREACH();
	return bb;
}

void
write_seg_hidden_emit(cpu_t *cpu, translated_code_t *tc, BasicBlock *bb, const unsigned int reg, Value *sel, Value *base, Value *limit, Value *flags)
{
	ST_SEG(sel, reg);
	ST_SEG_HIDDEN(base, reg, SEG_BASE_idx);
	ST_SEG_HIDDEN(limit, reg, SEG_LIMIT_idx);
	ST_SEG_HIDDEN(flags, reg, SEG_FLG_idx);

	if (reg == CS_idx) {
		Value *hflags = LD(cpu->ptr_hflags);
		ST(cpu->ptr_hflags, OR(SHR(AND(flags, CONST32(SEG_HIDDEN_DB)), CONST32(20)), hflags));
	}
}

void
set_access_flg_seg_desc_emit(cpu_t *cpu, translated_code_t *tc, BasicBlock *&bb, Value *desc, Value *desc_addr, Value *ptr_eip)
{
	Function *func = bb->getParent();
	BasicBlock *bb_a = BB();
	BasicBlock *bb_next1 = BB();

	BR_COND(bb_a, bb_next1, ICMP_EQ(OR(SHR(AND(desc, CONST64(SEG_DESC_S)), CONST64(44)), SHR(AND(desc, CONST64(SEG_DESC_A)), CONST64(39))), CONST64(1)), bb);
	bb = bb_a;
	ST_MEM_PRIV(MEM_ST64_idx, desc_addr, OR(desc, CONST64(SEG_DESC_A)));
	BR_UNCOND(bb_next1, bb);
	bb = bb_next1;
}

Value *
read_seg_desc_base_emit(translated_code_t *tc, BasicBlock *bb, Value *desc)
{
	return TRUNC32(OR(OR(SHR(AND(desc, CONST64(0xFFFF0000)), CONST64(16)), SHR(AND(desc, CONST64(0xFF00000000)), CONST64(16))), SHR(AND(desc, CONST64(0xFF00000000000000)), CONST64(32))));
}

Value *
read_seg_desc_flags_emit(translated_code_t *tc, BasicBlock *bb, Value *desc)
{
	return TRUNC32(SHR(AND(desc, CONST64(0xFFFFFFFF00000000)), CONST64(32)));
}

Value *
read_seg_desc_limit_emit(translated_code_t *tc, BasicBlock *&bb, Value *desc)
{
	Function *func = bb->getParent();
	Value *limit = ALLOC32();
	ST(limit, TRUNC32(OR(AND(desc, CONST64(0xFFFF)), SHR(AND(desc, CONST64(0xF000000000000)), CONST64(32)))));
	BasicBlock *bb_g = BB();
	BasicBlock *bb_next = BB();
	BR_COND(bb_g, bb_next, ICMP_NE(AND(desc, CONST64(SEG_DESC_G)), CONST64(0)), bb);
	bb = bb_g;
	ST(limit, OR(SHL(LD(limit), CONST32(12)), CONST32(PAGE_MASK)));
	BR_UNCOND(bb_next, bb);
	bb = bb_next;
	return LD(limit);
}

std::vector<Value *>
read_seg_desc_emit(cpu_t *cpu, translated_code_t *tc, BasicBlock *&bb, Value *sel, Value *ptr_eip)
{
	std::vector<Value *> vec;
	Function *func = bb->getParent();
	BasicBlock *bb_next1 = BB();
	BasicBlock *bb_next2 = BB();
	BasicBlock *bb_gdt = BB();
	BasicBlock *bb_ldt = BB();

	Value *base = ALLOC32();
	Value *limit = ALLOC32();
	Value *idx = SHR(sel, CONST16(3));
	Value *ti = SHR(AND(sel, CONST16(4)), CONST16(2));
	BR_COND(bb_gdt, bb_ldt, ICMP_EQ(ti, CONST16(0)), bb);
	bb = bb_gdt;
	ST(base, LD_SEG_HIDDEN(GDTR_idx, SEG_BASE_idx));
	ST(limit, LD_SEG_HIDDEN(GDTR_idx, SEG_LIMIT_idx));
	BR_UNCOND(bb_next1, bb);
	bb = bb_ldt;
	// we don't support LDTs yet, so just abort
	INTRINSIC(trap);
	UNREACH();
	bb = bb_next1;
	Value *desc_addr = ADD(LD(base), ZEXT32(MUL(idx, CONST16(8))));
	vec.push_back(desc_addr);
	BasicBlock *bb_exp = raise_exception_emit(cpu, tc, bb, EXP_GP, ptr_eip);
	BR_COND(bb_exp, bb_next2, ICMP_UGT(ADD(desc_addr, CONST32(7)), ADD(LD(base), LD(limit))), bb); // sel idx outside of descriptor table
	bb = bb_next2;
	Value *desc = LD_MEM_PRIV(MEM_LD64_idx, desc_addr);
	vec.push_back(desc);
	return vec;
}

std::vector<Value *>
read_tss_desc_emit(cpu_t *cpu, translated_code_t *tc, BasicBlock *&bb, Value *sel, Value *ptr_eip)
{
	std::vector<Value *> vec;
	Function *func = bb->getParent();
	BasicBlock *bb_next1 = BB();
	BasicBlock *bb_next2 = BB();

	Value *idx = SHR(sel, CONST16(3));
	Value *ti = SHR(AND(sel, CONST16(4)), CONST16(2));
	BasicBlock *bb_exp = raise_exception_emit(cpu, tc, bb, EXP_GP, ptr_eip);
	BR_COND(bb_exp, bb_next1, ICMP_NE(ti, CONST16(0)), bb); // must be in the gdt
	bb = bb_next1;
	Value *base = LD_SEG_HIDDEN(GDTR_idx, SEG_BASE_idx);
	Value *limit = LD_SEG_HIDDEN(GDTR_idx, SEG_LIMIT_idx);
	Value *desc_addr = ADD(base, ZEXT32(MUL(idx, CONST16(8))));
	vec.push_back(desc_addr);
	bb_exp = raise_exception_emit(cpu, tc, bb, EXP_GP, ptr_eip);
	BR_COND(bb_exp, bb_next2, ICMP_UGT(ADD(desc_addr, CONST32(7)), ADD(base, limit)), bb); // sel idx outside of descriptor table
	bb = bb_next2;
	Value *desc = LD_MEM_PRIV(MEM_LD64_idx, desc_addr);
	vec.push_back(desc);
	return vec;
}

std::vector<Value *>
check_ss_desc_priv_emit(cpu_t *cpu, translated_code_t *tc, BasicBlock *&bb, Value *sel, Value *ptr_eip)
{
	std::vector<Value *> vec;
	Function *func = bb->getParent();
	BasicBlock *bb_next1 = BB();
	BasicBlock *bb_next2 = BB();
	BasicBlock *bb_next3 = BB();

	BasicBlock *bb_exp = raise_exception_emit(cpu, tc, bb, EXP_GP, ptr_eip);
	BR_COND(bb_exp, bb_next1, ICMP_EQ(SHR(sel, CONST16(2)), CONST16(0)), bb); // sel == NULL
	bb = bb_next1;
	vec = read_seg_desc_emit(cpu, tc, bb, sel, ptr_eip);
	Value *desc = vec[1];
	Value *s = TRUNC16(SHR(AND(desc, CONST64(SEG_DESC_S)), CONST64(44))); // cannot be a system segment
	Value *d = TRUNC16(SHR(AND(desc, CONST64(SEG_DESC_DC)), CONST64(42))); // cannot be a code segment
	Value *w = TRUNC16(SHR(AND(desc, CONST64(SEG_DESC_W)), CONST64(39))); // cannot be a non-writable data segment
	Value *cpl = CONST16(cpu->cpu_ctx.hflags & HFLG_CPL); // check for segment privilege violations
	Value *dpl = TRUNC16(SHR(AND(desc, CONST64(SEG_DESC_DPL)), CONST64(42)));
	Value *rpl = SHL(AND(sel, CONST16(3)), CONST16(5));
	bb_exp = raise_exception_emit(cpu, tc, bb, EXP_GP, ptr_eip);
	Value *val = XOR(OR(OR(OR(OR(s, d), w), dpl), rpl), OR(OR(OR(OR(CONST16(1), CONST16(0)), CONST16(4)), SHL(cpl, CONST16(3))), SHL(cpl, CONST16(5))));
	BR_COND(bb_exp, bb_next2, ICMP_NE(val, CONST16(0)), bb);
	Value *p = AND(desc, CONST64(SEG_DESC_P));
	bb_exp = raise_exception_emit(cpu, tc, bb, EXP_SS, ptr_eip);
	BR_COND(bb_exp, bb_next3, ICMP_EQ(p, CONST64(0)), bb); // segment not present
	bb = bb_next3;
	return vec;
}

std::vector<Value *>
check_seg_desc_priv_emit(cpu_t *cpu, translated_code_t *tc, BasicBlock *&bb, Value *sel, Value *ptr_eip)
{
	std::vector<Value *> vec;
	Function *func = bb->getParent();
	BasicBlock *bb_nonsys = BB();
	BasicBlock *bb_check = BB();
	BasicBlock *bb_next1 = BB();
	BasicBlock *bb_next2 = BB();
	BasicBlock *bb_next3 = BB();

	vec = read_seg_desc_emit(cpu, tc, bb, sel, ptr_eip);
	Value *desc = vec[1];
	Value *s = AND(desc, CONST64(SEG_DESC_S));
	BasicBlock *bb_exp = raise_exception_emit(cpu, tc, bb, EXP_GP, ptr_eip);
	BR_COND(bb_exp, bb_nonsys, ICMP_EQ(s, CONST64(0)), bb); // cannot be a system segment
	bb = bb_nonsys;
	Value *d = TRUNC16(SHR(AND(desc, CONST64(SEG_DESC_DC)), CONST64(43)));
	Value *r = TRUNC16(SHR(AND(desc, CONST64(SEG_DESC_R)), CONST64(40)));
	bb_exp = raise_exception_emit(cpu, tc, bb, EXP_GP, ptr_eip);
	BR_COND(bb_exp, bb_next1, ICMP_EQ(OR(d, r), CONST16(1)), bb); // cannot be a non-readable code segment
	bb = bb_next1;
	BR_COND(bb_check, bb_next2, OR(ICMP_EQ(d, CONST16(0)), ICMP_EQ(AND(desc, CONST64(SEG_DESC_C)), CONST64(0))), bb);
	bb = bb_check;
	Value *cpl = CONST16(cpu->cpu_ctx.hflags & HFLG_CPL);
	Value *dpl = TRUNC16(SHR(AND(desc, CONST64(SEG_DESC_DPL)), CONST64(45)));
	Value *rpl = AND(sel, CONST16(3));
	bb_exp = raise_exception_emit(cpu, tc, bb, EXP_GP, ptr_eip);
	BR_COND(bb_exp, bb_next2, AND(ICMP_UGT(rpl, dpl), ICMP_UGT(cpl, dpl)), bb); // segment privilege violation
	bb = bb_next2;
	Value *p = AND(desc, CONST64(SEG_DESC_P));
	bb_exp = raise_exception_emit(cpu, tc, bb, EXP_NP, ptr_eip);
	BR_COND(bb_exp, bb_next3, ICMP_EQ(p, CONST64(0)), bb); // segment not present
	bb = bb_next3;
	return vec;
}

void
ljmp_pe_emit(cpu_t *cpu, translated_code_t *tc, BasicBlock *&bb, Value *sel, Value *eip, Value *ptr_eip)
{
	std::vector<Value *> vec;
	Function *func = bb->getParent();
	BasicBlock *bb_next1 = BB();
	BasicBlock *bb_next2 = BB();
	BasicBlock *bb_next3 = BB();
	BasicBlock *bb_next4 = BB();
	BasicBlock *bb_sys = BB();
	BasicBlock *bb_nonsys = BB();
	BasicBlock *bb_code = BB();
	BasicBlock *bb_conf = BB();
	BasicBlock *bb_nonconf = BB();

	BasicBlock *bb_exp = raise_exception_emit(cpu, tc, bb, EXP_GP, ptr_eip);
	BR_COND(bb_exp, bb_next1, ICMP_EQ(SHR(sel, CONST16(2)), CONST16(0)), bb); // sel == NULL
	bb = bb_next1;
	vec = read_seg_desc_emit(cpu, tc, bb, sel, ptr_eip);
	Value *desc = vec[1];
	Value *s = AND(desc, CONST64(SEG_DESC_S));
	BR_COND(bb_sys, bb_nonsys, ICMP_EQ(s, CONST64(0)), bb);
	bb = bb_sys;
	// we don't support system descriptors yet, so just abort
	INTRINSIC(trap);
	UNREACH();
	bb = bb_nonsys;
	bb_exp = raise_exception_emit(cpu, tc, bb, EXP_GP, ptr_eip);
	BR_COND(bb_exp, bb_code, ICMP_EQ(AND(desc, CONST64(SEG_DESC_DC)), CONST64(0)), bb); // cannot be a data segment
	bb = bb_code;
	Value *dpl = TRUNC16(SHR(AND(desc, CONST64(SEG_DESC_DPL)), CONST64(45)));
	BR_COND(bb_conf, bb_nonconf, ICMP_NE(AND(desc, CONST64(SEG_DESC_C)), CONST64(0)), bb);
	bb = bb_conf;
	// we don't support conforming code segments yet, so just abort
	INTRINSIC(trap);
	UNREACH();
	bb = bb_nonconf;
	Value *rpl = AND(sel, CONST16(3));
	bb_exp = raise_exception_emit(cpu, tc, bb, EXP_GP, ptr_eip);
	uint16_t cpl = cpu->cpu_ctx.hflags & HFLG_CPL;
	Value *val = OR(ICMP_UGT(rpl, CONST16(cpl)), ICMP_NE(dpl, CONST16(cpl)));
	BR_COND(bb_exp, bb_next2, val, bb); // segment privilege violation
	bb = bb_next2;
	Value *p = AND(desc, CONST64(SEG_DESC_P));
	bb_exp = raise_exception_emit(cpu, tc, bb, EXP_NP, ptr_eip);
	BR_COND(bb_exp, bb_next3, ICMP_EQ(p, CONST64(0)), bb); // segment not present
	bb = bb_next3;
	Value *limit = read_seg_desc_limit_emit(tc, bb, desc);
	bb_exp = raise_exception_emit(cpu, tc, bb, EXP_GP, ptr_eip);
	BR_COND(bb_exp, bb_next4, ICMP_UGT(eip, limit), bb); // segment limit exceeded
	bb = bb_next4;
	set_access_flg_seg_desc_emit(cpu, tc, bb, vec[1], vec[0], ptr_eip);
	write_seg_hidden_emit(cpu, tc, bb, CS_idx, OR(AND(sel, CONST16(0xFFFC)), CONST16(cpl)), read_seg_desc_base_emit(tc, bb, desc),
		limit, read_seg_desc_flags_emit(tc, bb, desc));
	ST_R32(eip, EIP_idx);
}

Value *
mem_read_no_cpl_emit(cpu_t *cpu, translated_code_t *tc, BasicBlock *bb, Value *addr, Value *ptr_eip, const unsigned int idx)
{
	Value *hflags = LD(cpu->ptr_hflags);
	hflags = AND(hflags, NOT(CONST32(HFLG_CPL_PRIV)));
	ST(cpu->ptr_hflags, hflags);
	Value *value = LD_MEM(idx, addr);
	hflags = LD(cpu->ptr_hflags);
	hflags = OR(hflags, CONST32(HFLG_CPL_PRIV));
	ST(cpu->ptr_hflags, hflags);
	return value;
}

void
mem_write_no_cpl_emit(cpu_t *cpu, translated_code_t *tc, BasicBlock *bb, Value *addr, Value *value, Value *ptr_eip, const unsigned int idx)
{
	Value *hflags = LD(cpu->ptr_hflags);
	hflags = AND(hflags, NOT(CONST32(HFLG_CPL_PRIV)));
	ST(cpu->ptr_hflags, hflags);
	ST_MEM(idx, addr, value);
	hflags = LD(cpu->ptr_hflags);
	hflags = OR(hflags, CONST32(HFLG_CPL_PRIV));
	ST(cpu->ptr_hflags, hflags);
}

void
check_io_priv_emit(cpu_t *cpu, translated_code_t *tc, BasicBlock *&bb, Value *port, Value *mask, Value *ptr_eip)
{
	if ((cpu->cpu_ctx.hflags & HFLG_PE_MODE) && ((cpu->cpu_ctx.hflags & HFLG_CPL) > ((cpu->cpu_ctx.regs.eflags & IOPL_MASK) >> 12))) {
		Function *func = bb->getParent();
		BasicBlock *bb_next1 = BB();
		BasicBlock *bb_next2 = BB();
		BasicBlock *bb_next3 = BB();
		BasicBlock *bb_exp = raise_exception_emit(cpu, tc, bb, EXP_GP, ptr_eip);

		Value *base = LD_SEG_HIDDEN(TR_idx, SEG_BASE_idx);
		Value *limit = LD_SEG_HIDDEN(TR_idx, SEG_LIMIT_idx);
		BR_COND(bb_exp, bb_next1, ICMP_ULT(limit, CONST32(103)), bb);
		bb = bb_next1;
		Value *io_map_offset = ZEXT32(LD_MEM(MEM_LD16_idx, ADD(base, CONST32(102))));
		Value *io_port_offset = ADD(io_map_offset, SHR(port, CONST32(3)));
		BR_COND(bb_exp, bb_next2, ICMP_UGT(ADD(io_port_offset, CONST32(1)), limit), bb);
		bb = bb_next2;
		Value *value = ALLOC32();
		ST(value, ZEXT32(LD_MEM(MEM_LD16_idx, ADD(base, io_port_offset))));
		ST(value, SHR(LD(value), AND(port, CONST32(7))));
		BR_COND(bb_exp, bb_next3, ICMP_NE(AND(LD(value), mask), CONST32(0)), bb);
		bb = bb_next3;
	}
}

Value *
get_immediate_op(translated_code_t *tc, x86_instr *instr, uint8_t idx, uint8_t size_mode)
{
	Value *value;

	switch (size_mode)
	{
	case SIZE8:
		value = CONST8(instr->operand[idx].imm);
		break;

	case SIZE16:
		value = CONST16(instr->operand[idx].imm);
		break;

	case SIZE32:
		value = CONST32(instr->operand[idx].imm);
		break;

	default:
		LIB86CPU_ABORT_msg("Invalid size_mode \"%c\" used in %s\n", size_mode, __func__);
	}

	return value;
}

Value *
get_register_op(cpu_t *cpu, translated_code_t *tc, x86_instr *instr, BasicBlock *bb, uint8_t idx)
{
	assert(instr->operand[idx].type == OPTYPE_REG || instr->operand[idx].type == OPTYPE_CR_REG);
	return get_operand(cpu, instr, tc, bb, idx);
}

void
set_flags_sum(cpu_t *cpu, translated_code_t *tc, BasicBlock *bb, Value *sum, Value *a, Value *b, uint8_t size_mode)
{
	switch (size_mode)
	{
	case SIZE8:
		ST_FLG_RES_ext(sum);
		ST_FLG_SUM_AUX8(a, b, sum);
		break;

	case SIZE16:
		ST_FLG_RES_ext(sum);
		ST_FLG_SUM_AUX16(a, b, sum);
		break;

	case SIZE32:
		ST_FLG_RES(sum);
		ST_FLG_SUM_AUX32(a, b, sum);
		break;

	default:
		LIB86CPU_ABORT_msg("Invalid size_mode \"%c\" used in %s\n", size_mode, __func__);
	}
}

void
set_flags_sub(cpu_t *cpu, translated_code_t *tc, BasicBlock *bb, Value *sub, Value *a, Value *b, uint8_t size_mode)
{
	switch (size_mode)
	{
	case SIZE8:
		ST_FLG_RES_ext(sub);
		ST_FLG_SUB_AUX8(a, b, sub);
		break;

	case SIZE16:
		ST_FLG_RES_ext(sub);
		ST_FLG_SUB_AUX16(a, b, sub);
		break;

	case SIZE32:
		ST_FLG_RES(sub);
		ST_FLG_SUB_AUX32(a, b, sub);
		break;

	default:
		LIB86CPU_ABORT_msg("Invalid size_mode \"%c\" used in %s\n", size_mode, __func__);
	}
}

void
set_flags(cpu_t *cpu, translated_code_t *tc, BasicBlock *bb, Value *res, Value *aux, uint8_t size_mode)
{
	size_mode == SIZE32 ? ST_FLG_RES(res) : ST_FLG_RES_ext(res);
	ST_FLG_AUX(aux);
}

void
optimize(translated_code_t *tc, Function *func)
{
	legacy::FunctionPassManager pm = legacy::FunctionPassManager(tc->mod);

	pm.add(createPromoteMemoryToRegisterPass());
	pm.add(createInstructionCombiningPass());
	pm.add(createConstantPropagationPass());
	pm.add(createDeadStoreEliminationPass());
	pm.add(createDeadCodeEliminationPass());
	pm.run(*func);
}

void
get_ext_fn(cpu_t *cpu, translated_code_t *tc, Function *func)
{
	static size_t bit_size[7] = { 8, 16, 32, 64, 8, 16, 32 };
	static size_t arg_size[7] = { 32, 32, 32, 32, 16, 16, 16 };
	static const char *func_name_ld[7] = { "mem_read8", "mem_read16", "mem_read32", "mem_read64", "io_read8", "io_read16", "io_read32" };
	static const char *func_name_st[7] = { "mem_write8", "mem_write16", "mem_write32", "mem_write64", "io_write8", "io_write16", "io_write32" };
	Function::arg_iterator args_start = func->arg_begin();
	args_start++;

	for (uint8_t i = 0; i < 7; i++) {
		cpu->ptr_mem_ldfn[i] = cast<Function>(tc->mod->getOrInsertFunction(func_name_ld[i], getIntegerType(bit_size[i]), args_start->getType(),
			getIntegerType(arg_size[i]), getIntegerType(32)));
	}

	for (uint8_t i = 0; i < 7; i++) {
		cpu->ptr_mem_stfn[i] = cast<Function>(tc->mod->getOrInsertFunction(func_name_st[i], getVoidType(), args_start->getType(),
			getIntegerType(arg_size[i]), getIntegerType(bit_size[i]), getIntegerType(32)));
	}

	cpu->exp_fn = cast<Function>(tc->mod->getOrInsertFunction("cpu_raise_exception", getVoidType(), args_start->getType(), getIntegerType(8), getIntegerType(32)));
	cpu->crN_fn = cast<Function>(tc->mod->getOrInsertFunction("cpu_update_crN", getVoidType(), args_start->getType(), getIntegerType(32), getIntegerType(8), getIntegerType(32),
		getIntegerType(32)));
}

translated_code_t *
tc_run_code(cpu_ctx_t *cpu_ctx, translated_code_t *tc)
{
	try {
		// run the translated code
		entry_t entry = static_cast<entry_t>(tc->ptr_code);
		return entry(0, cpu_ctx);
	}
	catch (uint8_t expno) {
		// don't link the previous code block if we returned with an exception
		return nullptr;
	}
}

static inline uint32_t
tc_hash(addr_t pc)
{
	return pc & (CODE_CACHE_MAX_SIZE - 1);
}

translated_code_t *
tc_cache_search(cpu_t *cpu, addr_t pc)
{
	uint32_t flags = cpu->cpu_ctx.hflags | (cpu->cpu_ctx.regs.eflags & (TF_MASK | IOPL_MASK | RF_MASK | AC_MASK));
	uint32_t idx = tc_hash(pc);
	auto it = cpu->code_cache[idx].begin();
	while (it != cpu->code_cache[idx].end()) {
		translated_code_t *tc = it->get();
		if (tc->cs_base == cpu->cpu_ctx.regs.cs_hidden.base &&
			tc->pc == pc &&
			tc->flags == flags) {
			return tc;
		}
		it++;
	}

	return nullptr;
}

void
tc_cache_insert(cpu_t *cpu, addr_t pc, std::unique_ptr<translated_code_t> &&tc)
{
	cpu->num_tc++;
	cpu->code_cache[tc_hash(pc)].push_front(std::move(tc));
}

void
tc_cache_clear(cpu_t *cpu)
{
	cpu->num_tc = 0;
	for (auto &bucket : cpu->code_cache) {
		bucket.clear();
	}

	// annoyingly, llvm doesn't implement module removal, which means we have to destroy the entire jit object to delete the memory of the
	// generated code blocks. This is documented at https://llvm.org/docs/ORCv2.html and in particular "Module removal is not yet supported.
	// There is no equivalent of the layer concept removeModule/removeObject methods. Work on resource tracking and removal in ORCv2 is ongoing."

	delete cpu->dl;
	auto jtmb = orc::JITTargetMachineBuilder::detectHost();
	if (!jtmb) {
		LIB86CPU_ABORT_msg("Couldn't recreate jit object! (failed at line %d)\n", __LINE__);
	}
	SubtargetFeatures features;
	StringMap<bool> host_features;
	if (sys::getHostCPUFeatures(host_features))
		for (auto &F : host_features) {
			features.AddFeature(F.first(), F.second);
		}
	jtmb->setCPU(sys::getHostCPUName())
		.addFeatures(features.getFeatures())
		.setRelocationModel(None)
		.setCodeModel(None);
	auto dl = jtmb->getDefaultDataLayoutForTarget();
	if (!dl) {
		LIB86CPU_ABORT_msg("Couldn't recreate jit object! (failed at line %d)\n", __LINE__);
	}
	cpu->dl = new DataLayout(*dl);
	if (cpu->dl == nullptr) {
		LIB86CPU_ABORT_msg("Couldn't recreate jit object! (failed at line %d)\n", __LINE__);
	}
	auto jit = orc::LLJIT::Create(std::move(*jtmb), *dl, std::thread::hardware_concurrency());
	if (!jit) {
		LIB86CPU_ABORT_msg("Couldn't recreate jit object! (failed at line %d)\n", __LINE__);
	}
	cpu->jit = std::move(*jit);
	cpu->jit->getMainJITDylib().setGenerator(
		*orc::DynamicLibrarySearchGenerator::GetForCurrentProcess(*dl));
#ifdef _WIN32
	cpu->jit->getObjLinkingLayer().setOverrideObjectFlagsWithResponsibilityFlags(true);
#endif
}

void
tc_link_direct(translated_code_t *prev_tc, translated_code_t *ptr_tc, addr_t pc)
{
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
		int32_t tc_offset = reinterpret_cast<uintptr_t>(ptr_tc->jmp_offset[2]) -
			reinterpret_cast<uintptr_t>(static_cast<uint8_t *>(prev_tc->jmp_offset[0]) + 6 /*sizeof(cmp)*/ + 6 /*sizeof(je)*/);
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
		int32_t tc_offset = reinterpret_cast<uintptr_t>(ptr_tc->jmp_offset[2]) -
			reinterpret_cast<uintptr_t>(static_cast<uint8_t *>(prev_tc->jmp_offset[1]) + 5 /*sizeof(jmp)*/);
		memcpy(prev_tc->jmp_offset[1], &jmp_instr, 1);
		memcpy(static_cast<uint8_t *>(prev_tc->jmp_offset[1]) + 1, &tc_offset, 4);  // jmp tc_offset
	}

#else
#error don't know how to patch tc on this platform
#endif

	tc_protect(prev_tc->jmp_offset[0], prev_tc->jmp_code_size, true);
}

static void
tc_link_indirect(translated_code_t *tc, translated_code_t *tc1, translated_code_t *tc2)
{
	// llvm marks the generated code memory as read/execute (it's done by Memory::protectMappedMemory), which triggers an access violation when
	// we try to write to it during the tc linking phase. So, we temporarily mark it as writable and then restore the write protection.
	// NOTE: perhaps we can use the llvm SectionMemoryManager to do this somehow...

	tc_protect(tc->jmp_offset[0], tc->jmp_code_size, false);

#if defined __i386 || defined _M_IX86

	static uint16_t cmp_instr = 0xf981;
	static uint16_t je_instr = 0x840f;
	static uint8_t nop_instr = 0x90;
	int32_t tc_offset1 = reinterpret_cast<uintptr_t>(tc1->jmp_offset[2]) -
		reinterpret_cast<uintptr_t>(static_cast<uint8_t *>(tc->jmp_offset[0]) + 6 /*sizeof(cmp)*/ + 6 /*sizeof(je)*/);
	int32_t tc_offset2 = reinterpret_cast<uintptr_t>(tc2->jmp_offset[2]) -
		reinterpret_cast<uintptr_t>(static_cast<uint8_t *>(tc->jmp_offset[0]) + (6 /*sizeof(cmp)*/ + 6 /*sizeof(je)*/) * 2);
	memcpy(tc->jmp_offset[0], &cmp_instr, 2);
	memcpy(static_cast<uint8_t *>(tc->jmp_offset[0]) + 2, &tc1->pc, 4);              // cmp ecx, pc1
	memcpy(static_cast<uint8_t *>(tc->jmp_offset[0]) + 6, &je_instr, 2);
	memcpy(static_cast<uint8_t *>(tc->jmp_offset[0]) + 8, &tc_offset1, 4);           // je tc_offset1
	memcpy(static_cast<uint8_t *>(tc->jmp_offset[0]) + 12, &cmp_instr, 2);
	memcpy(static_cast<uint8_t *>(tc->jmp_offset[0]) + 14, &tc2->pc, 4);             // cmp ecx, pc2
	memcpy(static_cast<uint8_t *>(tc->jmp_offset[0]) + 18, &je_instr, 2);
	memcpy(static_cast<uint8_t *>(tc->jmp_offset[0]) + 20, &tc_offset2, 4);          // je tc_offset2
	memcpy(static_cast<uint8_t *>(tc->jmp_offset[0]) + 24, &nop_instr, 1);           // nop

#else
#error don't know how to patch tc on this platform
#endif

	tc_protect(tc->jmp_offset[0], tc->jmp_code_size, true);
}

JIT_EXTERNAL_CALL_C uint8_t *
tc_profile_indirect(cpu_ctx_t *cpu_ctx, translated_code_t *tc, addr_t pc)
{
	cpu_t *cpu = cpu_ctx->cpu;

	if (tc->jmp_offset[1] == 0) {
		if (tc->profiling_vec.size() == PROFILE_NUM_TIMES) {

			std::map<addr_t, size_t> pc_count_hit;
			for (auto it = tc->profiling_vec.begin(); it != tc->profiling_vec.end(); it++) {
				++pc_count_hit[*it];
			}

			auto pc1 = std::max_element(pc_count_hit.begin(), pc_count_hit.end(), [](const auto &a, const auto &b)
				{
					return a.second < b.second;
				})->first;

			pc_count_hit.erase(pc_count_hit.find(pc1));

			auto pc2 = std::max_element(pc_count_hit.begin(), pc_count_hit.end(), [](const auto &a, const auto &b)
				{
					return a.second < b.second;
				})->first;

			tc_link_indirect(tc, tc_cache_search(cpu, pc1), tc_cache_search(cpu, pc2));
			tc->profiling_vec.clear();
			tc->jmp_offset[1] = reinterpret_cast<void *>(1);
		}
		else {
			tc->profiling_vec.push_back(pc);
		}
	}

	tc = tc_cache_search(cpu, pc);
	return reinterpret_cast<uint8_t *>(tc == nullptr ? 0 : tc->jmp_offset[2]);
}

FunctionType *
create_tc_fntype(cpu_t *cpu, translated_code_t *tc)
{
	std::vector<Type *>type_struct_cpu_ctx_t_fields;
	type_struct_cpu_ctx_t_fields.push_back(getPointerType(StructType::create(CTX(), "struct.cpu_t")));  // NOTE: opaque struct
	type_struct_cpu_ctx_t_fields.push_back(get_struct_reg(cpu, tc));
	type_struct_cpu_ctx_t_fields.push_back(get_struct_eflags(tc));
	type_struct_cpu_ctx_t_fields.push_back(getIntegerType(32));

	IntegerType *type_i32 = getIntegerType(32);                                      // eip/pc ptr
	PointerType *type_pstruct = getPointerType(StructType::create(CTX(),
		type_struct_cpu_ctx_t_fields, "struct.cpu_ctx_t", false));                   // cpu_ctx ptr

	std::vector<Type *> type_func_args;
	type_func_args.push_back(type_i32);
	type_func_args.push_back(type_pstruct);

	FunctionType *type_func = FunctionType::get(
		getPointerType(StructType::create(CTX(), "struct.tc_t")),  // ret, as opaque tc struct
		type_func_args,                                             // args
		false);

	return type_func;
}

Function *
create_tc_prologue(cpu_t *cpu, translated_code_t *tc, FunctionType *fntype)
{
	// create the function which calls the translation function
	Function *start = Function::Create(
		fntype,                               // func type
		GlobalValue::ExternalLinkage,         // linkage
		"start",                              // name
		tc->mod);
	start->setCallingConv(CallingConv::C);
	start->addAttribute(1U, Attribute::NoCapture);

	// create the bb of the start function
	BasicBlock *bb = BasicBlock::Create(CTX(), "", start, 0);

	Function::arg_iterator args_start = start->arg_begin();
	Value *dummy = args_start++;
	Value *ptr_cpu_ctx = args_start++;

	// create the translation function, it will hold all the translated code
	Function *func = Function::Create(
		fntype,                              // func type
		GlobalValue::ExternalLinkage,        // linkage
		"main",                              // name
		tc->mod);
	func->setCallingConv(CallingConv::Fast);

	// insert a call to the translation function and a ret for the start function
	CallInst *ci = CallInst::Create(func, std::vector<Value *> { dummy, ptr_cpu_ctx }, "", bb);
	ci->setCallingConv(CallingConv::Fast);
	ReturnInst::Create(CTX(), ci, bb);

	return func;
}

void
create_tc_epilogue(cpu_t *cpu, translated_code_t *tc, FunctionType *fntype, disas_ctx_t *disas_ctx)
{
	// create the tail function
	Function *tail = Function::Create(
		fntype,                              // func type
		GlobalValue::ExternalLinkage,        // linkage
		"tail",                              // name
		tc->mod);
	tail->setCallingConv(CallingConv::Fast);

	// create the bb of the tail function
	BasicBlock *bb = BasicBlock::Create(CTX(), "", tail, 0);

	FunctionType *type_func_asm = FunctionType::get(
		getVoidType(),  // void ret
		// no args
		false);

	if (disas_ctx->flags & DISAS_FLG_TC_INDIRECT) {
		// emit some dummy instructions, a call to tc_profile_indirect and a conditional jump. We do this ourselves to avoid llvm messing with the stack,
		// which would lead to a crash when a jump is taken

		Function::arg_iterator args_start = disas_ctx->bb->getParent()->arg_begin();
		args_start++;

		tc->mod->getOrInsertFunction("tc_profile_indirect", getPointerType(getIntegerType(8)), args_start->getType(),
			getPointerType(StructType::create(CTX(), "struct.tc_t")), getIntegerType(32));
		uintptr_t addr = cpu->jit->lookup("tc_profile_indirect")->getAddress();

#if defined __i386 || defined _M_IX86

		std::string asm_str = std::string("mov eax, $$-1\n\tmov eax, $$-2\n\tmov eax, $$-3\n\tmov eax, $$-4\n\tmov eax, $$-5\n\tsub esp, $$12\n\tmov [esp], edx\n\tmov dword ptr [esp+$$4], $$")
		+ std::to_string(reinterpret_cast<uintptr_t>(tc)) + std::string("\n\tmov [esp+$$8], ecx\n\tmov eax, $$") + std::to_string(addr) + std::string("\n\tcall eax\n\tadd esp, $$12\n\tmov edx, $$")
		+ std::to_string(reinterpret_cast<uintptr_t>(&cpu->cpu_ctx)) + std::string("\n\tcmp eax, $$0\n\tje skip_next\n\tjmp eax\n\tskip_next:");
		InlineAsm *ia = InlineAsm::get(type_func_asm, asm_str, "~{eax},~{ecx},~{edx}", true, false, InlineAsm::AsmDialect::AD_Intel);
		CallInst::Create(ia, "", bb);
		tc->jmp_code_size = 25;

#else
#error don't know how to construct the tc epilogue on this platform
#endif
	}
	else {
		// emit some dummy instructions, these will be replaced by jumps when we link this tc to another

#if defined __i386 || defined _M_IX86

		InlineAsm *ia = InlineAsm::get(type_func_asm, "mov ecx, $$-1\n\tmov ecx, $$-2\n\tmov ecx, $$-3\n\tmov ecx, $$-4", "~{ecx}", true, false, InlineAsm::AsmDialect::AD_Intel);
		CallInst::Create(ia, "", bb);
		tc->jmp_code_size = 20;

#else
#error don't know how to construct the tc epilogue on this platform
#endif
	}

	ReturnInst::Create(CTX(), CONSTptr(8, tc), bb);

	// insert a call to the tail function and a ret for the main function
	CallInst *ci = CallInst::Create(tail, std::vector<Value *> { disas_ctx->next_pc, cpu->ptr_cpu_ctx }, "", disas_ctx->bb);
	ci->setCallingConv(CallingConv::Fast);
	ci->setTailCallKind(CallInst::TailCallKind::TCK_Tail);
	ReturnInst::Create(CTX(), ci, disas_ctx->bb);
}

Value *
get_operand(cpu_t *cpu, x86_instr *instr , translated_code_t *tc, BasicBlock *bb, const unsigned opnum)
{
	assert(opnum < OPNUM_COUNT && "Invalid operand number specified\n");

	x86_operand *operand = &instr->operand[opnum];

	switch (operand->type) {
	case OPTYPE_MEM:
		if (instr->addr_size_override ^ ((cpu->cpu_ctx.hflags & HFLG_CS32) >> CS32_SHIFT)) {
			uint8_t reg_idx;
			switch (operand->reg) {
			case 0:
				reg_idx = EAX_idx;
				break;
			case 1:
				reg_idx = ECX_idx;
				break;
			case 2:
				reg_idx = EDX_idx;
				break;
			case 3:
				reg_idx = EBX_idx;
				break;
			case 6:
				reg_idx = ESI_idx;
				break;
			case 7:
				reg_idx = EDI_idx;
				break;
			case 4:
				assert(0 && "operand->reg specifies SIB with OPTYPE_MEM!\n");
				return nullptr;
			case 5:
				assert(0 && "operand->reg specifies OPTYPE_MEM_DISP with OPTYPE_MEM!\n");
				return nullptr;
			default:
				assert(0 && "Unknown reg index in OPTYPE_MEM\n");
				return nullptr;
			}
			return ADD(LD_R32(reg_idx), LD_SEG_HIDDEN(instr->seg + SEG_offset, SEG_BASE_idx));
		}
		else {
			Value *reg;
			switch (operand->reg) {
			case 0:
				reg = ADD(LD_R16(EBX_idx), LD_R16(ESI_idx));
				break;
			case 1:
				reg = ADD(LD_R16(EBX_idx), LD_R16(EDI_idx));
				break;
			case 2:
				reg = ADD(LD_R16(EBP_idx), LD_R16(ESI_idx));
				break;
			case 3:
				reg = ADD(LD_R16(EBP_idx), LD_R16(EDI_idx));
				break;
			case 4:
				reg = LD_R16(ESI_idx);
				break;
			case 5:
				reg = LD_R16(EDI_idx);
				break;
			case 7:
				reg = LD_R16(EBX_idx);
				break;
			case 6:
				assert(0 && "operand->reg specifies OPTYPE_MEM_DISP with OPTYPE_MEM!\n");
				return nullptr;
			default:
				assert(0 && "Unknown reg index in OPTYPE_MEM\n");
				return nullptr;
			}
			return ADD(ZEXT32(reg), LD_SEG_HIDDEN(instr->seg + SEG_offset, SEG_BASE_idx));
		}
	case OPTYPE_MOFFSET:
		return ADD(CONST32(operand->disp), LD_SEG_HIDDEN(instr->seg + SEG_offset, SEG_BASE_idx));
	case OPTYPE_MEM_DISP:
		if (instr->addr_size_override ^ ((cpu->cpu_ctx.hflags & HFLG_CS32) >> CS32_SHIFT)) {
			Value *reg;
			uint8_t reg_idx;
			switch (instr->mod) {
			case 0:
				if (instr->rm == 5) {
					reg = CONST32(operand->disp);
				}
				else {
					assert(0 && "instr->mod == 0 but instr->rm != 5 in OPTYPE_MEM_DISP!\n");
					return nullptr;
				}
				break;
			case 1:
				switch (instr->rm) {
				case 0:
					reg_idx = EAX_idx;
					break;
				case 1:
					reg_idx = ECX_idx;
					break;
				case 2:
					reg_idx = EDX_idx;
					break;
				case 3:
					reg_idx = EBX_idx;
					break;
				case 5:
					reg_idx = EBP_idx;
					break;
				case 6:
					reg_idx = ESI_idx;
					break;
				case 7:
					reg_idx = EDI_idx;
					break;
				case 4:
					assert(0 && "instr->rm specifies OPTYPE_SIB_DISP with OPTYPE_MEM_DISP!\n");
					return nullptr;
				default:
					assert(0 && "Unknown rm index in OPTYPE_MEM_DISP\n");
					return nullptr;
				}
				reg = ADD(LD_R32(reg_idx), SEXT32(CONST8(operand->disp)));
				break;
			case 2:
				switch (instr->rm) {
				case 0:
					reg_idx = EAX_idx;
					break;
				case 1:
					reg_idx = ECX_idx;
					break;
				case 2:
					reg_idx = EDX_idx;
					break;
				case 3:
					reg_idx = EBX_idx;
					break;
				case 5:
					reg_idx = EBP_idx;
					break;
				case 6:
					reg_idx = ESI_idx;
					break;
				case 7:
					reg_idx = EDI_idx;
					break;
				case 4:
					assert(0 && "instr->rm specifies OPTYPE_SIB_DISP with OPTYPE_MEM_DISP!\n");
					return nullptr;
				default:
					assert(0 && "Unknown rm index in OPTYPE_MEM_DISP\n");
					return nullptr;
				}
				reg = ADD(LD_R32(reg_idx), CONST32(operand->disp));
				break;
			case 3:
				assert(0 && "instr->rm specifies OPTYPE_REG with OPTYPE_MEM_DISP!\n");
				return nullptr;
			default:
				assert(0 && "Unknown rm index in OPTYPE_MEM_DISP\n");
				return nullptr;
			}
			return ADD(reg, LD_SEG_HIDDEN(instr->seg + SEG_offset, SEG_BASE_idx));
		}
		else {
			Value *reg;
			switch (instr->mod) {
			case 0:
				if (instr->rm == 6) {
					reg = CONST16(operand->disp);
				}
				else {
					assert(0 && "instr->mod == 0 but instr->rm != 6 in OPTYPE_MEM_DISP!\n");
					return nullptr;
				}
				break;
			case 1:
				switch (instr->rm) {
				case 0:
					reg = ADD(ADD(LD_R16(EBX_idx), LD_R16(ESI_idx)), SEXT16(CONST8(operand->disp)));
					break;
				case 1:
					reg = ADD(ADD(LD_R16(EBX_idx), LD_R16(EDI_idx)), SEXT16(CONST8(operand->disp)));
					break;
				case 2:
					reg = ADD(ADD(LD_R16(EBP_idx), LD_R16(ESI_idx)), SEXT16(CONST8(operand->disp)));
					break;
				case 3:
					reg = ADD(ADD(LD_R16(EBP_idx), LD_R16(EDI_idx)), SEXT16(CONST8(operand->disp)));
					break;
				case 4:
					reg = ADD(LD_R16(ESI_idx), SEXT16(CONST8(operand->disp)));
					break;
				case 5:
					reg = ADD(LD_R16(EDI_idx), SEXT16(CONST8(operand->disp)));
					break;
				case 6:
					reg = ADD(LD_R16(EBP_idx), SEXT16(CONST8(operand->disp)));
					break;
				case 7:
					reg = ADD(LD_R16(EBX_idx), SEXT16(CONST8(operand->disp)));
					break;
				default:
					assert(0 && "Unknown rm index in OPTYPE_MEM_DISP\n");
					return nullptr;
				}
				break;
			case 2:
				switch (instr->rm) {
				case 0:
					reg = ADD(ADD(LD_R16(EBX_idx), LD_R16(ESI_idx)), CONST16(operand->disp));
					break;
				case 1:
					reg = ADD(ADD(LD_R16(EBX_idx), LD_R16(EDI_idx)), CONST16(operand->disp));
					break;
				case 2:
					reg = ADD(ADD(LD_R16(EBP_idx), LD_R16(ESI_idx)), CONST16(operand->disp));
					break;
				case 3:
					reg = ADD(ADD(LD_R16(EBP_idx), LD_R16(EDI_idx)), CONST16(operand->disp));
					break;
				case 4:
					reg = ADD(LD_R16(ESI_idx), CONST16(operand->disp));
					break;
				case 5:
					reg = ADD(LD_R16(EDI_idx), CONST16(operand->disp));
					break;
				case 6:
					reg = ADD(LD_R16(EBP_idx), CONST16(operand->disp));
					break;
				case 7:
					reg = ADD(LD_R16(EBX_idx), CONST16(operand->disp));
					break;
				default:
					assert(0 && "Unknown rm index in OPTYPE_MEM_DISP\n");
					return nullptr;
				}
				break;
			case 3:
				assert(0 && "instr->rm specifies OPTYPE_REG with OPTYPE_MEM_DISP!\n");
				return nullptr;
			default:
				assert(0 && "Unknown rm index in OPTYPE_MEM_DISP\n");
				return nullptr;
			}
			return ADD(ZEXT32(reg), LD_SEG_HIDDEN(instr->seg + SEG_offset, SEG_BASE_idx));
		}
	case OPTYPE_REG:
	case OPTYPE_REG8:
		if (operand->reg > 7) {
			assert(0 && "Unknown reg index in OPTYPE_REG(8)\n");
			return nullptr;
		}
		if (instr->flags & WIDTH_BYTE || operand->type == OPTYPE_REG8) {
			if (operand->reg < 4) {
				return GEP_R8L(operand->reg);
			}
			else {
				return GEP_R8H(operand->reg - 4);
			}
		}
		else if (instr->flags & WIDTH_WORD) {
			return GEP_R16(operand->reg);
		}
		else {
			return GEP_R32(operand->reg);
		}
	case OPTYPE_SEG_REG:
		switch (operand->reg) {
		case 0:
			return GEP_ES();
		case 1:
			return GEP_CS();
		case 2:
			return GEP_SS();
		case 3:
			return GEP_DS();
		case 4:
			return GEP_FS();
		case 5:
			return GEP_GS();
		case 6:
		case 7:
			assert(0 && "operand->reg specifies a reserved segment register!\n");
			return nullptr;
		default:
			assert(0 && "Unknown reg index in OPTYPE_SEG_REG\n");
			return nullptr;
		}
	case OPTYPE_CR_REG:
		switch (operand->reg) {
		case 0:
			return GEP_CR0();
		case 2:
			return GEP_CR2();
		case 3:
			return GEP_CR3();
		case 4:
			return GEP_CR4();
		case 1:
		case 6:
		case 7:
			assert(0 && "operand->reg specifies a reserved control register!\n");
			return nullptr;
		default:
			assert(0 && "Unknown reg index in OPTYPE_CR_REG\n");
			return nullptr;
		}
	case OPTYPE_DBG_REG:
		switch (operand->reg) {
		case 0:
			return GEP_DR0();
		case 1:
			return GEP_DR1();
		case 2:
			return GEP_DR2();
		case 3:
			return GEP_DR3();
		case 6:
			return GEP_DR6();
		case 7:
			return GEP_DR7();
		case 4:
		case 5:
			assert(0 && "operand->reg specifies a reserved debug register!\n");
			return nullptr;
		default:
			assert(0 && "Unknown reg index in OPTYPE_DBG_REG\n");
			return nullptr;
		}
	case OPTYPE_REL:
		switch (instr->flags & WIDTH_MASK) {
		case WIDTH_BYTE:
			return CONST8(operand->rel);
		case WIDTH_WORD:
			return CONST16(operand->rel);
		case WIDTH_DWORD:
			return CONST32(operand->rel);
		default:
			assert(0 && "Missing operand size in OPTYPE_REL (calling %s on an instruction without operands?)\n");
			return nullptr;
		}
	case OPTYPE_SIB_MEM:
	case OPTYPE_SIB_DISP:
		assert((instr->mod == 0 || instr->mod == 1 || instr->mod == 2) && instr->rm == 4);
		Value *scale, *idx, *base;
		if (instr->scale < 4) {
			scale = CONST32(1ULL << instr->scale);
		}
		else {
			assert(0 && "Invalid sib scale specified\n");
			return nullptr;
		}
		switch (instr->idx) {
		case 0:
		case 1:
		case 2:
		case 3:
		case 5:
		case 6:
		case 7:
			idx = LD_R32(instr->idx);
			break;
		case 4:
			idx = CONST32(0);
			break;
		default:
			assert(0 && "Unknown sib index specified\n");
			return nullptr;
		}
		switch (instr->base) {
		case 0:
		case 1:
		case 2:
		case 3:
		case 4:
		case 6:
		case 7:
			base = LD_R32(instr->base);
			break;
		case 5:
			switch (instr->mod) {
			case 0:
				return ADD(ADD(MUL(idx, scale), CONST32(instr->disp)), LD_SEG_HIDDEN(instr->seg + SEG_offset, SEG_BASE_idx));
			case 1:
				return ADD(ADD(ADD(MUL(idx, scale), SEXT32(CONST8(operand->disp))), LD_R32(EBP_idx)), LD_SEG_HIDDEN(instr->seg + SEG_offset, SEG_BASE_idx));
			case 2:
				return ADD(ADD(ADD(MUL(idx, scale), CONST32(operand->disp)), LD_R32(EBP_idx)), LD_SEG_HIDDEN(instr->seg + SEG_offset, SEG_BASE_idx));
			case 3:
				assert(0 && "instr->mod specifies OPTYPE_REG with sib addressing mode!\n");
				return nullptr;
			default:
				assert(0 && "Unknown instr->mod specified with instr->base == 5\n");
				return nullptr;
			}
		default:
			assert(0 && "Unknown sib base specified\n");
			return nullptr;
		}
		return ADD(ADD(base, MUL(idx, scale)), LD_SEG_HIDDEN(instr->seg + SEG_offset, SEG_BASE_idx));
	default:
		assert(0 && "Unknown operand type specified\n");
		return nullptr;
	}
}
