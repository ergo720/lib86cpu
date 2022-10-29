/*
 * x86 llvm frontend
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#include "internal.h"
#include "frontend.h"
#include "memory.h"

#ifdef LIB86CPU_X64_EMITTER
#include "x64/jit.h"
#endif

#if 0

Value *
get_r8h_pointer(cpu_t *cpu, Value *gep_start)
{
	return GetElementPtrInst::CreateInBounds(getIntegerType(8), gep_start, CONST8(1), "", cpu->bb);
}

StructType *
get_struct_reg(cpu_t *cpu)
{
	std::vector<Type *>type_struct_reg_t_fields;
	StructType *type_struct_hiddenseg_t = StructType::create(CTX(), { getIntegerType(32) , getIntegerType(32) , getIntegerType(32) }, "struct.hiddenseg_t", false);
	StructType *type_struct_seg_t = StructType::create(CTX(), { getIntegerType(16), type_struct_hiddenseg_t }, "struct.seg_t", false);
	StructType *type_struct_fp80_t = StructType::create(CTX(), { getIntegerType(64), getIntegerType(16) }, "struct.fp80_t", true);

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
		case TR_idx:
			type_struct_reg_t_fields.push_back(type_struct_seg_t);
			break;

		case R0_idx:
		case R1_idx:
		case R2_idx:
		case R3_idx:
		case R4_idx:
		case R5_idx:
		case R6_idx:
		case R7_idx:
			type_struct_reg_t_fields.push_back(type_struct_fp80_t);
			break;

		default:
			type_struct_reg_t_fields.push_back(getIntegerType(cpu->regs_layout[n].bits_size));
		}
	}

	return StructType::create(CTX(), type_struct_reg_t_fields, "struct.regs_t", false);
}

std::vector<BasicBlock *>
gen_bbs(cpu_t *cpu, const unsigned num)
{
	Function *func = cpu->bb->getParent();
	std::vector<BasicBlock *> vec;
	for (unsigned i = 0; i < num; i++) {
		vec.push_back(BasicBlock::Create(CTX(), "", func, 0));
	}

	return vec;
}

void
optimize(cpu_t *cpu)
{
	legacy::FunctionPassManager pm = legacy::FunctionPassManager(cpu->mod);

	pm.add(createInstructionCombiningPass());
	pm.add(createDeadCodeEliminationPass());
	pm.add(createCFGSimplificationPass());
	pm.run(*cpu->bb->getParent());
}

Value *
gep_emit(cpu_t *cpu, Type *pointee_ty, Value *gep_start, const int gep_index)
{
	return GetElementPtrInst::CreateInBounds(pointee_ty, gep_start, { CONST32(0), CONST32(gep_index) }, "", cpu->bb);
}

Value *
gep_emit(cpu_t *cpu, Type *pointee_ty, Value *gep_start, Value *gep_index)
{
	return GetElementPtrInst::CreateInBounds(pointee_ty, gep_start, { CONST32(0), gep_index }, "", cpu->bb);
}

Value *
gep_seg_emit(cpu_t *cpu, const int gep_index)
{
	GetElementPtrInst *gep = GetElementPtrInst::CreateInBounds(getRegType(), cpu->ptr_regs, { CONST32(0), CONST32(gep_index) }, "", cpu->bb);
	return GetElementPtrInst::CreateInBounds(gep->getResultElementType(), gep, { CONST32(0), CONST32(SEG_SEL_idx) }, "", cpu->bb);
}

Value *
gep_seg_hidden_emit(cpu_t *cpu, const int seg_index, const int gep_index)
{
	GetElementPtrInst *gep1 = GetElementPtrInst::CreateInBounds(getRegType(), cpu->ptr_regs, { CONST32(0), CONST32(seg_index) }, "", cpu->bb);
	GetElementPtrInst *gep2 = GetElementPtrInst::CreateInBounds(gep1->getResultElementType(), gep1, { CONST32(0), CONST32(SEG_HIDDEN_idx) }, "", cpu->bb);
	return GetElementPtrInst::CreateInBounds(gep2->getResultElementType(), gep2, { CONST32(0), CONST32(gep_index) }, "", cpu->bb);
}

Value *
gep_f80_emit(cpu_t *cpu, const int gep_index, const int f80_index)
{
	GetElementPtrInst *gep = GetElementPtrInst::CreateInBounds(getRegType(), cpu->ptr_regs, { CONST32(0), CONST32(f80_index) }, "", cpu->bb);
	return GetElementPtrInst::CreateInBounds(gep->getResultElementType(), gep, { CONST32(0), CONST32(gep_index) }, "", cpu->bb);
}

Value *
calc_next_pc_emit(cpu_t *cpu, size_t instr_size)
{
	Value *next_eip = BinaryOperator::Create(Instruction::Add, cpu->instr_eip, CONST32(instr_size), "", cpu->bb);
	ST(GEP_EIP(), next_eip);
	return BinaryOperator::Create(Instruction::Add, CONST32(cpu->cpu_ctx.regs.cs_hidden.base), next_eip, "", cpu->bb);
}

Value *
floor_division_emit(cpu_t *cpu, Value *D, Value *d, size_t q_bits)
{
	std::vector<BasicBlock *> vec_bb = getBBs(3);
	Value *ret = ALLOCs(q_bits);
	Value *q = SDIV(D, d);
	Value *r = SREM(D, d);
	BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(XOR(ICMP_SGT(r, CONSTs(q_bits, 0)), ICMP_SGT(d, CONSTs(q_bits, 0))), CONSTs(1, 1)));
	cpu->bb = vec_bb[0];
	ST(ret, SUB(q, CONSTs(q_bits, 1)));
	BR_UNCOND(vec_bb[2]);
	cpu->bb = vec_bb[1];
	ST(ret, q);
	BR_UNCOND(vec_bb[2]);
	cpu->bb = vec_bb[2];
	return LD(ret, getIntegerType(q_bits));
}

void
link_ret_emit(cpu_t *cpu)
{
	// NOTE: perhaps find a way to use a return stack buffer to link to the next tc

	link_indirect_emit(cpu);
}

void
raise_exp_inline_isInt_emit(cpu_t *cpu, Value *fault_addr, Value *code, Value *idx, Value *eip)
{
	GetElementPtrInst *gep1 = GetElementPtrInst::CreateInBounds(cpu->cpu_ctx_type, cpu->ptr_cpu_ctx, { CONST32(0), CONST32(8) }, "", cpu->bb);
	GetElementPtrInst *gep2 = GetElementPtrInst::CreateInBounds(gep1->getResultElementType(), gep1, { CONST32(0), CONST32(0) }, "", cpu->bb);
	Value *ptr_exp_data = gep2;
	ST(GEP(ptr_exp_data, gep2->getResultElementType(), 0), fault_addr);
	ST(GEP(ptr_exp_data, gep2->getResultElementType(), 1), code);
	ST(GEP(ptr_exp_data, gep2->getResultElementType(), 2), idx);
	ST(GEP(ptr_exp_data, gep2->getResultElementType(), 3), eip);
	Function *exp_isInt = cast<Function>(cpu->mod->getOrInsertFunction("cpu_raise_exception_isInt", cpu->bb->getParent()->getReturnType(), cpu->ptr_cpu_ctx->getType()).getCallee());
	CallInst *ci = CALL(exp_isInt->getFunctionType(), exp_isInt, cpu->ptr_cpu_ctx);
	ReturnInst::Create(CTX(), ci, cpu->bb);
}

void
write_eflags(cpu_t *cpu, Value *eflags, Value *mask)
{
	ST_REG_idx(OR(OR(AND(LD_R32(EFLAGS_idx), NOT(mask)), AND(eflags, mask)), CONST32(2)), EFLAGS_idx);
	Value *cf_new = AND(eflags, CONST32(1));
	Value *of_new = SHL(XOR(SHR(AND(eflags, CONST32(0x800)), CONST32(11)), cf_new), CONST32(30));
	Value *sfd = SHR(AND(eflags, CONST32(128)), CONST32(7));
	Value *pdb = SHL(XOR(CONST32(4), AND(eflags, CONST32(4))), CONST32(6));
	ST_FLG_RES(SHL(XOR(AND(eflags, CONST32(64)), CONST32(64)), CONST32(2)));
	ST_FLG_AUX(OR(OR(OR(OR(SHL(cf_new, CONST32(31)), SHR(AND(eflags, CONST32(16)), CONST32(1))), of_new), sfd), pdb));
}

Value *
mem_read_emit(cpu_t *cpu, Value *addr, const unsigned idx, const unsigned is_priv)
{
	return CALL(cpu->ptr_mem_ldfn[idx]->getFunctionType(), cpu->ptr_mem_ldfn[idx], cpu->ptr_cpu_ctx, addr, cpu->instr_eip, CONST8(is_priv));
}

void
mem_write_emit(cpu_t *cpu, Value *addr, Value *value, const unsigned idx, const unsigned is_priv)
{
	CALL(cpu->ptr_mem_stfn[idx]->getFunctionType(), cpu->ptr_mem_stfn[idx], cpu->ptr_cpu_ctx, addr, value, cpu->instr_eip, CONST8(is_priv));
}

void
stack_push_emit(cpu_t *cpu, const std::vector<Value *> &vec, uint32_t size_mode)
{
	assert(size_mode != SIZE8);
	assert(vec.size() != 0);

	switch ((size_mode << 1) | ((cpu->cpu_ctx.hflags & HFLG_SS32) >> SS32_SHIFT))
	{
	case 0: { // sp, push 32
		Value *sp = LD_R16(ESP_idx);
		for (auto &val : vec) {
			sp = SUB(sp, CONST16(4));
			ST_MEM(MEM_ST32_idx, ADD(ZEXT32(sp), LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)), val);
		}
		ST_REG_idx(sp, ESP_idx);
	}
	break;

	case 1: { // esp, push 32
		Value *esp = LD_R32(ESP_idx);
		for (auto &val : vec) {
			esp = SUB(esp, CONST32(4));
			ST_MEM(MEM_ST32_idx, ADD(esp, LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)), val);
		}
		ST_REG_idx(esp, ESP_idx);
	}
	break;

	case 2: { // sp, push 16
		Value *sp = LD_R16(ESP_idx);
		for (auto &val : vec) {
			sp = SUB(sp, CONST16(2));
			ST_MEM(MEM_ST16_idx, ADD(ZEXT32(sp), LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)), val);
		}
		ST_REG_idx(sp, ESP_idx);
	}
	break;

	case 3: { // esp, push 16
		Value *esp = LD_R32(ESP_idx);
		for (auto &val : vec) {
			esp = SUB(esp, CONST32(2));
			ST_MEM(MEM_ST16_idx, ADD(esp, LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)), val);
		}
		ST_REG_idx(esp, ESP_idx);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

std::vector<Value *>
stack_pop_emit(cpu_t *cpu, uint32_t size_mode, const unsigned num, const unsigned pop_at)
{
	assert(size_mode != SIZE8);
	std::vector<Value *> vec;

	switch ((size_mode << 1) | ((cpu->cpu_ctx.hflags & HFLG_SS32) >> SS32_SHIFT))
	{
	case 0: { // sp, pop 32
		Value *sp = ADD(LD_R16(ESP_idx), MUL(CONST16(pop_at), CONST16(4)));
		for (unsigned i = 0; i < num; i++) {
			vec.push_back(LD_MEM(MEM_LD32_idx, ADD(ZEXT32(sp), LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx))));
			sp = ADD(sp, CONST16(4));
		}
		vec.push_back(sp);
		vec.push_back(GEP_REG_idx(ESP_idx));
	}
	break;

	case 1: { // esp, pop 32
		Value *esp = ADD(LD_R32(ESP_idx), MUL(CONST32(pop_at), CONST32(4)));
		for (unsigned i = 0; i < num; i++) {
			vec.push_back(LD_MEM(MEM_LD32_idx, ADD(esp, LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx))));
			esp = ADD(esp, CONST32(4));
		}
		vec.push_back(esp);
		vec.push_back(GEP_REG_idx(ESP_idx));
	}
	break;

	case 2: { // sp, pop 16
		Value *sp = ADD(LD_R16(ESP_idx), MUL(CONST16(pop_at), CONST16(2)));
		for (unsigned i = 0; i < num; i++) {
			vec.push_back(LD_MEM(MEM_LD16_idx, ADD(ZEXT32(sp), LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx))));
			sp = ADD(sp, CONST16(2));
		}
		vec.push_back(sp);
		vec.push_back(GEP_REG_idx(ESP_idx));
	}
	break;

	case 3: { // esp, pop 16
		Value *esp = ADD(LD_R32(ESP_idx), MUL(CONST32(pop_at), CONST32(2)));
		for (unsigned i = 0; i < num; i++) {
			vec.push_back(LD_MEM(MEM_LD16_idx, ADD(esp, LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx))));
			esp = ADD(esp, CONST32(2));
		}
		vec.push_back(esp);
		vec.push_back(GEP_REG_idx(ESP_idx));
	}
	break;

	default:
		LIB86CPU_ABORT();
	}

	return vec;
}

void
update_fpu_state_after_mmx_emit(cpu_t *cpu, int idx, Value *tag, bool is_write)
{
	if (is_write) {
		ST_MM_HIGH(CONST16(0xFFFF), idx);
	}
	ST_REG_idx(tag, TAG_idx);
	ST_REG_idx(AND(LD_R16(ST_idx), CONST16(~ST_TOP_MASK)), ST_idx);
}

int
get_seg_prfx_idx(ZydisDecodedInstruction *instr)
{
	// This is to be used for instructions that have hidden operands, for which zydis does not guarantee
	// their position in the operand array

	if (!(instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT)) {
		return DS_idx;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_CS) {
		return CS_idx;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_SS) {
		return SS_idx;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_DS) {
		return DS_idx;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_ES) {
		return ES_idx;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_FS) {
		return FS_idx;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_GS) {
		return GS_idx;
	}
	else {
		LIB86CPU_ABORT();
	}
}

void
hook_emit(cpu_t *cpu, hook *obj)
{
	std::vector<Type *> args_t;
	std::vector<Value *> args_val;
	for (unsigned i = 0; i < obj->args_t.size(); ++i) {
		switch (obj->args_t[i])
		{
		case arg_types::i8:
			args_t.push_back(getIntegerType(8));
			args_val.push_back(CONST8(obj->args_val[i]));
			break;

		case arg_types::i16:
			args_t.push_back(getIntegerType(16));
			args_val.push_back(CONST16(obj->args_val[i]));
			break;

		case arg_types::i32:
			args_t.push_back(getIntegerType(32));
			args_val.push_back(CONST32(obj->args_val[i]));
			break;

		case arg_types::i64:
			args_t.push_back(getIntegerType(64));
			args_val.push_back(CONST64(obj->args_val[i]));
			break;

		case arg_types::ptr:
			args_t.push_back(getPointerType());
			args_val.push_back(INT2PTR(args_t[i], CONSTs(cpu->dl->getPointerSize() * 8, obj->args_val[i])));
			break;

		default:
			LIB86CPU_ABORT_msg("Unknown hook argument type specified");
		}
	}

	Function *hook = Function::Create(FunctionType::get(getVoidType(), ArrayRef<Type *> { args_t }, false),
		GlobalValue::ExternalLinkage, obj->name, cpu->mod);
	cpu->jit->define_absolute(cpu->jit->mangle(hook), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(obj->addr),
		JITSymbolFlags::Absolute | JITSymbolFlags::Exported));
	CALL(hook->getFunctionType(), hook, args_val);

	// NOTE: hooks don't execute any guest instr, so we don't clear rf here

	check_int_emit(cpu);
}
#endif
