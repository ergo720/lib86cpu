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
#include "llvm/IR/Intrinsics.h"
#include "llvm/LinkAllPasses.h"
#include "llvm/IR/Verifier.h"
#include "jit.h"
#include "internal.h"
#include "frontend.h"
#include "memory.h"


Value *
get_r8h_pointer(cpu_t *cpu, Value *gep_start)
{
	std::vector<Value *> ptr_11_indices;
	ptr_11_indices.push_back(CONST8(1));
	return GetElementPtrInst::CreateInBounds(getIntegerType(8) , gep_start, ptr_11_indices, "", cpu->bb);
}

StructType *
get_struct_reg(cpu_t *cpu)
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
		case TR_idx:
			type_struct_reg_t_fields.push_back(type_struct_seg_t);
			break;

		default:
			type_struct_reg_t_fields.push_back(getIntegerType(cpu->regs_layout[n].bits_size));
		}
	}

	return StructType::create(CTX(), type_struct_reg_t_fields, "struct.regs_t", false);
}

StructType *
get_struct_eflags(cpu_t *cpu)
{
	std::vector<Type *>type_struct_eflags_t_fields;

	type_struct_eflags_t_fields.push_back(getIntegerType(32));
	type_struct_eflags_t_fields.push_back(getIntegerType(32));
	type_struct_eflags_t_fields.push_back(getArrayType(getIntegerType(8), 256));

	return StructType::create(CTX(), type_struct_eflags_t_fields, "struct.eflags_t", false);
}

std::vector<BasicBlock *>
gen_bbs(cpu_t *cpu, Function *func, const unsigned num)
{
	std::vector<BasicBlock *> vec;
	for (unsigned i = 0; i < num; i++) {
		vec.push_back(BB());
	}

	return vec;
}

void
optimize(cpu_t *cpu)
{
	legacy::FunctionPassManager pm = legacy::FunctionPassManager(cpu->mod);

	pm.add(createPromoteMemoryToRegisterPass());
	pm.add(createInstructionCombiningPass());
	pm.add(createConstantPropagationPass());
	pm.add(createDeadStoreEliminationPass());
	pm.add(createDeadCodeEliminationPass());
	pm.run(*cpu->bb->getParent());
}

void
get_ext_fn(cpu_t *cpu)
{
	static size_t bit_size[7] = { 8, 16, 32, 64, 8, 16, 32 };
	static const char *func_name_ld[7] = { "mem_read8", "mem_read16", "mem_read32", "mem_read64", "io_read8", "io_read16", "io_read32" };
	static const char *func_name_st[7] = { "mem_write8", "mem_write16", "mem_write32", "mem_write64", "io_write8", "io_write16", "io_write32" };
	Type *cpu_ctx_ty = cpu->bb->getParent()->arg_begin()->getType();
	Type *tc_ty = cpu->bb->getParent()->getReturnType();

	for (uint8_t i = 0; i < 4; i++) {
		cpu->ptr_mem_ldfn[i] = cast<Function>(cpu->mod->getOrInsertFunction(func_name_ld[i], getIntegerType(bit_size[i]), cpu_ctx_ty,
			getIntegerType(32), getIntegerType(32), getIntegerType(8)));
	}
	for (uint8_t i = 4; i < 7; i++) {
		cpu->ptr_mem_ldfn[i] = cast<Function>(cpu->mod->getOrInsertFunction(func_name_ld[i], getIntegerType(bit_size[i]), cpu_ctx_ty,
			getIntegerType(16)));
	}

	for (uint8_t i = 0; i < 4; i++) {
		cpu->ptr_mem_stfn[i] = cast<Function>(cpu->mod->getOrInsertFunction(func_name_st[i], getVoidType(), cpu_ctx_ty,
			getIntegerType(32), getIntegerType(bit_size[i]), getIntegerType(32), getIntegerType(8), tc_ty));
	}
	for (uint8_t i = 4; i < 7; i++) {
		cpu->ptr_mem_stfn[i] = cast<Function>(cpu->mod->getOrInsertFunction(func_name_st[i], getVoidType(), cpu_ctx_ty,
			getIntegerType(16), getIntegerType(bit_size[i])));
	}

	cpu->ptr_invtc_fn = cast<Function>(cpu->mod->getOrInsertFunction("tc_invalidate", getIntegerType(8), cpu_ctx_ty,
		tc_ty, getIntegerType(32), getIntegerType(8)));
}

Value *
gep_emit(cpu_t *cpu, Value *gep_start, const int gep_index)
{
	return gep_emit(cpu, gep_start, std::vector<Value *> { CONST32(0), CONST32(gep_index) });
}

Value *
gep_emit(cpu_t *cpu, Value *gep_start, Value *gep_index)
{
	return gep_emit(cpu, gep_start, std::vector<Value *> { CONST32(0), gep_index });
}

Value *
gep_emit(cpu_t *cpu, Value *gep_start, std::vector<Value *> &vec_index)
{
	return GetElementPtrInst::CreateInBounds(gep_start, vec_index, "", cpu->bb);
}

Value *
calc_next_pc_emit(cpu_t *cpu, size_t instr_size)
{
	Value *next_eip = BinaryOperator::Create(Instruction::Add, cpu->instr_eip, CONST32(instr_size), "", cpu->bb);
	ST(GEP_EIP(), next_eip);
	return BinaryOperator::Create(Instruction::Add, CONST32(cpu->cpu_ctx.regs.cs_hidden.base), next_eip, "", cpu->bb);
}

void
link_direct_emit(cpu_t *cpu, std::vector<addr_t> &vec_addr, Value *target_addr)
{
	// vec_addr: instr_pc, dst_pc, next_pc

	addr_t page_addr = vec_addr[0] & ~PAGE_MASK;
	uint32_t n, dst = (vec_addr[1] & ~PAGE_MASK) == page_addr;
	if (vec_addr.size() == 3) {
		n = dst + ((vec_addr[2] & ~PAGE_MASK) == page_addr);
	}
	else {
		assert(vec_addr.size() == 2);
		n = dst;
	}
	cpu->tc->tc_ctx.flags |= (n & TC_FLG_NUM_JMP);

	if (n == 0) {
		return;
	}

	std::vector<Type *> type_struct_tc_t_fields;
	type_struct_tc_t_fields.push_back(getIntegerType(32));
	type_struct_tc_t_fields.push_back(getIntegerType(32));
	type_struct_tc_t_fields.push_back(getIntegerType(32));
	type_struct_tc_t_fields.push_back(getPointerType(cpu->bb->getParent()->getFunctionType()));
	type_struct_tc_t_fields.push_back(getArrayType(getPointerType(cpu->bb->getParent()->getFunctionType()), 3));
	type_struct_tc_t_fields.push_back(getIntegerType(32));
	type_struct_tc_t_fields.push_back(getIntegerType(32));
	PointerType *tc_pstruct_type = getPointerType(StructType::create(CTX(), type_struct_tc_t_fields, "struct.tc_ctx_t", false));

	// NOTE: WHY??? Trying to use GEP to calculate the struct member offsets from the tc base address only works if optimizations are turned off. Unfortunately, after enabling the transform passes,
	// the generated code seems to assume that the function pointer members of the tc struct are 8 bytes large, instead of 4 (their real size), thus causing GEP to calculate wrong addresses,
	// and the generated code will then perform out of bounds memory accesses at runtime. As a workaround, we calculate the addresses ourselves and inject them in the IR as constant pointers.
	Value *tc_jmp0_ptr = ConstantExpr::getIntToPtr(INTPTR(&cpu->tc->tc_ctx.jmp_offset[0]), getPointerType(tc_pstruct_type->getElementType()->getStructElementType(3)));
	Value *tc_jmp1_ptr = ConstantExpr::getIntToPtr(INTPTR(&cpu->tc->tc_ctx.jmp_offset[1]), getPointerType(tc_pstruct_type->getElementType()->getStructElementType(3)));
	Value *tc_flg_ptr = ConstantExpr::getIntToPtr(INTPTR(&cpu->tc->tc_ctx.flags), getPointerType(tc_pstruct_type->getElementType()->getStructElementType(5)));

	switch (n)
	{
	case 1: {
		if (vec_addr.size() == 3) { // if(dst_pc) -> cond jmp dst_pc; if(next_pc) -> cond jmp next_pc
			if (dst) {
				std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, cpu->bb->getParent(), 2);
				BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(target_addr, CONST32(vec_addr[1])));
				cpu->bb = vec_bb[0];
				ST(tc_flg_ptr, AND(LD(tc_flg_ptr), CONST32(~TC_FLG_JMP_TAKEN)));
				CallInst *ci = CallInst::Create(LD(tc_jmp0_ptr), std::vector<Value *> { cpu->ptr_cpu_ctx }, "", cpu->bb);
				ci->setCallingConv(CallingConv::C);
				ci->setTailCallKind(CallInst::TailCallKind::TCK_Tail);
				ReturnInst::Create(CTX(), ci, cpu->bb);
				cpu->bb = vec_bb[1];
				ST(tc_flg_ptr, OR(AND(LD(tc_flg_ptr), CONST32(~TC_FLG_JMP_TAKEN)), CONST32(TC_FLG_RET << 4)));
			}
			else {
				std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, cpu->bb->getParent(), 2);
				BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(target_addr, CONST32(vec_addr[2])));
				cpu->bb = vec_bb[0];
				ST(tc_flg_ptr, OR(AND(LD(tc_flg_ptr), CONST32(~TC_FLG_JMP_TAKEN)), CONST32(TC_FLG_NEXT_PC << 4)));
				CallInst *ci = CallInst::Create(LD(tc_jmp1_ptr), std::vector<Value *> { cpu->ptr_cpu_ctx }, "", cpu->bb);
				ci->setCallingConv(CallingConv::C);
				ci->setTailCallKind(CallInst::TailCallKind::TCK_Tail);
				ReturnInst::Create(CTX(), ci, cpu->bb);
				cpu->bb = vec_bb[1];
				ST(tc_flg_ptr, OR(AND(LD(tc_flg_ptr), CONST32(~TC_FLG_JMP_TAKEN)), CONST32(TC_FLG_RET << 4)));
			}
		}
		else { // uncond jmp dst_pc
			CallInst *ci = CallInst::Create(LD(tc_jmp0_ptr), std::vector<Value *> { cpu->ptr_cpu_ctx }, "", cpu->bb);
			ci->setCallingConv(CallingConv::C);
			ci->setTailCallKind(CallInst::TailCallKind::TCK_Tail);
			ReturnInst::Create(CTX(), ci, cpu->bb);
			cpu->bb = BasicBlock::Create(CTX(), "", cpu->bb->getParent(), 0);
			INTRINSIC(trap);
		}
	}
	break;

	case 2: { // cond jmp next_pc + uncond jmp dst_pc
		std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, cpu->bb->getParent(), 3);
		BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(target_addr, CONST32(vec_addr[2])));
		cpu->bb = vec_bb[0];
		ST(tc_flg_ptr, OR(AND(LD(tc_flg_ptr), CONST32(~TC_FLG_JMP_TAKEN)), CONST32(TC_FLG_NEXT_PC << 4)));
		CallInst *ci1 = CallInst::Create(LD(tc_jmp1_ptr), std::vector<Value *> { cpu->ptr_cpu_ctx }, "", cpu->bb);
		ci1->setCallingConv(CallingConv::C);
		ci1->setTailCallKind(CallInst::TailCallKind::TCK_Tail);
		ReturnInst::Create(CTX(), ci1, cpu->bb);
		cpu->bb = vec_bb[1];
		ST(tc_flg_ptr, AND(LD(tc_flg_ptr), CONST32(~TC_FLG_JMP_TAKEN)));
		CallInst *ci2 = CallInst::Create(LD(tc_jmp0_ptr), std::vector<Value *> { cpu->ptr_cpu_ctx }, "", cpu->bb);
		ci2->setCallingConv(CallingConv::C);
		ci2->setTailCallKind(CallInst::TailCallKind::TCK_Tail);
		ReturnInst::Create(CTX(), ci2, cpu->bb);
		cpu->bb = vec_bb[2];
		INTRINSIC(trap);
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
gen_exp_fn(cpu_t *cpu)
{
	cpu->ctx = new LLVMContext();
	if (cpu->ctx == nullptr) {
		LIB86CPU_ABORT();
	}
	cpu->mod = new Module(cpu->cpu_name, *cpu->ctx);
	cpu->mod->setDataLayout(*cpu->dl);
	if (cpu->mod == nullptr) {
		LIB86CPU_ABORT();
	}

	StructType *cpu_ctx_struct_type = StructType::create(CTX(), "struct.cpu_ctx_t");
	std::vector<Type *> type_struct_exp_data_t_fields;
	type_struct_exp_data_t_fields.push_back(getIntegerType(32));
	type_struct_exp_data_t_fields.push_back(getIntegerType(16));
	type_struct_exp_data_t_fields.push_back(getIntegerType(16));
	type_struct_exp_data_t_fields.push_back(getIntegerType(32));
	StructType *type_exp_data_t = StructType::create(CTX(),
		type_struct_exp_data_t_fields, "struct.exp_data_t", false);

	StructType *tc_struct_type = StructType::create(CTX(), "struct.tc_t");  // NOTE: opaque tc struct
	FunctionType *type_exp_t = FunctionType::get(
		getPointerType(tc_struct_type),                                                                // tc ret
		std::vector<Type *> { getPointerType(cpu_ctx_struct_type), getPointerType(type_exp_data_t) },  // cpu_ctx, exp_data arg
		false);

	std::vector<Type *> type_struct_exp_info_t_fields;
	type_struct_exp_info_t_fields.push_back(type_exp_data_t);
	type_struct_exp_info_t_fields.push_back(getIntegerType(8));
	StructType *type_exp_info_t = StructType::create(CTX(),
		type_struct_exp_info_t_fields, "struct.exp_info_t", false);

	std::vector<Type *> type_struct_cpu_ctx_t_fields;
	type_struct_cpu_ctx_t_fields.push_back(getPointerType(StructType::create(CTX(), "struct.cpu_t")));  // NOTE: opaque cpu struct
	type_struct_cpu_ctx_t_fields.push_back(get_struct_reg(cpu));
	type_struct_cpu_ctx_t_fields.push_back(get_struct_eflags(cpu));
	type_struct_cpu_ctx_t_fields.push_back(getIntegerType(32));
	type_struct_cpu_ctx_t_fields.push_back(getArrayType(getIntegerType(32), TLB_MAX_SIZE));
	type_struct_cpu_ctx_t_fields.push_back(getPointerType(getIntegerType(8)));
	type_struct_cpu_ctx_t_fields.push_back(getPointerType(type_exp_t));
	type_struct_cpu_ctx_t_fields.push_back(getPointerType(type_exp_info_t));
	cpu_ctx_struct_type->setBody(type_struct_cpu_ctx_t_fields, false);

	Function *func = Function::Create(
		type_exp_t,                      // func type
		GlobalValue::ExternalLinkage,    // linkage
		"cpu_raise_exception",           // name
		cpu->mod);
	func->setCallingConv(CallingConv::C);

	cpu->bb = BB();
	cpu->tc = nullptr;
	cpu->instr_eip = CONST32(0);
	Function::arg_iterator args = func->arg_begin();
	cpu->ptr_cpu_ctx = args++;
	cpu->ptr_cpu_ctx->setName("cpu_ctx");
	cpu->ptr_regs = GEP(cpu->ptr_cpu_ctx, 1);
	cpu->ptr_regs->setName("regs");
	cpu->ptr_eflags = GEP(cpu->ptr_cpu_ctx, 2);
	cpu->ptr_eflags->setName("eflags");
	cpu->ptr_hflags = GEP(cpu->ptr_cpu_ctx, 3);
	cpu->ptr_hflags->setName("hflags");
	cpu->ptr_tlb = GEP(cpu->ptr_cpu_ctx, 4);
	cpu->ptr_tlb->setName("tlb");
	cpu->ptr_ram = LD(GEP(cpu->ptr_cpu_ctx, 5));
	cpu->ptr_ram->setName("ram");
	cpu->ptr_exp_fn = LD(GEP(cpu->ptr_cpu_ctx, 6));
	cpu->ptr_exp_fn->setName("exp_fn");
	Value *ptr_exp_info = LD(GEP(cpu->ptr_cpu_ctx, 7));
	ptr_exp_info->setName("exp_info");

	get_ext_fn(cpu);
	Value *exp_data = args++;
	BasicBlock *bb_exp_in_flight = BB();
	BasicBlock *bb_next = BB();
	BR_COND(bb_exp_in_flight, bb_next, ICMP_NE(LD(GEP(ptr_exp_info, 1)), CONST8(0)));
	cpu->bb = bb_exp_in_flight;
	// we don't handle double and triple faults yet, so just abort
	INTRINSIC(trap);
	UNREACH();
	cpu->bb = bb_next;
	ST(GEP(ptr_exp_info, 1), CONST8(1));
	Value *fault_addr = LD(GEP(exp_data, 0));
	Value *code = ZEXT32(LD(GEP(exp_data, 1)));
	Value *idx = ZEXT32(LD(GEP(exp_data, 2)));
	Value *eip = LD(GEP(exp_data, 3));
	ST(GEP(GEP(ptr_exp_info, 0), 0), fault_addr);
	ST(GEP(GEP(ptr_exp_info, 0), 1), TRUNC16(code));
	ST(GEP(GEP(ptr_exp_info, 0), 2), TRUNC16(idx));
	ST(GEP(GEP(ptr_exp_info, 0), 3), eip);

	Value *old_eflags = OR(OR(OR(OR(OR(OR(LD_R32(EFLAGS_idx),
		SHR(LD_CF(), CONST32(31))),
		SHL(XOR(ZEXT32(LD_PF()), CONST32(1)), CONST32(2))),
		SHL(LD_AF(), CONST32(1))),
		SHL(LD_ZF(), CONST32(6))),
		SHL(LD_SF(), CONST32(7))),
		SHR(LD_OF(), CONST32(20))
		);

	if (cpu->cpu_ctx.hflags & HFLG_PE_MODE) {
		std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, func, 39);

		Value *cpl = TRUNC16(AND(LD(cpu->ptr_hflags), CONST32(HFLG_CPL)));
		BR_COND(vec_bb[0], vec_bb[1], ICMP_UGT(ADD(MUL(idx, CONST32(8)), CONST32(7)), LD_SEG_HIDDEN(IDTR_idx, SEG_LIMIT_idx)));
		cpu->bb = vec_bb[1];
		Value *desc = ALLOC64();
		Value *temp = LD_MEM_PRIV(MEM_LD64_idx, ADD(LD_SEG_HIDDEN(IDTR_idx, SEG_BASE_idx), MUL(idx, CONST32(8))));
		ST(desc, temp);
		Value *type = ALLOC16();
		ST(type, TRUNC16(AND(SHR(LD(desc), CONST64(40)), CONST64(0x1F))));
		Value *new_eip = ALLOC32();
		Value *eflags = ALLOC32();
		SwitchInst *swi = SWITCH_new(5, LD(type), vec_bb[0]);
		swi->SWITCH_add(16, 5, vec_bb[0]);  // we don't support task gates yet, so just abort
		swi->SWITCH_add(16, 6, vec_bb[2]);  // interrupt gate, 16 bit
		swi->SWITCH_add(16, 14, vec_bb[2]); // interrupt gate, 32 bit
		swi->SWITCH_add(16, 7, vec_bb[3]);  // trap gate, 16 bit
		swi->SWITCH_add(16, 15, vec_bb[3]); // trap gate, 32 bit
		cpu->bb = vec_bb[2];
		ST(eflags, AND(LD_R32(EFLAGS_idx), CONST32(~IF_MASK)));
		ST(new_eip, TRUNC32(OR(SHR(AND(LD(desc), CONST64(0xFFFF000000000000)), CONST64(32)), AND(LD(desc), CONST64(0xFFFF)))));
		BR_UNCOND(vec_bb[4]);
		cpu->bb = vec_bb[3];
		ST(eflags, LD_R32(EFLAGS_idx));
		ST(new_eip, TRUNC32(OR(SHR(AND(LD(desc), CONST64(0xFFFF000000000000)), CONST64(32)), AND(LD(desc), CONST64(0xFFFF)))));
		BR_UNCOND(vec_bb[4]);
		cpu->bb = vec_bb[4];
		BR_COND(vec_bb[0], vec_bb[5], ICMP_EQ(AND(LD(desc), CONST64(SEG_DESC_P)), CONST64(0)));
		cpu->bb = vec_bb[5];
		Value *sel = TRUNC16(SHR(AND(LD(desc), CONST64(0xFFFF0000)), CONST64(16)));
		BR_COND(vec_bb[0], vec_bb[6], ICMP_EQ(AND(LD(desc), CONST64(0xFFFC)), CONST64(0)));
		cpu->bb = vec_bb[6];
		std::vector<Value *> vec = read_seg_desc_emit(cpu, sel, vec_bb[0]);
		Value *desc_addr = ALLOC32();
		ST(desc_addr, vec[0]);
		ST(desc, vec[1]);
		Value *dpl = ALLOC16();
		ST(dpl, TRUNC16(SHR(AND(LD(desc), CONST64(SEG_DESC_DPL)), CONST64(45))));
		// NOTE: can't inject cpl as a constant here or we would have to regenerate this function every time the cpl changes, which we don't want
		BR_COND(vec_bb[0], vec_bb[7], ICMP_UGT(LD(dpl), cpl));
		cpu->bb = vec_bb[7];
		BR_COND(vec_bb[0], vec_bb[8], ICMP_EQ(AND(LD(desc), CONST64(SEG_DESC_P)), CONST64(0)));
		cpu->bb = vec_bb[8];
		BR_COND(vec_bb[9], vec_bb[10], ICMP_NE(AND(LD(desc), CONST64(SEG_DESC_C)), CONST64(0)));
		cpu->bb = vec_bb[9];
		ST(dpl, cpl);
		BR_UNCOND(vec_bb[10]);
		cpu->bb = vec_bb[10];
		set_access_flg_seg_desc_emit(cpu, LD(desc), LD(desc_addr));
		Value *seg_base = read_seg_desc_base_emit(cpu, LD(desc));
		Value *seg_limit = read_seg_desc_limit_emit(cpu, LD(desc));
		Value *seg_flags = read_seg_desc_flags_emit(cpu, LD(desc));
		Value *stack_switch = ALLOCs(1);
		Value *stack_mask = ALLOC32();
		Value *stack_base = ALLOC32();
		Value *esp = ALLOC32();
		Value *new_esp = ALLOC32();
		Value *new_ss = ALLOC16();
		BR_COND(vec_bb[11], vec_bb[12], ICMP_ULT(LD(dpl), cpl));
		// more privileged
		cpu->bb = vec_bb[11];
		vec = read_stack_ptr_from_tss_emit(cpu, cpl, vec_bb[0]);
		ST(new_esp, vec[0]);
		ST(new_ss, vec[1]);
		BR_COND(vec_bb[0], vec_bb[13], ICMP_EQ(SHR(LD(new_ss), CONST16(2)), CONST16(0)));
		cpu->bb = vec_bb[13];
		vec = read_seg_desc_emit(cpu, LD(new_ss), vec_bb[0]);
		ST(desc_addr, vec[0]);
		ST(desc, vec[1]);
		check_ss_desc_priv_emit(cpu, LD(new_ss), nullptr, cpl, vec_bb[0]);
		set_access_flg_seg_desc_emit(cpu, LD(desc), LD(desc_addr));
		ST(stack_switch, CONSTs(1, 1));
		BR_COND(vec_bb[14], vec_bb[15], ICMP_NE(AND(LD(desc), CONST64(SEG_DESC_DB)), CONST64(0)));
		cpu->bb = vec_bb[14];
		ST(stack_mask, CONST32(0xFFFFFFFF));
		BR_UNCOND(vec_bb[16]);
		cpu->bb = vec_bb[15];
		ST(stack_mask, CONST32(0xFFFF));
		BR_UNCOND(vec_bb[16]);
		cpu->bb = vec_bb[16];
		ST(stack_base, read_seg_desc_base_emit(cpu, LD(desc)));
		ST(esp, LD(new_esp));
		BR_UNCOND(vec_bb[17]);
		// same privilege
		cpu->bb = vec_bb[12];
		ST(stack_switch, CONSTs(1, 0));
		BR_COND(vec_bb[18], vec_bb[19], ICMP_NE(AND(LD_SEG_HIDDEN(SS_idx, SEG_FLG_idx), CONST32(SEG_HIDDEN_DB)), CONST32(0)));
		cpu->bb = vec_bb[18];
		ST(stack_mask, CONST32(0xFFFFFFFF));
		BR_UNCOND(vec_bb[20]);
		cpu->bb = vec_bb[19];
		ST(stack_mask, CONST32(0xFFFF));
		BR_UNCOND(vec_bb[20]);
		cpu->bb = vec_bb[20];
		ST(stack_base, LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx));
		ST(esp, LD_R32(ESP_idx));
		BR_UNCOND(vec_bb[17]);
		cpu->bb = vec_bb[17];
		Value *has_code = ALLOCs(1);
		SwitchInst *swi2 = SWITCH_new(7, idx, vec_bb[21]);
		swi2->SWITCH_add(32, EXP_DF, vec_bb[22]);
		swi2->SWITCH_add(32, EXP_TS, vec_bb[22]);
		swi2->SWITCH_add(32, EXP_NP, vec_bb[22]);
		swi2->SWITCH_add(32, EXP_SS, vec_bb[22]);
		swi2->SWITCH_add(32, EXP_GP, vec_bb[22]);
		swi2->SWITCH_add(32, EXP_PF, vec_bb[22]);
		swi2->SWITCH_add(32, EXP_AC, vec_bb[22]);
		cpu->bb = vec_bb[21];
		ST(has_code, CONSTs(1, 0));
		BR_UNCOND(vec_bb[23]);
		cpu->bb = vec_bb[22];
		ST(has_code, CONSTs(1, 1));
		BR_UNCOND(vec_bb[23]);
		cpu->bb = vec_bb[23];
		ST(type, SHR(LD(type), CONST16(3)));
		BR_COND(vec_bb[24], vec_bb[25], LD(stack_switch));
		cpu->bb = vec_bb[24];
		BR_COND(vec_bb[26], vec_bb[27], ICMP_NE(LD(type), CONST16(0)));
		// push 32, priv
		cpu->bb = vec_bb[26];
		ST(esp, SUB(LD(esp), CONST32(4)));
		ST_MEM_PRIV(MEM_ST32_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), ZEXT32(LD_SEG(SS_idx)));
		ST(esp, SUB(LD(esp), CONST32(4)));
		ST_MEM_PRIV(MEM_ST32_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), LD_R32(ESP_idx));
		ST(esp, SUB(LD(esp), CONST32(4)));
		ST_MEM_PRIV(MEM_ST32_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), old_eflags);
		ST(esp, SUB(LD(esp), CONST32(4)));
		ST_MEM_PRIV(MEM_ST32_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), ZEXT32(LD_SEG(CS_idx)));
		ST(esp, SUB(LD(esp), CONST32(4)));
		ST_MEM_PRIV(MEM_ST32_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), eip);
		BR_COND(vec_bb[28], vec_bb[29], LD(has_code));
		cpu->bb = vec_bb[28];
		ST(esp, SUB(LD(esp), CONST32(4)));
		ST_MEM_PRIV(MEM_ST32_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), code);
		BR_UNCOND(vec_bb[29]);
		// push 16, priv
		cpu->bb = vec_bb[27];
		ST(esp, SUB(LD(esp), CONST32(2)));
		ST_MEM_PRIV(MEM_ST16_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), LD_SEG(SS_idx));
		ST(esp, SUB(LD(esp), CONST32(2)));
		ST_MEM_PRIV(MEM_ST16_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), LD_R16(ESP_idx));
		ST(esp, SUB(LD(esp), CONST32(2)));
		ST_MEM_PRIV(MEM_ST16_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), TRUNC16(old_eflags));
		ST(esp, SUB(LD(esp), CONST32(2)));
		ST_MEM_PRIV(MEM_ST16_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), LD_SEG(CS_idx));
		ST(esp, SUB(LD(esp), CONST32(2)));
		ST_MEM_PRIV(MEM_ST16_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), TRUNC16(eip));
		BR_COND(vec_bb[30], vec_bb[29], LD(has_code));
		cpu->bb = vec_bb[30];
		ST(esp, SUB(LD(esp), CONST32(2)));
		ST_MEM_PRIV(MEM_ST16_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), TRUNC16(code));
		BR_UNCOND(vec_bb[29]);
		cpu->bb = vec_bb[25];
		BR_COND(vec_bb[31], vec_bb[32], ICMP_NE(LD(type), CONST16(0)));
		cpu->bb = vec_bb[31];
		// push 32, not priv
		ST(esp, SUB(LD(esp), CONST32(4)));
		ST_MEM(MEM_ST32_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), old_eflags);
		ST(esp, SUB(LD(esp), CONST32(4)));
		ST_MEM(MEM_ST32_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), ZEXT32(LD_SEG(CS_idx)));
		ST(esp, SUB(LD(esp), CONST32(4)));
		ST_MEM(MEM_ST32_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), eip);
		BR_COND(vec_bb[33], vec_bb[29], LD(has_code));
		cpu->bb = vec_bb[33];
		ST(esp, SUB(LD(esp), CONST32(4)));
		ST_MEM(MEM_ST32_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), code);
		BR_UNCOND(vec_bb[29]);
		// push 16, not priv
		cpu->bb = vec_bb[32];
		ST(esp, SUB(LD(esp), CONST32(2)));
		ST_MEM(MEM_ST16_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), TRUNC16(old_eflags));
		ST(esp, SUB(LD(esp), CONST32(2)));
		ST_MEM(MEM_ST16_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), LD_SEG(CS_idx));
		ST(esp, SUB(LD(esp), CONST32(2)));
		ST_MEM(MEM_ST16_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), TRUNC16(eip));
		BR_COND(vec_bb[34], vec_bb[29], LD(has_code));
		cpu->bb = vec_bb[34];
		ST(esp, SUB(LD(esp), CONST32(2)));
		ST_MEM(MEM_ST16_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), TRUNC16(code));
		BR_UNCOND(vec_bb[29]);
		cpu->bb = vec_bb[29];
		BR_COND(vec_bb[35], vec_bb[36], LD(stack_switch));
		cpu->bb = vec_bb[35];
		Value *flags = read_seg_desc_flags_emit(cpu, LD(desc));
		Value *limit = read_seg_desc_limit_emit(cpu, LD(desc));
		ST_SEG(OR(AND(LD(new_ss), CONST16(~3)), LD(dpl)), SS_idx);
		ST_SEG_HIDDEN(LD(stack_base), SS_idx, SEG_BASE_idx);
		ST_SEG_HIDDEN(limit, SS_idx, SEG_LIMIT_idx);
		ST_SEG_HIDDEN(flags, SS_idx, SEG_FLG_idx);
		ST(cpu->ptr_hflags, OR(SHR(AND(flags, CONST32(SEG_HIDDEN_DB)), CONST32(19)), AND(LD(cpu->ptr_hflags), CONST32(~HFLG_SS32))));
		BR_UNCOND(vec_bb[36]);
		cpu->bb = vec_bb[36];
		ST_R32(AND(LD(eflags), CONST32(~(VM_MASK | RF_MASK | NT_MASK | TF_MASK))), EFLAGS_idx);
		ST_R32(OR(AND(LD_R32(ESP_idx), NOT(LD(stack_mask))), AND(LD(esp), LD(stack_mask))), ESP_idx);
		ST_SEG(OR(AND(sel, CONST16(~3)), LD(dpl)), CS_idx);
		ST_SEG_HIDDEN(seg_base, CS_idx, SEG_BASE_idx);
		ST_SEG_HIDDEN(seg_limit, CS_idx, SEG_LIMIT_idx);
		ST_SEG_HIDDEN(seg_flags, CS_idx, SEG_FLG_idx);
		ST(cpu->ptr_hflags, OR(OR(SHR(AND(seg_flags, CONST32(SEG_HIDDEN_DB)), CONST32(20)), ZEXT32(LD(dpl))), AND(LD(cpu->ptr_hflags), CONST32(~(HFLG_CS32 | HFLG_CPL)))));
		ST_R32(LD(new_eip), EIP_idx);
		BR_COND(vec_bb[37], vec_bb[38], ICMP_EQ(idx, CONST32(EXP_PF)));
		cpu->bb = vec_bb[37];
		ST_R32(fault_addr, CR2_idx);
		BR_UNCOND(vec_bb[38]);
		cpu->bb = vec_bb[38];
		ST(GEP(ptr_exp_info, 1), CONST8(0));
		ReturnInst::Create(CTX(), ConstantExpr::getIntToPtr(INTPTR(nullptr), cpu->bb->getParent()->getReturnType()), cpu->bb);
		cpu->bb = vec_bb[0];
		// we don't handle double and triple faults yet, so just abort
		INTRINSIC(trap);
		UNREACH();
	}
	else {
		std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, func, 2);

		BR_COND(vec_bb[0], vec_bb[1], ICMP_UGT(ADD(MUL(idx, CONST32(4)), CONST32(3)), LD_SEG_HIDDEN(IDTR_idx, SEG_LIMIT_idx)));
		cpu->bb = vec_bb[1];
		Value *vec_entry = LD_MEM(MEM_LD32_idx, ADD(LD_SEG_HIDDEN(IDTR_idx, SEG_BASE_idx), MUL(idx, CONST32(4))));
		Value *stack_mask = CONST32(0xFFFF);
		Value *stack_base = LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx);
		Value *esp = ALLOC32();
		ST(esp, LD_R32(ESP_idx));
		ST(esp, SUB(LD(esp), CONST32(2)));
		ST_MEM(MEM_LD16_idx, ADD(stack_base, AND(LD(esp), stack_mask)), TRUNC16(old_eflags));
		ST(esp, SUB(LD(esp), CONST32(2)));
		ST_MEM(MEM_LD16_idx, ADD(stack_base, AND(LD(esp), stack_mask)), LD_SEG(CS_idx));
		ST(esp, SUB(LD(esp), CONST32(2)));
		ST_MEM(MEM_LD16_idx, ADD(stack_base, AND(LD(esp), stack_mask)), TRUNC16(eip));
		ST_R32(AND(LD_R32(EFLAGS_idx), CONST32(~(AC_MASK | RF_MASK | IF_MASK | TF_MASK))), EFLAGS_idx);
		ST_R32(OR(AND(LD_R32(ESP_idx), NOT(stack_mask)), AND(LD(esp), stack_mask)), ESP_idx);
		ST_SEG(TRUNC16(SHR(vec_entry, CONST32(16))), CS_idx);
		ST_SEG_HIDDEN(SHL(ZEXT32(LD_SEG(CS_idx)), CONST32(4)), CS_idx, SEG_BASE_idx);
		ST_R32(AND(vec_entry, CONST32(0xFFFF)), EIP_idx);
		ST(GEP(ptr_exp_info, 1), CONST8(0));
		ReturnInst::Create(CTX(), ConstantExpr::getIntToPtr(INTPTR(nullptr), cpu->bb->getParent()->getReturnType()), cpu->bb);
		cpu->bb = vec_bb[0];
		// we don't handle double and triple faults yet, so just abort
		INTRINSIC(trap);
		UNREACH();
	}

	if (cpu->cpu_flags & CPU_PRINT_IR) {
		cpu->mod->print(errs(), nullptr);
	}

	if (cpu->cpu_flags & CPU_CODEGEN_OPTIMIZE) {
		optimize(cpu);
		if (cpu->cpu_flags & CPU_PRINT_IR_OPTIMIZED) {
			cpu->mod->print(errs(), nullptr);
		}
	}

	orc::ThreadSafeContext tsc(std::unique_ptr<LLVMContext>(cpu->ctx));
	orc::ThreadSafeModule tsm(std::unique_ptr<Module>(cpu->mod), tsc);
	cpu->jit->add_ir_module(std::move(tsm));
	cpu->cpu_ctx.exp_fn = reinterpret_cast<raise_exp_t>(cpu->jit->lookup("cpu_raise_exception")->getAddress());
	assert(cpu->cpu_ctx.exp_fn);
	cpu->jit->remove_symbols(std::vector<std::string> { "cpu_raise_exception" });
}

void
raise_exp_inline_emit(cpu_t *cpu, std::vector<Value *> &exp_data)
{
	ST(GEP(cpu->exp_data, 0), exp_data[0]);
	ST(GEP(cpu->exp_data, 1), exp_data[1]);
	ST(GEP(cpu->exp_data, 2), exp_data[2]);
	ST(GEP(cpu->exp_data, 3), exp_data[3]);
	CallInst *ci = CallInst::Create(cpu->ptr_exp_fn, std::vector<Value *> { cpu->ptr_cpu_ctx, cpu->exp_data }, "", cpu->bb);
	ci->setCallingConv(CallingConv::C);
	ReturnInst::Create(CTX(), ci, cpu->bb);
}

BasicBlock *
raise_exception_emit(cpu_t *cpu, std::vector<Value *> &exp_data)
{
	BasicBlock *bb_exp = BasicBlock::Create(CTX(), "", cpu->bb->getParent(), 0);
	BasicBlock *bb = cpu->bb;
	cpu->bb = bb_exp;
	raise_exp_inline_emit(cpu, exp_data);
	cpu->bb = bb;
	return bb_exp;
}

void
write_eflags(cpu_t *cpu, Value *eflags, Value *mask)
{
	ST_R32(AND(OR(OR(AND(LD_R32(EFLAGS_idx), NOT(mask)), AND(eflags, mask)), CONST32(2)), CONST32(~RF_MASK)), EFLAGS_idx);
	Value *cf_new = AND(eflags, CONST32(1));
	Value *of_new = SHL(XOR(SHR(AND(eflags, CONST32(0x800)), CONST32(11)), cf_new), CONST32(30));
	Value *sfd = SHR(AND(eflags, CONST32(128)), CONST32(7));
	Value *pdb = SHL(XOR(CONST32(4), AND(eflags, CONST32(4))), CONST32(6));
	ST_FLG_RES(SHL(XOR(AND(eflags, CONST32(64)), CONST32(64)), CONST32(2)));
	ST_FLG_AUX(OR(OR(OR(OR(SHL(cf_new, CONST32(31)), SHR(AND(eflags, CONST32(16)), CONST32(1))), of_new), sfd), pdb));
}

static void
validate_seg_emit(cpu_t *cpu, const unsigned reg)
{
	std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, cpu->bb->getParent(), 2);
	Value *flags = LD_SEG_HIDDEN(reg, SEG_FLG_idx);
	Value *c = AND(flags, CONST32(1 << 10));
	Value *d = AND(flags, CONST32(1 << 11));
	Value *s = AND(flags, CONST32(1 << 12));
	Value *dpl = SHR(AND(flags, CONST32(3 << 13)), CONST32(13));
	Value *cpl = AND(LD(cpu->ptr_hflags), CONST32(HFLG_CPL));
	BR_COND(vec_bb[0], vec_bb[1], AND(ICMP_UGT(cpl, dpl), AND(ICMP_NE(s, CONST32(0)), OR(ICMP_EQ(d, CONST32(0)), ICMP_EQ(c, CONST32(0))))));
	cpu->bb = vec_bb[0];
	write_seg_reg_emit(cpu, reg, std::vector<Value *> { CONST16(0), CONST32(0), CONST32(0), CONST32(0) });
	BR_UNCOND(vec_bb[1]);
	cpu->bb = vec_bb[1];
}

void
write_seg_reg_emit(cpu_t *cpu, const unsigned reg, std::vector<Value *> &vec)
{
	ST_SEG(vec[0], reg);
	ST_SEG_HIDDEN(vec[1], reg, SEG_BASE_idx);
	ST_SEG_HIDDEN(vec[2], reg, SEG_LIMIT_idx);
	ST_SEG_HIDDEN(vec[3], reg, SEG_FLG_idx);

	if (reg == CS_idx) {
		ST(cpu->ptr_hflags, OR(SHR(AND(vec[3], CONST32(SEG_HIDDEN_DB)), CONST32(20)), AND(LD(cpu->ptr_hflags), CONST32(~HFLG_CS32))));
	}
	else if (reg == SS_idx) {
		ST(cpu->ptr_hflags, OR(OR(SHR(AND(vec[3], CONST32(SEG_HIDDEN_DB)), CONST32(19)), AND(ZEXT32(vec[0]), CONST32(3))), AND(LD(cpu->ptr_hflags), CONST32(~(HFLG_SS32 | HFLG_CPL)))));
	}
}

void
set_access_flg_seg_desc_emit(cpu_t *cpu, Value *desc, Value *desc_addr)
{
	std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, cpu->bb->getParent(), 2);
	BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(OR(SHR(AND(desc, CONST64(SEG_DESC_S)), CONST64(44)), SHR(AND(desc, CONST64(SEG_DESC_A)), CONST64(39))), CONST64(1)));
	cpu->bb = vec_bb[0];
	ST_MEM_PRIV(MEM_ST64_idx, desc_addr, OR(desc, CONST64(SEG_DESC_A)));
	BR_UNCOND(vec_bb[1]);
	cpu->bb = vec_bb[1];
}

Value *
read_seg_desc_base_emit(cpu_t *cpu, Value *desc)
{
	return TRUNC32(OR(OR(SHR(AND(desc, CONST64(0xFFFF0000)), CONST64(16)), SHR(AND(desc, CONST64(0xFF00000000)), CONST64(16))), SHR(AND(desc, CONST64(0xFF00000000000000)), CONST64(32))));
}

Value *
read_seg_desc_flags_emit(cpu_t *cpu, Value *desc)
{
	return TRUNC32(SHR(AND(desc, CONST64(0xFFFFFFFF00000000)), CONST64(32)));
}

Value *
read_seg_desc_limit_emit(cpu_t *cpu, Value *desc)
{
	std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, cpu->bb->getParent(), 2);
	Value *limit = ALLOC32();
	ST(limit, TRUNC32(OR(AND(desc, CONST64(0xFFFF)), SHR(AND(desc, CONST64(0xF000000000000)), CONST64(32)))));
	BR_COND(vec_bb[0], vec_bb[1], ICMP_NE(AND(desc, CONST64(SEG_DESC_G)), CONST64(0)));
	cpu->bb = vec_bb[0];
	ST(limit, OR(SHL(LD(limit), CONST32(12)), CONST32(PAGE_MASK)));
	BR_UNCOND(vec_bb[1]);
	cpu->bb = vec_bb[1];
	return LD(limit);
}

std::vector<Value *>
read_seg_desc_emit(cpu_t *cpu, Value *sel, BasicBlock *bb_exp)
{
	std::vector<Value *> vec;
	std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, cpu->bb->getParent(), 4);
	Value *base = ALLOC32();
	Value *limit = ALLOC32();
	Value *idx = SHR(sel, CONST16(3));
	Value *ti = SHR(AND(sel, CONST16(4)), CONST16(2));
	BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(ti, CONST16(0)));
	cpu->bb = vec_bb[0];
	ST(base, LD_SEG_HIDDEN(GDTR_idx, SEG_BASE_idx));
	ST(limit, LD_SEG_HIDDEN(GDTR_idx, SEG_LIMIT_idx));
	BR_UNCOND(vec_bb[2]);
	cpu->bb = vec_bb[1];
	ST(base, LD_SEG_HIDDEN(LDTR_idx, SEG_BASE_idx));
	ST(limit, LD_SEG_HIDDEN(LDTR_idx, SEG_LIMIT_idx));
	BR_UNCOND(vec_bb[2]);
	cpu->bb = vec_bb[2];
	Value *desc_addr = ADD(LD(base), ZEXT32(MUL(idx, CONST16(8))));
	vec.push_back(desc_addr);
	BR_COND(bb_exp ? bb_exp : RAISE(AND(sel, CONST16(0xFFFC)), EXP_GP),
		vec_bb[3], ICMP_UGT(ADD(desc_addr, CONST32(7)), ADD(LD(base), LD(limit)))); // sel idx outside of descriptor table
	cpu->bb = vec_bb[3];
	Value *desc = LD_MEM_PRIV(MEM_LD64_idx, desc_addr);
	vec.push_back(desc);
	return vec;
}

std::vector<Value *>
read_tss_desc_emit(cpu_t *cpu, Value *sel)
{
	std::vector<Value *> vec;
	std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, cpu->bb->getParent(), 2);
	Value *idx = SHR(sel, CONST16(3));
	Value *ti = SHR(AND(sel, CONST16(4)), CONST16(2));
	BasicBlock *bb_exp = RAISE(AND(sel, CONST16(0xFFFC)), EXP_GP);
	BR_COND(bb_exp, vec_bb[0], ICMP_NE(ti, CONST16(0))); // must be in the gdt
	cpu->bb = vec_bb[0];
	Value *base = LD_SEG_HIDDEN(GDTR_idx, SEG_BASE_idx);
	Value *limit = LD_SEG_HIDDEN(GDTR_idx, SEG_LIMIT_idx);
	Value *desc_addr = ADD(base, ZEXT32(MUL(idx, CONST16(8))));
	vec.push_back(desc_addr);
	BR_COND(bb_exp, vec_bb[1], ICMP_UGT(ADD(desc_addr, CONST32(7)), ADD(base, limit))); // sel idx outside of descriptor table
	cpu->bb = vec_bb[1];
	Value *desc = LD_MEM_PRIV(MEM_LD64_idx, desc_addr);
	vec.push_back(desc);
	return vec;
}

std::vector<Value *>
read_stack_ptr_from_tss_emit(cpu_t *cpu, Value *cpl, BasicBlock *bb_exp)
{
	std::vector<Value *> vec;
	std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, cpu->bb->getParent(), 4);
	Value *esp = ALLOC32();
	Value *ss = ALLOC16();
	Value *type = SHR(AND(LD_SEG_HIDDEN(TR_idx, SEG_FLG_idx), CONST32(SEG_HIDDEN_TSS_TY)), CONST32(11));
	Value *idx = ADD(SHL(CONST32(2), type), MUL(ZEXT32(cpl), SHL(CONST32(4), type)));
	BR_COND(bb_exp ? bb_exp : RAISE(AND(LD_SEG(TR_idx), CONST16(0xFFFC)), EXP_TS),
		vec_bb[0], ICMP_UGT(SUB(ADD(idx, SHL(CONST32(4), type)), CONST32(1)), LD_SEG_HIDDEN(TR_idx, SEG_LIMIT_idx)));
	cpu->bb = vec_bb[0];
	BR_COND(vec_bb[1], vec_bb[2], ICMP_NE(type, CONST32(0)));
	cpu->bb = vec_bb[1];
	Value *temp1 = LD_MEM(MEM_LD32_idx, ADD(LD_SEG_HIDDEN(TR_idx, SEG_BASE_idx), idx));
	ST(esp, temp1);
	temp1 = LD_MEM(MEM_LD16_idx, ADD(LD_SEG_HIDDEN(TR_idx, SEG_BASE_idx), ADD(idx, CONST32(4))));
	ST(ss, temp1);
	BR_UNCOND(vec_bb[3]);
	cpu->bb = vec_bb[2];
	Value *temp2 = LD_MEM(MEM_LD16_idx, ADD(LD_SEG_HIDDEN(TR_idx, SEG_BASE_idx), idx));
	ST(esp, ZEXT32(temp2));
	temp2 = LD_MEM(MEM_LD16_idx, ADD(LD_SEG_HIDDEN(TR_idx, SEG_BASE_idx), ADD(idx, CONST32(2))));
	ST(ss, temp2);
	BR_UNCOND(vec_bb[3]);
	cpu->bb = vec_bb[3];
	vec.push_back(LD(esp));
	vec.push_back(LD(ss));
	return vec;
}

std::vector<Value *>
check_ss_desc_priv_emit(cpu_t *cpu, Value *sel, Value *cs, Value *cpl, BasicBlock *bb_exp)
{
	std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, cpu->bb->getParent(), 3);
	BR_COND(bb_exp ? bb_exp : RAISE(CONST16(0), EXP_GP),
		vec_bb[0], ICMP_EQ(SHR(sel, CONST16(2)), CONST16(0))); // sel == NULL
	cpu->bb = vec_bb[0];
	std::vector<Value *> vec = read_seg_desc_emit(cpu, sel, bb_exp);
	Value *desc = vec[1];
	Value *s = TRUNC16(SHR(AND(desc, CONST64(SEG_DESC_S)), CONST64(44))); // cannot be a system segment
	Value *d = TRUNC16(SHR(AND(desc, CONST64(SEG_DESC_DC)), CONST64(42))); // cannot be a code segment
	Value *w = TRUNC16(SHR(AND(desc, CONST64(SEG_DESC_W)), CONST64(39))); // cannot be a non-writable data segment
	Value *dpl = TRUNC16(SHR(AND(desc, CONST64(SEG_DESC_DPL)), CONST64(42)));
	Value *rpl = SHL(AND(sel, CONST16(3)), CONST16(5));
	Value *val;
	// check for segment privilege violations
	if (cs == nullptr) {
		Value *cpl2 = cpl ? cpl : CONST16(cpu->cpu_ctx.hflags & HFLG_CPL);
		val = XOR(OR(OR(OR(OR(s, d), w), dpl), rpl), OR(OR(OR(OR(CONST16(1), CONST16(0)), CONST16(4)), SHL(cpl2, CONST16(3))), SHL(cpl2, CONST16(5))));
	}
	else {
		Value *rpl_cs = AND(cs, CONST16(3));
		val = XOR(OR(OR(OR(OR(s, d), w), dpl), rpl), OR(OR(OR(OR(CONST16(1), CONST16(0)), CONST16(4)), SHL(rpl_cs, CONST16(3))), SHL(rpl_cs, CONST16(5))));
	}
	BR_COND(bb_exp ? bb_exp : RAISE(AND(sel, CONST16(0xFFFC)), EXP_GP),
		vec_bb[1], ICMP_NE(val, CONST16(0)));
	cpu->bb = vec_bb[1];
	Value *p = AND(desc, CONST64(SEG_DESC_P));
	BR_COND(bb_exp ? bb_exp : RAISE(AND(sel, CONST16(0xFFFC)), EXP_SS),
		vec_bb[2], ICMP_EQ(p, CONST64(0))); // segment not present
	cpu->bb = vec_bb[2];
	return vec;
}

std::vector<Value *>
check_seg_desc_priv_emit(cpu_t *cpu, Value *sel)
{
	std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, cpu->bb->getParent(), 5);
	std::vector<Value *> vec = read_seg_desc_emit(cpu, sel);
	Value *desc = vec[1];
	Value *s = AND(desc, CONST64(SEG_DESC_S));
	BasicBlock *bb_exp = RAISE(AND(sel, CONST16(0xFFFC)), EXP_GP);
	BR_COND(bb_exp, vec_bb[0], ICMP_EQ(s, CONST64(0))); // cannot be a system segment
	cpu->bb = vec_bb[0];
	Value *d = TRUNC16(SHR(AND(desc, CONST64(SEG_DESC_DC)), CONST64(43)));
	Value *r = TRUNC16(SHR(AND(desc, CONST64(SEG_DESC_R)), CONST64(40)));
	BR_COND(bb_exp, vec_bb[1], ICMP_EQ(OR(d, r), CONST16(1))); // cannot be a non-readable code segment
	cpu->bb = vec_bb[1];
	BR_COND(vec_bb[3], vec_bb[2], OR(ICMP_EQ(d, CONST16(0)), ICMP_EQ(AND(desc, CONST64(SEG_DESC_C)), CONST64(0))));
	cpu->bb = vec_bb[3];
	Value *cpl = CONST16(cpu->cpu_ctx.hflags & HFLG_CPL);
	Value *dpl = TRUNC16(SHR(AND(desc, CONST64(SEG_DESC_DPL)), CONST64(45)));
	Value *rpl = AND(sel, CONST16(3));
	BR_COND(bb_exp, vec_bb[2], AND(ICMP_UGT(rpl, dpl), ICMP_UGT(cpl, dpl))); // segment privilege violation
	cpu->bb = vec_bb[2];
	Value *p = AND(desc, CONST64(SEG_DESC_P));
	bb_exp = RAISE(AND(sel, CONST16(0xFFFC)), EXP_NP);
	BR_COND(bb_exp, vec_bb[4], ICMP_EQ(p, CONST64(0))); // segment not present
	cpu->bb = vec_bb[4];
	return vec;
}

void
lcall_pe_emit(cpu_t *cpu, std::vector<Value *> &vec, uint8_t size_mode, uint32_t ret_eip, uint32_t call_eip)
{
	std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, cpu->bb->getParent(), 38);
	BasicBlock *bb_exp = RAISE0(EXP_GP);
	Value *sel = vec[0];
	vec.erase(vec.begin());
	Value *cpl = CONST16(cpu->cpu_ctx.hflags & HFLG_CPL);
	Value *dpl = ALLOC16();
	Value *rpl = ALLOC16();
	Value *esp = ALLOC32();
	Value *ss = ALLOC16();
	Value *stack_mask = ALLOC32();
	Value *stack_base = ALLOC32();
	Value *stack_switch = ALLOC8();
	BR_COND(bb_exp, vec_bb[0], ICMP_EQ(SHR(sel, CONST16(2)), CONST16(0))); // sel == NULL
	cpu->bb = vec_bb[0];
	std::vector<Value *> vec1 = read_seg_desc_emit(cpu, sel);
	Value *desc_addr = ALLOC32();
	Value *desc = ALLOC64();
	ST(desc_addr, vec1[0]);
	ST(desc, vec1[1]);
	Value *sys_ty = ALLOC8();
	BR_COND(vec_bb[1], vec_bb[2], ICMP_EQ(AND(LD(desc), CONST64(SEG_DESC_S)), CONST64(0)));

	// non-system desc
	cpu->bb = vec_bb[2];
	bb_exp = RAISE(AND(sel, CONST16(0xFFFC)), EXP_GP);
	BR_COND(bb_exp, vec_bb[3], ICMP_EQ(AND(LD(desc), CONST64(SEG_DESC_DC)), CONST64(0))); // !(data desc)
	cpu->bb = vec_bb[3];
	ST(dpl, TRUNC16(SHR(AND(LD(desc), CONST64(SEG_DESC_DPL)), CONST64(45))));
	BR_COND(vec_bb[4], vec_bb[5], ICMP_NE(AND(LD(desc), CONST64(SEG_DESC_C)), CONST64(0)));

	// conforming
	cpu->bb = vec_bb[4];
	BR_COND(bb_exp, vec_bb[6], ICMP_UGT(LD(dpl), cpl)); // dpl > cpl

	// non-conforming
	cpu->bb = vec_bb[5];
	ST(rpl, AND(sel, CONST16(3)));
	BR_COND(bb_exp, vec_bb[6], OR(ICMP_UGT(LD(rpl), cpl), ICMP_NE(LD(dpl), cpl))); // rpl > cpl || dpl != cpl

	// commmon path for conf/non-conf
	cpu->bb = vec_bb[6];
	bb_exp = RAISE(AND(sel, CONST16(0xFFFC)), EXP_NP);
	BR_COND(bb_exp, vec_bb[7], ICMP_EQ(AND(LD(desc), CONST64(SEG_DESC_P)), CONST64(0))); // p == 0
	cpu->bb = vec_bb[7];
	MEM_PUSH(vec);
	set_access_flg_seg_desc_emit(cpu, LD(desc), LD(desc_addr));
	write_seg_reg_emit(cpu, CS_idx, std::vector<Value *> { OR(AND(sel, CONST16(0xFFFC)), cpl), read_seg_desc_base_emit(cpu, LD(desc)),
		read_seg_desc_limit_emit(cpu, LD(desc)), read_seg_desc_flags_emit(cpu, LD(desc))});
	ST_R32(CONST32(call_eip), EIP_idx);
	BR_UNCOND(vec_bb[37]);

	// system desc
	cpu->bb = vec_bb[1];
	ST(sys_ty, TRUNC8(SHR(AND(LD(desc), CONST64(SEG_DESC_TY)), CONST64(40))));
	bb_exp = RAISE(AND(sel, CONST16(0xFFFC)), EXP_GP);
	SwitchInst *swi = SWITCH_new(5, LD(sys_ty), bb_exp);
	swi->SWITCH_add(8, 5, vec_bb[8]);
	swi->SWITCH_add(8, 1, vec_bb[8]);
	swi->SWITCH_add(8, 9, vec_bb[8]);
	swi->SWITCH_add(8, 4, vec_bb[9]); // call gate, 16 bit
	swi->SWITCH_add(8, 12, vec_bb[9]); // call gate, 32 bit
	cpu->bb = vec_bb[8];
	// we don't support tss and task gates yet, so just abort
	INTRINSIC(trap);
	UNREACH();

	// call gate
	cpu->bb = vec_bb[9];
	ST(sys_ty, SHR(LD(sys_ty), CONST8(3)));
	ST(dpl, TRUNC16(SHR(AND(LD(desc), CONST64(SEG_DESC_DPL)), CONST64(45))));
	ST(rpl, AND(sel, CONST16(3)));
	BR_COND(bb_exp, vec_bb[10], OR(ICMP_ULT(LD(dpl), cpl), ICMP_UGT(LD(rpl), LD(dpl)))); // dpl < cpl || rpl > dpl
	cpu->bb = vec_bb[10];
	bb_exp = RAISE(AND(sel, CONST16(0xFFFC)), EXP_NP);
	BR_COND(bb_exp, vec_bb[11], ICMP_EQ(AND(LD(desc), CONST64(SEG_DESC_P)), CONST64(0))); // p == 0
	cpu->bb = vec_bb[11];
	Value *num_param = TRUNC32(AND(SHR(LD(desc), CONST64(32)), CONST64(0x1F)));
	Value *new_eip = TRUNC32(OR(SHR(AND(LD(desc), CONST64(0xFFFF0000)), CONST64(32)), AND(LD(desc), CONST64(0xFFFF))));
	Value *code_sel = TRUNC16(SHR(AND(LD(desc), CONST64(0xFFFF0000)), CONST64(16)));
	bb_exp = RAISE0(EXP_GP);
	BR_COND(bb_exp, vec_bb[12], ICMP_EQ(SHR(code_sel, CONST16(2)), CONST16(0))); // code_sel == NULL
	cpu->bb = vec_bb[12];
	vec1 = read_seg_desc_emit(cpu, code_sel); // read code desc pointed by the call gate sel
	Value *cs_desc_addr = vec1[0];
	Value *cs_desc = vec1[1];
	ST(dpl, TRUNC16(SHR(AND(cs_desc, CONST64(SEG_DESC_DPL)), CONST64(45))));
	bb_exp = RAISE(AND(code_sel, CONST16(0xFFFC)), EXP_GP);
	BR_COND(bb_exp, vec_bb[13], OR(ICMP_NE(OR(SHR(AND(cs_desc, CONST64(SEG_DESC_S)), CONST64(43)), SHR(AND(cs_desc, CONST64(SEG_DESC_DC)), CONST64(43))), CONST64(3)),
		ICMP_UGT(LD(dpl), cpl))); // !(code desc) || dpl > cpl
	cpu->bb = vec_bb[13];
	bb_exp = RAISE(AND(code_sel, CONST16(0xFFFC)), EXP_NP);
	BR_COND(bb_exp, vec_bb[14], ICMP_EQ(AND(cs_desc, CONST64(SEG_DESC_P)), CONST64(0))); // p == 0
	cpu->bb = vec_bb[14];
	BR_COND(vec_bb[15], vec_bb[30], AND(ICMP_EQ(AND(cs_desc, CONST64(SEG_DESC_C)), CONST64(0)), ICMP_ULT(LD(dpl), cpl)));

	// more privileged
	cpu->bb = vec_bb[15];
	vec1 = read_stack_ptr_from_tss_emit(cpu, LD(dpl));
	ST(esp, vec1[0]);
	ST(ss, vec1[1]);
	ST(stack_switch, CONST8(1));
	bb_exp = RAISE(AND(LD(ss), CONST16(0xFFFC)), EXP_TS);
	BR_COND(bb_exp, vec_bb[16], ICMP_EQ(SHR(LD(ss), CONST16(2)), CONST16(0))); // ss == NULL
	cpu->bb = vec_bb[16];
	vec1 = read_seg_desc_emit(cpu, LD(ss)); // load data (stack) desc pointed by ss
	ST(desc_addr, vec1[0]);
	ST(desc, vec1[1]);
	Value *s = TRUNC16(SHR(AND(LD(desc), CONST64(SEG_DESC_S)), CONST64(44))); // !(sys desc)
	Value *d = TRUNC16(SHR(AND(LD(desc), CONST64(SEG_DESC_DC)), CONST64(42))); // data desc
	Value *w = TRUNC16(SHR(AND(LD(desc), CONST64(SEG_DESC_W)), CONST64(39))); // writable
	Value *dpl_ss = TRUNC16(SHR(AND(LD(desc), CONST64(SEG_DESC_DPL)), CONST64(42))); // dpl(ss) == dpl(code)
	Value *rpl_ss = SHL(AND(LD(ss), CONST16(3)), CONST16(5)); // rpl(ss) == dpl(code)
	bb_exp = RAISE(AND(LD(ss), CONST16(0xFFFC)), EXP_TS);
	BR_COND(bb_exp, vec_bb[17], ICMP_NE(XOR(OR(OR(OR(OR(s, d), w), dpl_ss), rpl_ss), OR(OR(CONST16(5), SHL(LD(dpl), CONST16(3))), SHL(LD(dpl), CONST16(5)))), CONST16(0)));
	cpu->bb = vec_bb[17];
	bb_exp = RAISE(AND(LD(ss), CONST16(0xFFFC)), EXP_SS);
	BR_COND(bb_exp, vec_bb[18], ICMP_EQ(AND(LD(desc), CONST64(SEG_DESC_P)), CONST64(0))); // p == 0
	cpu->bb = vec_bb[18];
	BR_COND(vec_bb[19], vec_bb[20], ICMP_NE(AND(LD(desc), CONST64(SEG_DESC_DB)), CONST64(0)));
	cpu->bb = vec_bb[19];
	ST(stack_mask, CONST32(0xFFFFFFFF));
	BR_UNCOND(vec_bb[21]);
	cpu->bb = vec_bb[20];
	ST(stack_mask, CONST32(0xFFFF));
	BR_UNCOND(vec_bb[21]);
	cpu->bb = vec_bb[21];
	ST(stack_base, read_seg_desc_base_emit(cpu, LD(desc)));
	Value *i = ALLOC32();
	ST(i, SUB(num_param, CONST32(1)));
	BR_COND(vec_bb[22], vec_bb[24], ICMP_NE(LD(sys_ty), CONST8(0)));
	// 32 bit pushes
	cpu->bb = vec_bb[22];
	ST(esp, SUB(LD(esp), CONST32(4)));
	ST_MEM_PRIV(MEM_ST32_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), ZEXT32(LD_SEG(SS_idx))); // push ss
	ST(esp, SUB(LD(esp), CONST32(4)));
	ST_MEM_PRIV(MEM_ST32_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), LD_R32(ESP_idx)); // push esp
	BR_COND(vec_bb[23], vec_bb[26], ICMP_SGE(LD(i), CONST32(0)));
	cpu->bb = vec_bb[23];
	Value *param32 = LD_MEM(MEM_LD32_idx, ADD(LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx), AND(ADD(LD_R32(ESP_idx), MUL(LD(i), CONST32(4))), LD(stack_mask)))); // read param from src stack
	ST(esp, SUB(LD(esp), CONST32(4)));
	ST_MEM_PRIV(MEM_ST32_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), param32); // push param to dst stack
	ST(i, SUB(LD(i), CONST32(1)));
	BR_COND(vec_bb[23], vec_bb[26], ICMP_SGE(LD(i), CONST32(0)));
	// 16 bit pushes
	cpu->bb = vec_bb[24];
	ST(esp, SUB(LD(esp), CONST32(2)));
	ST_MEM_PRIV(MEM_ST16_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), LD_SEG(SS_idx)); // push ss
	ST(esp, SUB(LD(esp), CONST32(2)));
	ST_MEM_PRIV(MEM_ST16_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), LD_R16(ESP_idx)); // push sp
	BR_COND(vec_bb[25], vec_bb[26], ICMP_SGE(LD(i), CONST32(0)));
	cpu->bb = vec_bb[25];
	Value *param16 = LD_MEM(MEM_LD16_idx, ADD(LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx), AND(ADD(LD_R32(ESP_idx), MUL(LD(i), CONST32(2))), LD(stack_mask)))); // read param from src stack
	ST(esp, SUB(LD(esp), CONST32(2)));
	ST_MEM_PRIV(MEM_ST16_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), param16); // push param to dst stack
	ST(i, SUB(LD(i), CONST32(1)));
	BR_COND(vec_bb[25], vec_bb[26], ICMP_SGE(LD(i), CONST32(0)));
	cpu->bb = vec_bb[26];
	BR_COND(vec_bb[27], vec_bb[28], ICMP_NE(LD(sys_ty), CONST8(0)));
	// 32 bit pushes
	cpu->bb = vec_bb[27];
	ST(esp, SUB(LD(esp), CONST32(4)));
	ST_MEM_PRIV(MEM_ST32_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), CONST32(cpu->cpu_ctx.regs.cs)); // push cs
	ST(esp, SUB(LD(esp), CONST32(4)));
	ST_MEM_PRIV(MEM_ST32_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), CONST32(ret_eip)); // push eip
	BR_UNCOND(vec_bb[29]);
	// 16 bit pushes
	cpu->bb = vec_bb[28];
	ST(esp, SUB(LD(esp), CONST32(2)));
	ST_MEM_PRIV(MEM_ST16_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), CONST16(cpu->cpu_ctx.regs.cs)); // push cs
	ST(esp, SUB(LD(esp), CONST32(2)));
	ST_MEM_PRIV(MEM_ST16_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), CONST16(ret_eip)); // push ip
	BR_UNCOND(vec_bb[29]);

	// same privilege
	cpu->bb = vec_bb[30];
	ST(stack_switch, CONST8(0));
	ST(esp, LD_R32(ESP_idx));
	BR_COND(vec_bb[31], vec_bb[32], ICMP_NE(AND(LD_SEG_HIDDEN(SS_idx, SEG_FLG_idx), CONST32(SEG_HIDDEN_DB)), CONST32(0)));
	cpu->bb = vec_bb[31];
	ST(stack_mask, CONST32(0xFFFFFFFF));
	BR_UNCOND(vec_bb[33]);
	cpu->bb = vec_bb[32];
	ST(stack_mask, CONST32(0xFFFF));
	BR_UNCOND(vec_bb[33]);
	cpu->bb = vec_bb[33];
	BR_COND(vec_bb[34], vec_bb[35], ICMP_NE(LD(sys_ty), CONST8(0)));
	// 32 bit pushes
	cpu->bb = vec_bb[34];
	ST(esp, SUB(LD(esp), CONST32(4)));
	ST_MEM(MEM_ST32_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), CONST32(cpu->cpu_ctx.regs.cs)); // push cs
	ST(esp, SUB(LD(esp), CONST32(4)));
	ST_MEM(MEM_ST32_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), CONST32(ret_eip)); // push eip
	BR_UNCOND(vec_bb[36]);
	// 16 bit pushes
	cpu->bb = vec_bb[35];
	ST(esp, SUB(LD(esp), CONST32(2)));
	ST_MEM(MEM_ST16_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), CONST16(cpu->cpu_ctx.regs.cs)); // push cs
	ST(esp, SUB(LD(esp), CONST32(2)));
	ST_MEM(MEM_ST16_idx, ADD(LD(stack_base), AND(LD(esp), LD(stack_mask))), CONST16(ret_eip)); // push ip
	BR_UNCOND(vec_bb[36]);

	// commmon path for call gates
	cpu->bb = vec_bb[29];
	set_access_flg_seg_desc_emit(cpu, LD(desc), LD(desc_addr));
	write_seg_reg_emit(cpu, SS_idx, std::vector<Value *> { OR(AND(LD(ss), CONST16(0xFFFC)), LD(dpl)), LD(stack_base), // load ss
		read_seg_desc_limit_emit(cpu, LD(desc)), read_seg_desc_flags_emit(cpu, LD(desc))});
	BR_UNCOND(vec_bb[36]);
	cpu->bb = vec_bb[36];
	set_access_flg_seg_desc_emit(cpu, cs_desc, cs_desc_addr);
	write_seg_reg_emit(cpu, CS_idx, std::vector<Value *> { OR(AND(code_sel, CONST16(0xFFFC)), LD(dpl)), read_seg_desc_base_emit(cpu, cs_desc), // load cs
		read_seg_desc_limit_emit(cpu, cs_desc), read_seg_desc_flags_emit(cpu, cs_desc)});
	ST_R32(OR(AND(LD_R32(ESP_idx), NOT(LD(stack_mask))), AND(LD(esp), LD(stack_mask))), ESP_idx);
	ST_R32(new_eip, EIP_idx);
	BR_UNCOND(vec_bb[37]);
	cpu->bb = vec_bb[37];
}

void
ljmp_pe_emit(cpu_t *cpu, Value *sel, uint8_t size_mode, uint32_t eip)
{
	std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, cpu->bb->getParent(), 18);
	BasicBlock *bb_exp = RAISE0(EXP_GP);
	Value *cpl = CONST16(cpu->cpu_ctx.hflags & HFLG_CPL);
	Value *dpl = ALLOC16();
	Value *rpl = ALLOC16();
	BR_COND(bb_exp, vec_bb[0], ICMP_EQ(SHR(sel, CONST16(2)), CONST16(0))); // sel == NULL
	cpu->bb = vec_bb[0];
	std::vector<Value *> vec1 = read_seg_desc_emit(cpu, sel);
	Value *desc_addr = ALLOC32();
	Value *desc = ALLOC64();
	ST(desc_addr, vec1[0]);
	ST(desc, vec1[1]);
	BR_COND(vec_bb[1], vec_bb[2], ICMP_EQ(AND(LD(desc), CONST64(SEG_DESC_S)), CONST64(0)));

	// non-system desc
	cpu->bb = vec_bb[2];
	bb_exp = RAISE(AND(sel, CONST16(0xFFFC)), EXP_GP);
	BR_COND(bb_exp, vec_bb[3], ICMP_EQ(AND(LD(desc), CONST64(SEG_DESC_DC)), CONST64(0))); // !(data desc)
	cpu->bb = vec_bb[3];
	ST(dpl, TRUNC16(SHR(AND(LD(desc), CONST64(SEG_DESC_DPL)), CONST64(45))));
	BR_COND(vec_bb[4], vec_bb[5], ICMP_NE(AND(LD(desc), CONST64(SEG_DESC_C)), CONST64(0)));

	// conforming
	cpu->bb = vec_bb[4];
	BR_COND(bb_exp, vec_bb[6], ICMP_UGT(LD(dpl), cpl)); // dpl > cpl

	// non-conforming
	cpu->bb = vec_bb[5];
	ST(rpl, AND(sel, CONST16(3)));
	BR_COND(bb_exp, vec_bb[6], OR(ICMP_UGT(LD(rpl), cpl), ICMP_NE(LD(dpl), cpl))); // rpl > cpl || dpl != cpl

	// commmon path for conf/non-conf
	cpu->bb = vec_bb[6];
	bb_exp = RAISE(AND(sel, CONST16(0xFFFC)), EXP_NP);
	BR_COND(bb_exp, vec_bb[7], ICMP_EQ(AND(LD(desc), CONST64(SEG_DESC_P)), CONST64(0))); // p == 0
	cpu->bb = vec_bb[7];
	set_access_flg_seg_desc_emit(cpu, LD(desc), LD(desc_addr));
	write_seg_reg_emit(cpu, CS_idx, std::vector<Value *> { OR(AND(sel, CONST16(0xFFFC)), cpl), read_seg_desc_base_emit(cpu, LD(desc)),
		read_seg_desc_limit_emit(cpu, LD(desc)), read_seg_desc_flags_emit(cpu, LD(desc))});
	ST_R32(CONST32(size_mode == SIZE16 ? eip & 0xFFFF : eip), EIP_idx);
	BR_UNCOND(vec_bb[17]);

	// system desc
	cpu->bb = vec_bb[1];
	Value *sys_ty = ALLOC8();
	ST(sys_ty, TRUNC8(SHR(AND(LD(desc), CONST64(SEG_DESC_TY)), CONST64(40))));
	bb_exp = RAISE(AND(sel, CONST16(0xFFFC)), EXP_GP);
	SwitchInst *swi = SWITCH_new(5, LD(sys_ty), bb_exp);
	swi->SWITCH_add(8, 5, vec_bb[8]);
	swi->SWITCH_add(8, 1, vec_bb[8]);
	swi->SWITCH_add(8, 9, vec_bb[8]);
	swi->SWITCH_add(8, 4, vec_bb[9]); // call gate, 16 bit
	swi->SWITCH_add(8, 12, vec_bb[9]); // call gate, 32 bit
	cpu->bb = vec_bb[8];
	// we don't support tss and task gates yet, so just abort
	INTRINSIC(trap);
	UNREACH();

	// call gate
	cpu->bb = vec_bb[9];
	ST(sys_ty, SHR(LD(sys_ty), CONST8(3)));
	ST(dpl, TRUNC16(SHR(AND(LD(desc), CONST64(SEG_DESC_DPL)), CONST64(45))));
	ST(rpl, AND(sel, CONST16(3)));
	BR_COND(bb_exp, vec_bb[10], OR(ICMP_ULT(LD(dpl), cpl), ICMP_UGT(LD(rpl), LD(dpl)))); // dpl < cpl || rpl > dpl
	cpu->bb = vec_bb[10];
	bb_exp = RAISE(AND(sel, CONST16(0xFFFC)), EXP_NP);
	BR_COND(bb_exp, vec_bb[11], ICMP_EQ(AND(LD(desc), CONST64(SEG_DESC_P)), CONST64(0))); // p == 0
	cpu->bb = vec_bb[11];
	Value *code_sel = TRUNC16(SHR(AND(LD(desc), CONST64(0xFFFF0000)), CONST64(16)));
	bb_exp = RAISE0(EXP_GP);
	BR_COND(bb_exp, vec_bb[12], ICMP_EQ(SHR(code_sel, CONST16(2)), CONST16(0))); // code_sel == NULL
	cpu->bb = vec_bb[12];
	vec1 = read_seg_desc_emit(cpu, code_sel); // read code desc pointed by the call gate sel
	ST(desc_addr, vec1[0]);
	ST(desc, vec1[1]);
	ST(dpl, TRUNC16(SHR(AND(LD(desc), CONST64(SEG_DESC_DPL)), CONST64(45))));
	bb_exp = RAISE(AND(code_sel, CONST16(0xFFFC)), EXP_GP);
	BR_COND(bb_exp, vec_bb[13], OR(OR(ICMP_NE(OR(SHR(AND(LD(desc), CONST64(SEG_DESC_S)), CONST64(43)), SHR(AND(LD(desc), CONST64(SEG_DESC_DC)), CONST64(43))), CONST64(3)),
		AND(ICMP_NE(AND(LD(desc), CONST64(SEG_DESC_C)), CONST64(0)), ICMP_UGT(LD(dpl), cpl))),
		AND(ICMP_EQ(AND(LD(desc), CONST64(SEG_DESC_C)), CONST64(0)), ICMP_NE(LD(dpl), cpl)))); // !(code desc) || (conf && dpl > cpl) || (non-conf && dpl != cpl)
	cpu->bb = vec_bb[13];
	bb_exp = RAISE(AND(code_sel, CONST16(0xFFFC)), EXP_NP);
	BR_COND(bb_exp, vec_bb[14], ICMP_EQ(AND(LD(desc), CONST64(SEG_DESC_P)), CONST64(0))); // p == 0
	cpu->bb = vec_bb[14];
	set_access_flg_seg_desc_emit(cpu, LD(desc), LD(desc_addr));
	write_seg_reg_emit(cpu, CS_idx, std::vector<Value *> { OR(AND(sel, CONST16(0xFFFC)), cpl), read_seg_desc_base_emit(cpu, LD(desc)),
		read_seg_desc_limit_emit(cpu, LD(desc)), read_seg_desc_flags_emit(cpu, LD(desc))});
	Value *temp_eip = ALLOC32();
	ST(temp_eip, CONST32(eip));
	BR_COND(vec_bb[15], vec_bb[16], ICMP_EQ(LD(sys_ty), CONST8(0)));
	cpu->bb = vec_bb[15];
	ST(temp_eip, AND(LD(temp_eip), CONST32(0xFFFF)));
	BR_UNCOND(vec_bb[16]);
	cpu->bb = vec_bb[16];
	ST_R32(LD(temp_eip), EIP_idx);
	BR_UNCOND(vec_bb[17]);
	cpu->bb = vec_bb[17];
}

void
ret_pe_emit(cpu_t *cpu, uint8_t size_mode, bool is_iret)
{
	std::vector<Value *> vec;
	Value *eip, *cs, *eflags, *mask, *temp_eflags, *esp_old, *esp_old_ptr;
	std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, cpu->bb->getParent(), 11);
	uint16_t cpl = cpu->cpu_ctx.hflags & HFLG_CPL;
	unsigned pop_at;
	if (is_iret) {
		std::vector<BasicBlock *> vec_bb2 = gen_bbs(cpu, cpu->bb->getParent(), 4);
		pop_at = 3;
		eflags = LD_R32(EFLAGS_idx);
		BR_COND(vec_bb2[0], vec_bb2[1], ICMP_NE(AND(eflags, CONST32(VM_MASK)), CONST32(0)));
		cpu->bb = vec_bb2[0];
		// we don't support virtual 8086 mode, so just abort
		INTRINSIC(trap);
		UNREACH();
		cpu->bb = vec_bb2[1];
		BR_COND(vec_bb2[2], vec_bb2[3], ICMP_NE(AND(eflags, CONST32(NT_MASK)), CONST32(0)));
		cpu->bb = vec_bb2[2];
		// we don't support task returns yet, so just abort
		INTRINSIC(trap);
		UNREACH();
		cpu->bb = vec_bb2[3];
		vec = MEM_POP(3);
		eip = vec[0];
		cs = vec[1];
		temp_eflags = vec[2];
		esp_old = vec[3];
		esp_old_ptr = vec[4];

		if (size_mode == SIZE16) {
			eip = ZEXT32(eip);
			temp_eflags = ZEXT32(temp_eflags);
			mask = CONST32(NT_MASK | DF_MASK | TF_MASK);
		}
		else {
			cs = TRUNC16(cs);
			mask = CONST32(ID_MASK | AC_MASK | RF_MASK | NT_MASK | DF_MASK | TF_MASK);
		}

		if (cpl <= ((cpu->cpu_ctx.regs.eflags & IOPL_MASK) >> 12)) {
			mask = OR(mask, CONST32(IF_MASK));
		}

		if (cpl == 0) {
			mask = OR(mask, CONST32(VIP_MASK | VIF_MASK | VM_MASK | IOPL_MASK));
			vec_bb2.push_back(BasicBlock::Create(CTX(), "", cpu->bb->getParent(), 0));
			BR_COND(vec_bb2[0], vec_bb2[4], ICMP_NE(AND(temp_eflags, CONST32(VM_MASK)), CONST32(0)));
			cpu->bb = vec_bb2[4];
		}
	}
	else {
		pop_at = 2;
		vec = MEM_POP(2);
		eip = vec[0];
		cs = vec[1];
		esp_old = vec[2];
		esp_old_ptr = vec[3];
		if (size_mode == SIZE16) {
			eip = ZEXT32(eip);
		}
		else {
			cs = TRUNC16(cs);
		}
	}

	BasicBlock *bb_exp = RAISE0(EXP_GP);
	BR_COND(bb_exp, vec_bb[0], ICMP_EQ(SHR(cs, CONST16(2)), CONST16(0))); // sel == NULL
	cpu->bb = vec_bb[0];
	std::vector<Value *> vec_cs = read_seg_desc_emit(cpu, cs);
	Value *cs_desc_addr = vec_cs[0];
	Value *cs_desc = vec_cs[1];
	Value *s = SHR(AND(cs_desc, CONST64(SEG_DESC_S)), CONST64(44)); // !(sys desc)
	Value *d = SHR(AND(cs_desc, CONST64(SEG_DESC_DC)), CONST64(42)); // !(data desc)
	bb_exp = RAISE(AND(cs, CONST16(0xFFFC)), EXP_GP);
	BR_COND(bb_exp, vec_bb[1], ICMP_NE(OR(s, d), CONST64(3)));
	cpu->bb = vec_bb[1];
	Value *rpl = AND(cs, CONST16(3));
	BR_COND(bb_exp, vec_bb[2], ICMP_ULT(rpl, CONST16(cpl))); // rpl < cpl
	cpu->bb = vec_bb[2];
	Value *c = AND(cs_desc, CONST64(SEG_DESC_C));
	Value *dpl = TRUNC16(SHR(AND(cs_desc, CONST64(SEG_DESC_DPL)), CONST64(45)));
	BR_COND(bb_exp, vec_bb[3], AND(ICMP_NE(c, CONST64(0)), ICMP_UGT(dpl, rpl))); // conf && dpl > rpl
	cpu->bb = vec_bb[3];
	Value *p = AND(cs_desc, CONST64(SEG_DESC_P));
	bb_exp = RAISE(AND(cs, CONST16(0xFFFC)), EXP_NP);
	BR_COND(bb_exp, vec_bb[4], ICMP_EQ(p, CONST64(0))); // p == 0
	cpu->bb = vec_bb[4];
	BR_COND(vec_bb[5], vec_bb[10], ICMP_UGT(rpl, CONST16(cpl)));

	// less privileged
	cpu->bb = vec_bb[5];
	vec = MEM_POP_AT(2, pop_at);
	Value *esp = vec[0];
	Value *ss = vec[1];
	if (size_mode == SIZE32) {
		ss = TRUNC16(ss);
	}
	std::vector<Value *> vec_ss = check_ss_desc_priv_emit(cpu, ss, cs);
	Value *ss_desc_addr = vec_ss[0];
	Value *ss_desc = vec_ss[1];
	set_access_flg_seg_desc_emit(cpu, ss_desc, ss_desc_addr);
	write_seg_reg_emit(cpu, SS_idx, std::vector<Value *> { ss, read_seg_desc_base_emit(cpu, ss_desc),
		read_seg_desc_limit_emit(cpu, ss_desc), read_seg_desc_flags_emit(cpu, ss_desc)});
	set_access_flg_seg_desc_emit(cpu, cs_desc, cs_desc_addr);
	write_seg_reg_emit(cpu, CS_idx, std::vector<Value *> { cs, read_seg_desc_base_emit(cpu, cs_desc),
		read_seg_desc_limit_emit(cpu, cs_desc), read_seg_desc_flags_emit(cpu, cs_desc)});
	Value *stack_mask = ALLOC32();
	BR_COND(vec_bb[6], vec_bb[7], ICMP_NE(AND(LD_SEG_HIDDEN(SS_idx, SEG_FLG_idx), CONST32(SEG_HIDDEN_DB)), CONST32(0)));
	cpu->bb = vec_bb[6];
	ST(stack_mask, CONST32(0xFFFFFFFF));
	BR_UNCOND(vec_bb[8]);
	cpu->bb = vec_bb[7];
	ST(stack_mask, CONST32(0xFFFF));
	BR_UNCOND(vec_bb[8]);
	cpu->bb = vec_bb[8];
	ST_R32(OR(AND(LD_R32(ESP_idx), NOT(LD(stack_mask))), AND(size_mode == SIZE16 ? ZEXT32(esp) : esp, LD(stack_mask))), ESP_idx);
	ST_R32(eip, EIP_idx);
	ST(cpu->ptr_hflags, OR(ZEXT32(rpl), AND(LD(cpu->ptr_hflags), CONST32(~HFLG_CPL))));
	validate_seg_emit(cpu, DS_idx);
	validate_seg_emit(cpu, ES_idx);
	validate_seg_emit(cpu, FS_idx);
	validate_seg_emit(cpu, GS_idx);
	BR_UNCOND(vec_bb[9]);

	// same privilege
	cpu->bb = vec_bb[10];
	ST_REG_val(esp_old, esp_old_ptr);
	ST_R32(eip, EIP_idx);
	set_access_flg_seg_desc_emit(cpu, cs_desc, cs_desc_addr);
	write_seg_reg_emit(cpu, CS_idx, std::vector<Value *> { cs, read_seg_desc_base_emit(cpu, cs_desc),
		read_seg_desc_limit_emit(cpu, cs_desc), read_seg_desc_flags_emit(cpu, cs_desc)});
	BR_UNCOND(vec_bb[9]);
	cpu->bb = vec_bb[9];
	if (is_iret) {
		write_eflags(cpu, temp_eflags, mask);
	}
}

Value *
mem_read_emit(cpu_t *cpu, Value *addr, const unsigned idx, const unsigned is_priv)
{
	static const uint8_t idx_to_size[4] = { 8, 16, 32, 64 };
	uint8_t mem_size = idx_to_size[idx];

	std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, cpu->bb->getParent(), 5);
	Value *ret = ALLOCs(mem_size);
	Value *tlb_idx1 = SHR(addr, CONST32(PAGE_SHIFT));
	Value *tlb_idx2 = SHR(SUB(ADD(addr, CONST32(mem_size / 8)), CONST32(1)), CONST32(PAGE_SHIFT));
	Value *tlb_entry = LD(GEP(cpu->ptr_tlb, tlb_idx1));
	Value *mem_access = CONST32((tlb_access[0][(cpu->cpu_ctx.hflags & HFLG_CPL) >> is_priv]));

	// interrogate the tlb
	BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(XOR(OR(AND(tlb_entry, mem_access), SHL(tlb_idx1, CONST32(PAGE_SHIFT))),
		OR(mem_access, SHL(tlb_idx2, CONST32(PAGE_SHIFT)))), CONST32(0)));

	// tlb hit, check if it's ram
	cpu->bb = vec_bb[0];
	Value *ram_offset = ALLOC32();
	ST(ram_offset, OR(AND(tlb_entry, CONST32(~PAGE_MASK)), AND(addr, CONST32(PAGE_MASK))));
	SwitchInst *swi = SWITCH_new(2, AND(tlb_entry, CONST32(TLB_RAM)), vec_bb[4]);
	swi->SWITCH_add(32, TLB_RAM, vec_bb[3]);

	// no, acccess the memory region with is_phys flag=1
	cpu->bb = vec_bb[4];
	ST(ret, CallInst::Create(cpu->ptr_mem_ldfn[idx], std::vector<Value *> { cpu->ptr_cpu_ctx, LD(ram_offset), cpu->instr_eip, CONST8(1 | is_priv) }, "", cpu->bb));
	BR_UNCOND(vec_bb[2]);

	// yes, access ram directly
	cpu->bb = vec_bb[3];
	ST(ret, LD(IBITCASTs(mem_size, GEP(cpu->ptr_ram, std::vector<Value *> { LD(ram_offset) }))));
	if ((cpu->cpu_flags & CPU_FLAG_SWAPMEM) && (mem_size != 8)) {
		std::vector<Type *> vec_types { getIntegerType(mem_size) };
		std::vector<Value *> vec_params { LD(ret) };
		ST(ret, INTRINSIC_ty(bswap, vec_types, vec_params));
	}
	BR_UNCOND(vec_bb[2]);

	// tlb miss, acccess the memory region with is_phys flag=0
	cpu->bb = vec_bb[1];
	ST(ret, CallInst::Create(cpu->ptr_mem_ldfn[idx], std::vector<Value *> { cpu->ptr_cpu_ctx, addr, cpu->instr_eip, CONST8(is_priv) }, "", cpu->bb));
	BR_UNCOND(vec_bb[2]);

	cpu->bb = vec_bb[2];
	return LD(ret);
}

void
mem_write_emit(cpu_t *cpu, Value *addr, Value *value, const unsigned idx, const unsigned is_priv)
{
	static const uint8_t idx_to_size[4] = { 8, 16, 32, 64 };
	uint8_t mem_size = idx_to_size[idx];

	std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, cpu->bb->getParent(), (cpu->cpu_ctx.hflags & HFLG_DISAS_ONE) ? 5 : 7);
	Value *tlb_idx1 = SHR(addr, CONST32(PAGE_SHIFT));
	Value *tlb_idx2 = SHR(SUB(ADD(addr, CONST32(mem_size / 8)), CONST32(1)), CONST32(PAGE_SHIFT));
	Value *tlb_entry = LD(GEP(cpu->ptr_tlb, tlb_idx1));
	Value *mem_access = CONST32((tlb_access[1][(cpu->cpu_ctx.hflags & HFLG_CPL) >> is_priv]) | TLB_DIRTY);
	Value *tc_ptr = ConstantExpr::getIntToPtr(INTPTR(cpu->tc), cpu->bb->getParent()->getReturnType());

	// interrogate the tlb
	BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(XOR(OR(AND(tlb_entry, mem_access), SHL(tlb_idx1, CONST32(PAGE_SHIFT))),
		OR(mem_access, SHL(tlb_idx2, CONST32(PAGE_SHIFT)))), CONST32(0)));

	// tlb hit, check if it's ram
	cpu->bb = vec_bb[0];
	Value *ram_offset = ALLOC32();
	ST(ram_offset, OR(AND(tlb_entry, CONST32(~PAGE_MASK)), AND(addr, CONST32(PAGE_MASK))));
	SwitchInst *swi = SWITCH_new(2, AND(tlb_entry, CONST32(TLB_RAM | TLB_CODE)), vec_bb[4]);
	swi->SWITCH_add(32, TLB_RAM, vec_bb[3]);
	if (!(cpu->cpu_ctx.hflags & HFLG_DISAS_ONE)) {
		swi->SWITCH_add(32, TLB_RAM | TLB_CODE, vec_bb[5]);
	}

	// no, acccess the memory region with is_phys flag=1
	cpu->bb = vec_bb[4];
	CallInst::Create(cpu->ptr_mem_stfn[idx], std::vector<Value *> { cpu->ptr_cpu_ctx, LD(ram_offset), value, cpu->instr_eip, CONST8(1 | is_priv), tc_ptr }, "", cpu->bb);
	BR_UNCOND(vec_bb[2]);

	// yes, access ram directly
	cpu->bb = vec_bb[3];
	Value *val_ptr = ALLOCs(mem_size);
	ST(val_ptr, value);
	if ((cpu->cpu_flags & CPU_FLAG_SWAPMEM) && (mem_size != 8)) {
		std::vector<Type *> vec_types { getIntegerType(mem_size) };
		std::vector<Value *> vec_params { LD(val_ptr) };
		ST(val_ptr, INTRINSIC_ty(bswap, vec_types, vec_params));
	}
	ST(IBITCASTs(mem_size, GEP(cpu->ptr_ram, std::vector<Value *> { LD(ram_offset) })), LD(val_ptr));
	BR_UNCOND(vec_bb[2]);

	if (!(cpu->cpu_ctx.hflags & HFLG_DISAS_ONE)) {
		// yes, but we are writing to a page which holds translated code, check for self-modifying code
		cpu->bb = vec_bb[5];
		CallInst *ci = CallInst::Create(cpu->ptr_invtc_fn, std::vector<Value *>{ cpu->ptr_cpu_ctx, tc_ptr, addr, CONST8(mem_size / 8) }, "", cpu->bb);
		BR_COND(vec_bb[6], vec_bb[3], ICMP_NE(ci, CONST8(0)));

		// we have been asked to exit the current tc, so we simply return from main
		cpu->bb = vec_bb[6];
		ST_R32(cpu->instr_eip, EIP_idx);
		ReturnInst::Create(CTX(), ConstantExpr::getIntToPtr(INTPTR(nullptr), cpu->bb->getParent()->getReturnType()), cpu->bb);
	}

	// tlb miss, acccess the memory region with is_phys flag=0
	cpu->bb = vec_bb[1];
	CallInst::Create(cpu->ptr_mem_stfn[idx], std::vector<Value *> { cpu->ptr_cpu_ctx, addr, value, cpu->instr_eip, CONST8(is_priv), tc_ptr }, "", cpu->bb);
	BR_UNCOND(vec_bb[2]);

	cpu->bb = vec_bb[2];
}

void
check_io_priv_emit(cpu_t *cpu, Value *port, uint8_t size_mode)
{
	static const uint8_t op_size_to_mem_size[3] = { 4, 2, 1 };

	if ((cpu->cpu_ctx.hflags & HFLG_PE_MODE) && ((cpu->cpu_ctx.hflags & HFLG_CPL) > ((cpu->cpu_ctx.regs.eflags & IOPL_MASK) >> 12))) {
		std::vector<BasicBlock *> vec_bb = gen_bbs(cpu, cpu->bb->getParent(), 3);
		BasicBlock *bb_exp = RAISE0(EXP_GP);
		Value *base = LD_SEG_HIDDEN(TR_idx, SEG_BASE_idx);
		Value *limit = LD_SEG_HIDDEN(TR_idx, SEG_LIMIT_idx);
		BR_COND(bb_exp, vec_bb[0], ICMP_ULT(limit, CONST32(103)));
		cpu->bb = vec_bb[0];
		Value *io_map_offset = LD_MEM(MEM_LD16_idx, ADD(base, CONST32(102)));
		Value *io_port_offset = ADD(ZEXT32(io_map_offset), SHR(port, CONST32(3)));
		BR_COND(bb_exp, vec_bb[1], ICMP_UGT(ADD(io_port_offset, CONST32(1)), limit));
		cpu->bb = vec_bb[1];
		Value *temp, *value = ALLOC32();
		temp = LD_MEM(MEM_LD16_idx, ADD(base, io_port_offset));
		ST(value, ZEXT32(temp));
		ST(value, SHR(LD(value), AND(port, CONST32(7))));
		BR_COND(bb_exp, vec_bb[2], ICMP_NE(AND(LD(value), CONST32((1 << op_size_to_mem_size[size_mode]) - 1)), CONST32(0)));
		cpu->bb = vec_bb[2];
	}
}

void
stack_push_emit(cpu_t *cpu, std::vector<Value *> &vec, uint32_t size_mode)
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
		ST_R16(sp, ESP_idx);
	}
	break;

	case 1: { // esp, push 32
		Value *esp = LD_R32(ESP_idx);
		for (auto &val : vec) {
			esp = SUB(esp, CONST32(4));
			ST_MEM(MEM_ST32_idx, ADD(esp, LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)), val);
		}
		ST_R32(esp, ESP_idx);
	}
	break;

	case 2: { // sp, push 16
		Value *sp = LD_R16(ESP_idx);
		for (auto &val : vec) {
			sp = SUB(sp, CONST16(2));
			ST_MEM(MEM_ST16_idx, ADD(ZEXT32(sp), LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)), val);
		}
		ST_R16(sp, ESP_idx);
	}
	break;

	case 3: { // esp, push 16
		Value *esp = LD_R32(ESP_idx);
		for (auto &val : vec) {
			esp = SUB(esp, CONST32(2));
			ST_MEM(MEM_ST16_idx, ADD(esp, LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)), val);
		}
		ST_R32(esp, ESP_idx);
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
		vec.push_back(GEP_R16(ESP_idx));
	}
	break;

	case 1: { // esp, pop 32
		Value *esp = ADD(LD_R32(ESP_idx), MUL(CONST32(pop_at), CONST32(4)));
		for (unsigned i = 0; i < num; i++) {
			vec.push_back(LD_MEM(MEM_LD32_idx, ADD(esp, LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx))));
			esp = ADD(esp, CONST32(4));
		}
		vec.push_back(esp);
		vec.push_back(GEP_R32(ESP_idx));
	}
	break;

	case 2: { // sp, pop 16
		Value *sp = ADD(LD_R16(ESP_idx), MUL(CONST16(pop_at), CONST16(2)));
		for (unsigned i = 0; i < num; i++) {
			vec.push_back(LD_MEM(MEM_LD16_idx, ADD(ZEXT32(sp), LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx))));
			sp = ADD(sp, CONST16(2));
		}
		vec.push_back(sp);
		vec.push_back(GEP_R16(ESP_idx));
	}
	break;

	case 3: { // esp, pop 16
		Value *esp = ADD(LD_R32(ESP_idx), MUL(CONST32(pop_at), CONST32(2)));
		for (unsigned i = 0; i < num; i++) {
			vec.push_back(LD_MEM(MEM_LD16_idx, ADD(esp, LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx))));
			esp = ADD(esp, CONST32(2));
		}
		vec.push_back(esp);
		vec.push_back(GEP_R32(ESP_idx));
	}
	break;

	default:
		LIB86CPU_ABORT();
	}

	return vec;
}

Value *
get_immediate_op(cpu_t *cpu, x86_instr *instr, uint8_t idx, uint8_t size_mode)
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
get_register_op(cpu_t *cpu, x86_instr *instr, uint8_t idx)
{
	assert(instr->operand[idx].type == OPTYPE_REG || instr->operand[idx].type == OPTYPE_CR_REG);
	return get_operand(cpu, instr, idx);
}

void
set_flags_sum(cpu_t *cpu, std::vector<Value *> &vec, uint8_t size_mode)
{
	switch (size_mode)
	{
	case SIZE8:
		ST_FLG_RES_ext(vec[0]);
		ST_FLG_SUM_AUX8(vec[1], vec[2], vec[0]);
		break;

	case SIZE16:
		ST_FLG_RES_ext(vec[0]);
		ST_FLG_SUM_AUX16(vec[1], vec[2], vec[0]);
		break;

	case SIZE32:
		ST_FLG_RES(vec[0]);
		ST_FLG_SUM_AUX32(vec[1], vec[2], vec[0]);
		break;

	default:
		LIB86CPU_ABORT_msg("Invalid size_mode \"%c\" used in %s\n", size_mode, __func__);
	}
}

void
set_flags_sub(cpu_t *cpu, std::vector<Value *> &vec, uint8_t size_mode)
{
	switch (size_mode)
	{
	case SIZE8:
		ST_FLG_RES_ext(vec[0]);
		ST_FLG_SUB_AUX8(vec[1], vec[2], vec[0]);
		break;

	case SIZE16:
		ST_FLG_RES_ext(vec[0]);
		ST_FLG_SUB_AUX16(vec[1], vec[2], vec[0]);
		break;

	case SIZE32:
		ST_FLG_RES(vec[0]);
		ST_FLG_SUB_AUX32(vec[1], vec[2], vec[0]);
		break;

	default:
		LIB86CPU_ABORT_msg("Invalid size_mode \"%c\" used in %s\n", size_mode, __func__);
	}
}

void
set_flags(cpu_t *cpu, Value *res, Value *aux, uint8_t size_mode)
{
	size_mode == SIZE32 ? ST_FLG_RES(res) : ST_FLG_RES_ext(res);
	ST_FLG_AUX(aux);
}

Value *
get_operand(cpu_t *cpu, x86_instr *instr, const unsigned opnum)
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
		Value *scale, *idx, *base, *disp;
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
		switch (instr->mod)
		{
		case 0:
			disp = CONST32(0);
			break;
		case 1:
			disp = SEXT32(CONST8(instr->disp));
			break;
		case 2:
			disp = CONST32(instr->disp);
			break;
		case 3:
			assert(0 && "instr->mod specifies OPTYPE_REG with sib addressing mode!\n");
			return nullptr;
		default:
			assert(0 && "Unknown instr->mod specified with instr->base == 5\n");
			return nullptr;
		}
		return ADD(ADD(ADD(base, MUL(idx, scale)), disp), LD_SEG_HIDDEN(instr->seg + SEG_offset, SEG_BASE_idx));
	default:
		assert(0 && "Unknown operand type specified\n");
		return nullptr;
	}
}

static void
hook_clean_stack_emit(cpu_t *cpu, const unsigned stack_bytes)
{
	// assumes that the hooked function was called with a near call, not with a far call
	Value *stack_ptr = ADD(LD_R32(ESP_idx), LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)); // assumes a 32 bit esp
	Value *eip = LD_MEM(MEM_LD32_idx, stack_ptr);
	ST_R32(eip, EIP_idx);
	ST_R32(ADD(stack_ptr, CONST32(4 + stack_bytes)), ESP_idx);
}

static std::vector<Value *>
hook_get_args(cpu_t *cpu, hook *obj, std::vector<int> &reg_args, int *stack_bytes)
{
	assert(obj->info.args.size() >= 1);

	std::vector<Value *> args;
	switch (obj->o_conv)
	{
	case call_conv::X86_STDCALL: {
		int stack_arg_size = 0;
		Value *stack_ptr = ALLOC32(); // assumes that call pushed a 32 bit eip
		ST(stack_ptr, ADD(ADD(LD_R32(ESP_idx), LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)), CONST32(4))); // assumes a 32 bit esp
		for (unsigned i = 1; i < obj->info.args.size(); i++) {
			args.push_back(LD_MEM(static_cast<int>(obj->info.args[i]), LD(stack_ptr)));
			int arg_size = obj->info.args[i] == arg_types::I64 ? 8 : 4;
			ST(stack_ptr, ADD(LD(stack_ptr), CONST32(arg_size)));
			stack_arg_size += arg_size;
		}
		*stack_bytes = stack_arg_size;
	}
	break;

	case call_conv::X86_FASTCALL: {
		int stack_arg_size = 0;
		int num_reg_args = 0;
		bool use_stack = false;
		Value *stack_ptr = ALLOC32(); // assumes that call pushed a 32 bit eip
		ST(stack_ptr, ADD(ADD(LD_R32(ESP_idx), LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)), CONST32(4))); // assumes a 32 bit esp
		for (unsigned i = 1; i < obj->info.args.size(); i++) {
			if (use_stack || (obj->info.args[i] == arg_types::I64)) {
				args.push_back(LD_MEM(static_cast<int>(obj->info.args[i]), LD(stack_ptr)));
				int arg_size = obj->info.args[i] == arg_types::I64 ? 8 : 4;
				ST(stack_ptr, ADD(LD(stack_ptr), CONST32(arg_size)));
				stack_arg_size += arg_size;
			}
			else {
				int reg_idx = num_reg_args ? EDX_idx : ECX_idx;
				switch (obj->info.args[i])
				{
				case arg_types::I8:
					reg_args.push_back(i);
					args.push_back(LD_R8L(reg_idx));
					break;

				case arg_types::I16:
					reg_args.push_back(i);
					args.push_back(LD_R16(reg_idx));
					break;

				case arg_types::I32:
				case arg_types::PTR:
					reg_args.push_back(i);
					args.push_back(LD_R32(reg_idx));
					break;

				default:
					LIB86CPU_ABORT_msg("Unknown hook argument type specified\n");
				}

				num_reg_args++;
				if (num_reg_args == 2) {
					use_stack = true;
				}
			}
		}
		*stack_bytes = stack_arg_size;
	}
	break;

	case call_conv::UNDEFINED:
		break;

	default:
		LIB86CPU_ABORT_msg("Unknown hook calling convention specified\n");
	}

	return args;
}

void
hook_emit(cpu_t *cpu, hook *obj)
{
	std::vector<Type *> args;
	for (const auto &type : obj->info.args) {
		switch (type)
		{
		case arg_types::VOID:
			args.push_back(getVoidType());
			break;

		case arg_types::I8:
			args.push_back(getIntegerType(8));
			break;

		case arg_types::I16:
			args.push_back(getIntegerType(16));
			break;

		case arg_types::I32:
			args.push_back(getIntegerType(32));
			break;

		case arg_types::I64:
			args.push_back(getIntegerType(64));
			break;

		case arg_types::PTR:
			args.push_back(getPointerType(getIntegerType(8)));
			break;

		default:
			LIB86CPU_ABORT_msg("Unknown hook argument type specified\n");
		}
	}

	Function *hook = Function::Create(FunctionType::get(args[0], std::vector<Type *> { args.begin() + 1, args.end() }, false),
		GlobalValue::ExternalLinkage, obj->info.name, cpu->mod);
	CallInst *ci;
	int stack_bytes;
	std::vector<int> reg_args;
	auto &vec_args = hook_get_args(cpu, obj, reg_args, &stack_bytes);
	switch (obj->d_conv)
	{
	case call_conv::X86_STDCALL: {
		hook->setCallingConv(CallingConv::X86_StdCall);
		cpu->jit->define_absolute(cpu->jit->mangle(hook), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(obj->info.addr),
			JITSymbolFlags::Absolute | JITSymbolFlags::Exported));
		ci = CallInst::Create(hook, vec_args, "", cpu->bb);
		ci->setCallingConv(CallingConv::X86_StdCall);
		hook_clean_stack_emit(cpu, stack_bytes);
	}
	break;

	case call_conv::X86_FASTCALL: {
		hook->setCallingConv(CallingConv::X86_FastCall);
		for (int arg_idx : reg_args) {
			hook->addAttribute(arg_idx, Attribute::AttrKind::InReg);
		}
		cpu->jit->define_absolute(cpu->jit->mangle(hook), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(obj->info.addr),
			JITSymbolFlags::Absolute | JITSymbolFlags::Exported));
		ci = CallInst::Create(hook, vec_args, "", cpu->bb);
		ci->setCallingConv(CallingConv::X86_FastCall);
		hook_clean_stack_emit(cpu, stack_bytes);
	}
	break;

	case call_conv::UNDEFINED:
	default:
		LIB86CPU_ABORT_msg("Unknown or invalid hook calling convention specified\n");
	}

	switch (obj->info.args[0])
	{
	case arg_types::VOID:
		break;

	case arg_types::I8:
		ST_R8L(ci, EAX_idx);
		break;

	case arg_types::I16:
		ST_R32(ci, EAX_idx);
		break;

	case arg_types::I32:
	case arg_types::PTR:
		ST_R32(ci, EAX_idx);
		break;

	case arg_types::I64:
		ST_R32(TRUNC32(ci), EAX_idx);
		ST_R32(TRUNC32(SHR(ci, CONST64(32))), EDX_idx);
		break;

	default:
		LIB86CPU_ABORT_msg("Unknown hook return type specified\n");
	}
}
