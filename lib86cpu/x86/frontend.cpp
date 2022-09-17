/*
 * x86 llvm frontend
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/LinkAllPasses.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/LegacyPassManager.h"
#include "jit.h"
#include "internal.h"
#include "frontend.h"
#include "memory.h"


enum class fn_emit_t {
	main_t,
	int_t,
};

static const std::unordered_map<ZydisRegister, int> zydis_to_reg_idx_table = {
	{ ZYDIS_REGISTER_AL,     EAX_idx },
	{ ZYDIS_REGISTER_CL,     ECX_idx },
	{ ZYDIS_REGISTER_DL,     EDX_idx },
	{ ZYDIS_REGISTER_BL,     EBX_idx },
	{ ZYDIS_REGISTER_AH,     EAX_idx },
	{ ZYDIS_REGISTER_CH,     ECX_idx },
	{ ZYDIS_REGISTER_DH,     EDX_idx },
	{ ZYDIS_REGISTER_BH,     EBX_idx },
	{ ZYDIS_REGISTER_AX,     EAX_idx },
	{ ZYDIS_REGISTER_CX,     ECX_idx },
	{ ZYDIS_REGISTER_DX,     EDX_idx },
	{ ZYDIS_REGISTER_BX,     EBX_idx },
	{ ZYDIS_REGISTER_SP,     ESP_idx },
	{ ZYDIS_REGISTER_BP,     EBP_idx },
	{ ZYDIS_REGISTER_SI,     ESI_idx },
	{ ZYDIS_REGISTER_DI,     EDI_idx },
	{ ZYDIS_REGISTER_EAX,    EAX_idx },
	{ ZYDIS_REGISTER_ECX,    ECX_idx },
	{ ZYDIS_REGISTER_EDX,    EDX_idx },
	{ ZYDIS_REGISTER_EBX,    EBX_idx },
	{ ZYDIS_REGISTER_ESP,    ESP_idx },
	{ ZYDIS_REGISTER_EBP,    EBP_idx },
	{ ZYDIS_REGISTER_ESI,    ESI_idx },
	{ ZYDIS_REGISTER_EDI,    EDI_idx },
	{ ZYDIS_REGISTER_EFLAGS, EFLAGS_idx},
	{ ZYDIS_REGISTER_EIP,    EIP_idx},
	{ ZYDIS_REGISTER_ES,     ES_idx },
	{ ZYDIS_REGISTER_CS,     CS_idx },
	{ ZYDIS_REGISTER_SS,     SS_idx },
	{ ZYDIS_REGISTER_DS,     DS_idx },
	{ ZYDIS_REGISTER_FS,     FS_idx },
	{ ZYDIS_REGISTER_GS,     GS_idx },
	{ ZYDIS_REGISTER_GDTR,   GDTR_idx },
	{ ZYDIS_REGISTER_LDTR,   LDTR_idx },
	{ ZYDIS_REGISTER_IDTR,   IDTR_idx },
	{ ZYDIS_REGISTER_TR,     TR_idx},
	{ ZYDIS_REGISTER_CR0,    CR0_idx },
	{ ZYDIS_REGISTER_CR1,    CR1_idx },
	{ ZYDIS_REGISTER_CR2,    CR2_idx },
	{ ZYDIS_REGISTER_CR3,    CR3_idx },
	{ ZYDIS_REGISTER_CR4,    CR4_idx },
	{ ZYDIS_REGISTER_DR0,    DR0_idx },
	{ ZYDIS_REGISTER_DR1,    DR1_idx },
	{ ZYDIS_REGISTER_DR2,    DR2_idx },
	{ ZYDIS_REGISTER_DR3,    DR3_idx },
	{ ZYDIS_REGISTER_DR4,    DR4_idx },
	{ ZYDIS_REGISTER_DR5,    DR5_idx },
	{ ZYDIS_REGISTER_DR6,    DR6_idx },
	{ ZYDIS_REGISTER_DR7,    DR7_idx },
	{ ZYDIS_REGISTER_MM0,    R0_idx },
	{ ZYDIS_REGISTER_MM1,    R1_idx },
	{ ZYDIS_REGISTER_MM2,    R2_idx },
	{ ZYDIS_REGISTER_MM3,    R3_idx },
	{ ZYDIS_REGISTER_MM4,    R4_idx },
	{ ZYDIS_REGISTER_MM5,    R5_idx },
	{ ZYDIS_REGISTER_MM6,    R6_idx },
	{ ZYDIS_REGISTER_MM7,    R7_idx },
};

int
get_reg_idx(ZydisRegister reg)
{
	auto it = zydis_to_reg_idx_table.find(reg);
	if (it == zydis_to_reg_idx_table.end()) {
		LIB86CPU_ABORT_msg("Unhandled register index %d in %s", reg, __func__);
	}

	return it->second;
}

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

void
get_ext_fn(cpu_t *cpu)
{
	static const char *func_name_ld[] = { "mem_read_helper8", "mem_read_helper16", "mem_read_helper32", "mem_read_helper64", "io_read8", "io_read16", "io_read32" };
	static const char *func_name_st[] = { "mem_write_helper8", "mem_write_helper16", "mem_write_helper32", "mem_write_helper64", "io_write8", "io_write16", "io_write32" };
	Type *cpu_ctx_ty = cpu->bb->getParent()->arg_begin()->getType();

	for (uint8_t i = 0; i < 4; i++) {
		cpu->ptr_mem_ldfn[i] = cast<Function>(cpu->mod->getOrInsertFunction(func_name_ld[i], getIntegerType(8 << i), cpu_ctx_ty,
			getIntegerType(32), getIntegerType(32), getIntegerType(8)).getCallee());
	}
	for (uint8_t i = 4; i < 7; i++) {
		cpu->ptr_mem_ldfn[i] = cast<Function>(cpu->mod->getOrInsertFunction(func_name_ld[i], getIntegerType(8 << (i - 4)), cpu_ctx_ty,
			getIntegerType(16)).getCallee());
	}

	for (uint8_t i = 0; i < 4; i++) {
		cpu->ptr_mem_stfn[i] = cast<Function>(cpu->mod->getOrInsertFunction(func_name_st[i], getVoidType(), cpu_ctx_ty,
			getIntegerType(32), getIntegerType(8 << i), getIntegerType(32), getIntegerType(8)).getCallee());
	}
	for (uint8_t i = 4; i < 7; i++) {
		cpu->ptr_mem_stfn[i] = cast<Function>(cpu->mod->getOrInsertFunction(func_name_st[i], getVoidType(), cpu_ctx_ty,
			getIntegerType(16), getIntegerType(8 << (i - 4))).getCallee());
	}

	cpu->ptr_abort_fn = cast<Function>(cpu->mod->getOrInsertFunction("cpu_runtime_abort", getVoidType(), getPointerType()).getCallee());
	cpu->ptr_abort_fn->addFnAttr(Attribute::AttrKind::NoReturn);

	cpu->ptr_exp_fn = cast<Function>(cpu->mod->getOrInsertFunction("cpu_raise_exception", cpu->bb->getParent()->getReturnType(), cpu_ctx_ty).getCallee());
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

Value *
store_atomic_emit(cpu_t *cpu, Value *ptr, Value *val, AtomicOrdering order, uint8_t align)
{
	StoreInst *instr = ST(ptr, val);
	instr->setOrdering(order);
	instr->setAlignment(Align(align));
	return instr;
}

Value *
load_atomic_emit(cpu_t *cpu, Value *ptr, Type *ptr_ty, AtomicOrdering order, uint8_t align)
{
	LoadInst *instr = LD(ptr, ptr_ty);
	instr->setOrdering(order);
	instr->setAlignment(Align(align));
	return instr;
}

void
check_int_emit(cpu_t *cpu)
{
	unsigned ptr_size = cpu->dl->getPointerSize();
	FunctionType *main_ty = cpu->bb->getParent()->getFunctionType();
	Value *int_flg = ZEXTs(ptr_size * 8, LD_ATOMIC(GEP(cpu->ptr_cpu_ctx, cpu->cpu_ctx_type, 9), getIntegerType(8), AtomicOrdering::Monotonic, 1));
	Value *tc_jmp_int_ptr = INT2PTR(getPointerType(),
		ADD(CONSTs(ptr_size * 8, reinterpret_cast<uintptr_t>(&cpu->tc->jmp_offset[TC_JMP_INT_OFFSET])), MUL(int_flg, CONSTs(ptr_size * 8, ptr_size))));
	CALL(main_ty, LD(tc_jmp_int_ptr, getPointerType()), cpu->ptr_cpu_ctx);
}

bool
check_rf_single_step_emit(cpu_t *cpu)
{
	if ((cpu->cpu_ctx.regs.eflags & (RF_MASK | TF_MASK)) | (cpu->cpu_flags & CPU_SINGLE_STEP)) {

		if (cpu->cpu_ctx.regs.eflags & (RF_MASK | TF_MASK)) {
			cpu->cpu_flags |= CPU_FORCE_INSERT;
		}

		if (cpu->cpu_ctx.regs.eflags & RF_MASK) {
			// clear rf if it is set. This happens in the one-instr tc that contains the instr that originally caused the instr breakpoint. This must be done at runtime
			// because otherwise tc_cache_insert will register rf as clear, when it was set at the beginning of this tc
			ST(GEP_EFLAGS(), AND(LD(GEP_EFLAGS(), getIntegerType(32)), CONST32(~RF_MASK)));
		}

		if ((cpu->cpu_ctx.regs.eflags & TF_MASK) | (cpu->cpu_flags & CPU_SINGLE_STEP)) {
			// NOTE: if this instr also has a watchpoint, the other DB exp won't be generated
			ST_REG_idx(OR(LD_R32(DR6_idx), CONST32(DR6_BS_MASK)), DR6_idx);
			raise_exp_inline_emit(cpu, CONST32(0), CONST16(0), CONST16(EXP_DB), LD_R32(EIP_idx));
			cpu->bb = getBB();
			return true;
		}
	}

	return false;
}

void
link_indirect_emit(cpu_t *cpu)
{
	if (check_rf_single_step_emit(cpu)) {
		return;
	}

	// make sure we check for interrupts before jumping to the next tc
	check_int_emit(cpu);

	auto func = cpu->mod->getOrInsertFunction("link_indirect_handler", getPointerType(), getPointerType(), getPointerType());
	CallInst *ci1 = CALL(func.getFunctionType(), func.getCallee(), cpu->ptr_cpu_ctx, ConstantExpr::getIntToPtr(CONSTp(cpu->tc), getPointerType()));
	CallInst *ci2 = CALL_tail(cpu->bb->getParent()->getFunctionType(), ci1, cpu->ptr_cpu_ctx);
	ReturnInst::Create(CTX(), ci2, cpu->bb);
	cpu->bb = getBB();
}

void
link_ret_emit(cpu_t *cpu)
{
	// NOTE: perhaps find a way to use a return stack buffer to link to the next tc

	link_indirect_emit(cpu);
}

void
link_direct_emit(cpu_t *cpu, addr_t instr_pc, addr_t dst_pc, addr_t *next_pc, Value *target_addr)
{
	if (check_rf_single_step_emit(cpu)) {
		return;
	}

	// make sure we check for interrupts before jumping to the next tc
	check_int_emit(cpu);

	// vec_addr: instr_pc, dst_pc, next_pc
	addr_t page_addr = instr_pc & ~PAGE_MASK;
	uint32_t n, dst = (dst_pc & ~PAGE_MASK) == page_addr;
	if (next_pc) {
		n = dst + ((*next_pc & ~PAGE_MASK) == page_addr);
	}
	else {
		n = dst;
	}
	cpu->tc->flags |= (n & TC_FLG_NUM_JMP);

	if (n == 0) {
		return;
	}

	FunctionType *main_ty = cpu->bb->getParent()->getFunctionType();
	Value *tc_jmp0_ptr = ConstantExpr::getIntToPtr(CONSTp(&cpu->tc->jmp_offset[0]), getPointerType());
	Value *tc_jmp1_ptr = ConstantExpr::getIntToPtr(CONSTp(&cpu->tc->jmp_offset[1]), getPointerType());
	Value *tc_flg_ptr = ConstantExpr::getIntToPtr(CONSTp(&cpu->tc->flags), getPointerType());

	switch (n)
	{
	case 1: {
		if (next_pc) { // if(dst_pc) -> cond jmp dst_pc; if(next_pc) -> cond jmp next_pc
			if (dst) {
				BasicBlock *bb0 = getBB();
				BasicBlock *bb1 = getBB();
				BR_COND(bb0, bb1, ICMP_EQ(target_addr, CONST32(dst_pc)));
				cpu->bb = bb0;
				ST(tc_flg_ptr, AND(LD(tc_flg_ptr, getIntegerType(32)), CONST32(~TC_FLG_JMP_TAKEN)));
				CallInst *ci = CALL_tail(main_ty, LD(tc_jmp0_ptr, getPointerType()), cpu->ptr_cpu_ctx);
				ReturnInst::Create(CTX(), ci, cpu->bb);
				cpu->bb = bb1;
				ST(tc_flg_ptr, OR(AND(LD(tc_flg_ptr, getIntegerType(32)), CONST32(~TC_FLG_JMP_TAKEN)), CONST32(TC_JMP_RET << 4)));
			}
			else {
				BasicBlock *bb0 = getBB();
				BasicBlock *bb1 = getBB();
				BR_COND(bb0, bb1, ICMP_EQ(target_addr, CONST32(*next_pc)));
				cpu->bb = bb0;
				ST(tc_flg_ptr, OR(AND(LD(tc_flg_ptr, getIntegerType(32)), CONST32(~TC_FLG_JMP_TAKEN)), CONST32(TC_JMP_NEXT_PC << 4)));
				CallInst *ci = CALL_tail(main_ty, LD(tc_jmp1_ptr, getPointerType()), cpu->ptr_cpu_ctx);
				ReturnInst::Create(CTX(), ci, cpu->bb);
				cpu->bb = bb1;
				ST(tc_flg_ptr, OR(AND(LD(tc_flg_ptr, getIntegerType(32)), CONST32(~TC_FLG_JMP_TAKEN)), CONST32(TC_JMP_RET << 4)));
			}
		}
		else { // uncond jmp dst_pc
			CallInst *ci = CALL_tail(main_ty, LD(tc_jmp0_ptr, getPointerType()), cpu->ptr_cpu_ctx);
			ReturnInst::Create(CTX(), ci, cpu->bb);
			cpu->bb = getBB();
			ABORT("Unreachable code in link_direct_emit reached with n = 1");
		}
	}
	break;

	case 2: { // cond jmp next_pc + uncond jmp dst_pc
		BasicBlock *bb0 = getBB();
		BasicBlock *bb1 = getBB();
		BasicBlock *bb2 = getBB();
		BR_COND(bb0, bb1, ICMP_EQ(target_addr, CONST32(*next_pc)));
		cpu->bb = bb0;
		ST(tc_flg_ptr, OR(AND(LD(tc_flg_ptr, getIntegerType(32)), CONST32(~TC_FLG_JMP_TAKEN)), CONST32(TC_JMP_NEXT_PC << 4)));
		CallInst *ci1 = CALL_tail(main_ty, LD(tc_jmp1_ptr, getPointerType()), cpu->ptr_cpu_ctx);
		ReturnInst::Create(CTX(), ci1, cpu->bb);
		cpu->bb = bb1;
		ST(tc_flg_ptr, AND(LD(tc_flg_ptr, getIntegerType(32)), CONST32(~TC_FLG_JMP_TAKEN)));
		CallInst *ci2 = CALL_tail(main_ty, LD(tc_jmp0_ptr, getPointerType()), cpu->ptr_cpu_ctx);
		ReturnInst::Create(CTX(), ci2, cpu->bb);
		cpu->bb = bb2;
		ABORT("Unreachable code in link_direct_emit reached with n = 2");
	}
	break;

	default:
		LIB86CPU_ABORT();
	}
}

void
link_dst_only_emit(cpu_t *cpu)
{
	if (check_rf_single_step_emit(cpu)) {
		return;
	}

	// make sure we check for interrupts before jumping to the next tc
	check_int_emit(cpu);

	cpu->tc->flags |= (1 & TC_FLG_NUM_JMP);

	FunctionType *main_ty = cpu->bb->getParent()->getFunctionType();
	Value *tc_jmp0_ptr = ConstantExpr::getIntToPtr(CONSTp(&cpu->tc->jmp_offset[0]), getPointerType());
	CallInst *ci = CALL_tail(main_ty, LD(tc_jmp0_ptr, getPointerType()), cpu->ptr_cpu_ctx);
	ReturnInst::Create(CTX(), ci, cpu->bb);
}

entry_t
link_indirect_handler(cpu_ctx_t *cpu_ctx, translated_code_t *tc)
{
	const auto it = cpu_ctx->cpu->ibtc.find(get_pc(cpu_ctx));

	if (it != cpu_ctx->cpu->ibtc.end()) {
		if (it->second->cs_base == cpu_ctx->regs.cs_hidden.base &&
			it->second->cpu_flags == ((cpu_ctx->hflags & HFLG_CONST) | (cpu_ctx->regs.eflags & EFLAGS_CONST)) &&
			((it->second->virt_pc & ~PAGE_MASK) == (tc->virt_pc & ~PAGE_MASK))) {
			return it->second->ptr_code;
		}
	}

	return tc->jmp_offset[2];
}

template<fn_emit_t fn_type>
static Function *
gen_fn(cpu_t *cpu)
{
	cpu->cpu_ctx_type = StructType::create(CTX(), "struct.cpu_ctx_t");
	StructType *type_exp_data_t = StructType::create(CTX(),
		{ getIntegerType(32), getIntegerType(16), getIntegerType(16), getIntegerType(32) }, "struct.exp_data_t", false);

	StructType *type_exp_info_t = StructType::create(CTX(),
		{ type_exp_data_t, getIntegerType(16) }, "struct.exp_info_t", false);

	cpu->cpu_ctx_type->setBody({
		getPointerType(),       // cpu struct
		get_struct_reg(cpu),
		StructType::create(CTX(), { getIntegerType(32), getIntegerType(32), getArrayType(getIntegerType(8), 256) }, "struct.eflags_t", false),
		getIntegerType(32),
		getArrayType(getIntegerType(32), TLB_MAX_SIZE),
		getArrayType(getIntegerType(16), TLB_MAX_SIZE),
		getArrayType(getIntegerType(16), IOTLB_MAX_SIZE),
		getPointerType(),
		type_exp_info_t,
		getIntegerType(8)
		}, false);

	cpu->reg_ty = cpu->cpu_ctx_type->getTypeAtIndex(1);
	cpu->eflags_ty = cpu->cpu_ctx_type->getTypeAtIndex(2);

	Function *func = nullptr;
	if constexpr (constexpr bool type_match = fn_type == fn_emit_t::main_t) {
		FunctionType *type_entry_t = FunctionType::get(
			getPointerType(),       // tc ret
			getPointerType(),       // cpu_ctx
			false);

		func = Function::Create(
			type_entry_t,                        // func type
			GlobalValue::ExternalLinkage,        // linkage
			"main",                              // name
			cpu->mod);
#if defined(_WIN64) && defined(_MSC_VER)
		func->setCallingConv(CallingConv::Win64);
#elif defined(_WIN32) && defined(_MSC_VER)
		func->setCallingConv(CallingConv::C);
#else
#error Unknow calling convention for gen_fn
#endif
	}
	else if constexpr (fn_type == fn_emit_t::int_t) {
		FunctionType *type_int_t = FunctionType::get(
			getVoidType(),                               // void ret
			{ getPointerType(), getIntegerType(8) },     // cpu_ctx, int flag
			false);

		func = Function::Create(
			type_int_t,                      // func type
			GlobalValue::ExternalLinkage,    // linkage
			"cpu_raise_interrupt",           // name
			cpu->mod);
#if defined(_WIN64) && defined(_MSC_VER)
		func->setCallingConv(CallingConv::Win64);
#elif defined(_WIN32) && defined(_MSC_VER)
		func->setCallingConv(CallingConv::C);
#else
#error Unknow calling convention for gen_fn
#endif
	}
	else {
		static_assert(type_match, "Unknown function type to emit!");
	}

	return func;
}

void
create_tc_prologue(cpu_t *cpu)
{
	// create the translation function, it will hold all the translated code
	Function *func = gen_fn<fn_emit_t::main_t>(cpu);

	cpu->bb = BasicBlock::Create(CTX(), "", func, 0);
	cpu->ptr_cpu_ctx = cpu->bb->getParent()->arg_begin();
	cpu->ptr_cpu_ctx->setName("cpu_ctx");
	cpu->ptr_regs = GEP(cpu->ptr_cpu_ctx, cpu->cpu_ctx_type, 1);
	cpu->ptr_regs->setName("regs");
	cpu->ptr_eflags = GEP(cpu->ptr_cpu_ctx, cpu->cpu_ctx_type, 2);
	cpu->ptr_eflags->setName("eflags");
	cpu->ptr_hflags = GEP(cpu->ptr_cpu_ctx, cpu->cpu_ctx_type, 3);
	cpu->ptr_hflags->setName("hflags");
	cpu->ptr_tlb = GEP(cpu->ptr_cpu_ctx, cpu->cpu_ctx_type, 4);
	cpu->ptr_tlb->setName("tlb");
	cpu->ptr_tlb_region_idx = GEP(cpu->ptr_cpu_ctx, cpu->cpu_ctx_type, 5);
	cpu->ptr_tlb_region_idx->setName("tlb_region_idx");
	cpu->ptr_iotlb = GEP(cpu->ptr_cpu_ctx, cpu->cpu_ctx_type, 6);
	cpu->ptr_iotlb->setName("iotlb");
	cpu->ptr_ram = LD(GEP(cpu->ptr_cpu_ctx, cpu->cpu_ctx_type, 7), getPointerType());
	cpu->ptr_ram->setName("ram");
}

void
gen_int_fn(cpu_t *cpu)
{
	// the interrupt function should never be generated more than once per emulation session

	cpu->ctx = new LLVMContext();
	if (cpu->ctx == nullptr) {
		LIB86CPU_ABORT();
	}
	cpu->mod = new Module(cpu->cpu_name, *cpu->ctx);
	cpu->mod->setDataLayout(*cpu->dl);
	if (cpu->mod == nullptr) {
		LIB86CPU_ABORT();
	}

	Function *func = gen_fn<fn_emit_t::int_t>(cpu);

	cpu->bb = BasicBlock::Create(CTX(), "", func, 0);
	cpu->tc = nullptr;

	ST_ATOMIC(GEP(func->arg_begin(), cpu->cpu_ctx_type, 9), func->arg_begin() + 1, AtomicOrdering::Monotonic, 1);
	ReturnInst::Create(CTX(), cpu->bb);

	if (cpu->cpu_flags & CPU_PRINT_IR) {
		std::string str;
		raw_string_ostream os(str);
		os << *cpu->mod;
		os.flush();
		LOG(log_level::debug, str.c_str());
	}

	if (cpu->cpu_flags & CPU_CODEGEN_OPTIMIZE) {
		optimize(cpu);
		if (cpu->cpu_flags & CPU_PRINT_IR_OPTIMIZED) {
			std::string str;
			raw_string_ostream os(str);
			os << *cpu->mod;
			os.flush();
			LOG(log_level::debug, str.c_str());
		}
	}

	orc::ThreadSafeContext tsc(std::unique_ptr<LLVMContext>(cpu->ctx));
	orc::ThreadSafeModule tsm(std::unique_ptr<Module>(cpu->mod), tsc);
	cpu->jit->add_ir_module(std::move(tsm));
	cpu->int_fn = reinterpret_cast<raise_int_t>(cpu->jit->lookup("cpu_raise_interrupt")->getAddress());
	assert(cpu->int_fn);
	cpu->jit->remove_symbols("cpu_raise_interrupt");
	cpu->tc = nullptr;
	cpu->bb = nullptr;
}

void
create_tc_epilogue(cpu_t *cpu)
{
	Value *tc_ptr1 = new IntToPtrInst(CONSTp(cpu->tc), cpu->bb->getParent()->getReturnType(), "", cpu->bb);
	ReturnInst::Create(CTX(), tc_ptr1, cpu->bb);

	// create the function that returns to the translator
	Function *exit = Function::Create(
		cpu->bb->getParent()->getFunctionType(),  // func type
		GlobalValue::ExternalLinkage,             // linkage
		"exit",                                   // name
		cpu->mod);
#if defined(_WIN64) && defined(_MSC_VER)
	exit->setCallingConv(CallingConv::Win64);
#elif defined(_WIN32) && defined(_MSC_VER)
	exit->setCallingConv(CallingConv::C);
#else
#error Unknow calling convention for create_tc_epilogue
#endif

	BasicBlock *bb = BasicBlock::Create(CTX(), "", exit, 0);
	Value *tc_ptr2 = new IntToPtrInst(CONSTp(cpu->tc), exit->getReturnType(), "", bb);
	ReturnInst::Create(CTX(), tc_ptr2, bb);
}

void
raise_exp_inline_emit(cpu_t *cpu, Value *fault_addr, Value *code, Value *idx, Value *eip)
{
	GetElementPtrInst *gep1 = GetElementPtrInst::CreateInBounds(cpu->cpu_ctx_type, cpu->ptr_cpu_ctx, { CONST32(0), CONST32(8) }, "", cpu->bb);
	GetElementPtrInst *gep2 = GetElementPtrInst::CreateInBounds(gep1->getResultElementType(), gep1, { CONST32(0), CONST32(0) }, "", cpu->bb);
	Value *ptr_exp_data = gep2;
	ST(GEP(ptr_exp_data, gep2->getResultElementType(), 0), fault_addr);
	ST(GEP(ptr_exp_data, gep2->getResultElementType(), 1), code);
	ST(GEP(ptr_exp_data, gep2->getResultElementType(), 2), idx);
	ST(GEP(ptr_exp_data, gep2->getResultElementType(), 3), eip);
	CallInst *ci = CALL(cpu->ptr_exp_fn->getFunctionType(), cpu->ptr_exp_fn, cpu->ptr_cpu_ctx);
	ReturnInst::Create(CTX(), ci, cpu->bb);
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

BasicBlock *
raise_exception_emit(cpu_t *cpu, Value *fault_addr, Value *code, Value *idx, Value *eip)
{
	BasicBlock *bb_exp = BasicBlock::Create(CTX(), "", cpu->bb->getParent(), 0);
	BasicBlock *bb = cpu->bb;
	cpu->bb = bb_exp;
	raise_exp_inline_emit(cpu, fault_addr, code, idx, eip);
	cpu->bb = bb;
	return bb_exp;
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

Value *
io_read_emit(cpu_t *cpu, Value *port, const unsigned size_mode)
{
	static const uint8_t fn_io_idx[3] = { IO_LD32_idx, IO_LD16_idx, IO_LD8_idx };
	static const uint8_t op_size_to_mem_size[3] = { 4, 2, 1 };
	const unsigned size = op_size_to_mem_size[size_mode];

	BasicBlock *bb0 = getBB();
	BasicBlock *bb1 = getBB();
	BasicBlock *bb2 = getBB();
	Value *ret = ALLOCs(size * 8);
	Value *iotlb_idx1 = SHR(port, CONST16(IO_SHIFT));
	Value *iotlb_idx2 = SHR(SUB(ADD(port, CONST16(size)), CONST16(1)), CONST16(IO_SHIFT));
	Value *iotlb_entry = LD(GEP(cpu->ptr_iotlb, cpu->cpu_ctx_type->getTypeAtIndex(6), iotlb_idx1), getIntegerType(16));

	// interrogate the iotlb
	// this checks if the last byte of the read is in the same io entry as the first (port + size - 1)
	// reads that cross io entries or that reside in an entry where a watchpoint is installed always result in iotlb misses
	BR_COND(bb0, bb1, ICMP_EQ(XOR(OR(AND(iotlb_entry, CONST16(IOTLB_VALID | IOTLB_WATCH)), SHL(iotlb_idx1, CONST16(IO_SHIFT))),
		OR(CONST16(IOTLB_VALID), SHL(iotlb_idx2, CONST16(IO_SHIFT)))), CONST16(0)));

	// iotlb hit
	cpu->bb = bb0;
	FunctionType *type_io_read_t = FunctionType::get(
		getIntegerType(64),                                                            // ret
		{ getIntegerType(32), getIntegerType(sizeof(size_t) * 8), getPointerType() },  // port, size, opaque
		false);
	StructType *type_io_t = StructType::create(CTX(), {
		getPointerType(),  // NOTE: opaque io region struct
		getPointerType(),
		getPointerType(),  // NOTE: opaque io write func
		getPointerType()   // NOTE: opaque io value
		}, "", false);

	Value *io_ptr = INT2PTR(getPointerType(), CONSTs(cpu->dl->getPointerSize() * 8, reinterpret_cast<uintptr_t>(&cpu->iotlb_regions_ptr)));
	GetElementPtrInst *gep = GetElementPtrInst::CreateInBounds(type_io_t, LD(io_ptr, getPointerType()), SHR(iotlb_entry, CONST16(IO_SHIFT)), "", cpu->bb);
	Value *io = gep;
	ST(ret, TRUNCs(size * 8, CALL(type_io_read_t, LD(GEP(io, gep->getResultElementType(), 1), getPointerType()), ZEXT32(port),
		CONSTs(sizeof(size_t) * 8, size), LD(GEP(io, gep->getResultElementType(), 3), getPointerType()))));
	BR_UNCOND(bb2);

	// iotlb miss
	cpu->bb = bb1;
	ST(ret, CALL(cpu->ptr_mem_ldfn[fn_io_idx[size_mode]]->getFunctionType(), cpu->ptr_mem_ldfn[fn_io_idx[size_mode]], cpu->ptr_cpu_ctx, port));
	BR_UNCOND(bb2);

	cpu->bb = bb2;
	return LD(ret, getIntegerType(size * 8));
}

void
io_write_emit(cpu_t *cpu, Value *port, Value *value, const unsigned size_mode)
{
	static const uint8_t fn_io_idx[3] = { IO_LD32_idx, IO_LD16_idx, IO_LD8_idx };
	static const uint8_t op_size_to_mem_size[3] = { 4, 2, 1 };
	const unsigned size = op_size_to_mem_size[size_mode];

	BasicBlock *bb0 = getBB();
	BasicBlock *bb1 = getBB();
	BasicBlock *bb2 = getBB();
	Value *iotlb_idx1 = SHR(port, CONST16(IO_SHIFT));
	Value *iotlb_idx2 = SHR(SUB(ADD(port, CONST16(size)), CONST16(1)), CONST16(IO_SHIFT));
	Value *iotlb_entry = LD(GEP(cpu->ptr_iotlb, cpu->cpu_ctx_type->getTypeAtIndex(6), iotlb_idx1), getIntegerType(16));

	// interrogate the iotlb
	// this checks if the last byte of the write is in the same io entry as the first (port + size - 1)
	// writes that cross io entries or that reside in an entry where a watchpoint is installed always result in iotlb misses
	BR_COND(bb0, bb1, ICMP_EQ(XOR(OR(AND(iotlb_entry, CONST16(IOTLB_VALID | IOTLB_WATCH)), SHL(iotlb_idx1, CONST16(IO_SHIFT))),
		OR(CONST16(IOTLB_VALID), SHL(iotlb_idx2, CONST16(IO_SHIFT)))), CONST16(0)));

	// iotlb hit
	cpu->bb = bb0;
	FunctionType *type_io_write_t = FunctionType::get(
		getVoidType(),                                                                                     // void ret
		{ getIntegerType(32), getIntegerType(sizeof(size_t) * 8), getIntegerType(64), getPointerType() },  // port, size, val, opaque
		false);
	StructType *type_io_t = StructType::create(CTX(), {
		getPointerType(),  // NOTE: opaque io region struct
		getPointerType(),  // NOTE: opaque io read func
		getPointerType(),
		getPointerType()   // NOTE: opaque io value
		}, "", false);

	Value *io_ptr = INT2PTR(getPointerType(), CONSTs(cpu->dl->getPointerSize() * 8, reinterpret_cast<uintptr_t>(&cpu->iotlb_regions_ptr)));
	GetElementPtrInst *gep = GetElementPtrInst::CreateInBounds(type_io_t, LD(io_ptr, getPointerType()), SHR(iotlb_entry, CONST16(IO_SHIFT)), "", cpu->bb);
	Value *io = gep;
	CALL(type_io_write_t, LD(GEP(io, gep->getResultElementType(), 2), getPointerType()), ZEXT32(port),
		CONSTs(sizeof(size_t) * 8, size), ZEXT64(value), LD(GEP(io, gep->getResultElementType(), 3), getPointerType()));
	BR_UNCOND(bb2);

	// iotlb miss
	cpu->bb = bb1;
	CALL(cpu->ptr_mem_stfn[fn_io_idx[size_mode]]->getFunctionType(), cpu->ptr_mem_stfn[fn_io_idx[size_mode]], cpu->ptr_cpu_ctx, port, value);
	BR_UNCOND(bb2);

	cpu->bb = bb2;
}

void
check_io_priv_emit(cpu_t *cpu, Value *port, uint8_t size_mode)
{
	static const uint8_t op_size_to_mem_size[3] = { 4, 2, 1 };

	if ((cpu->cpu_ctx.hflags & HFLG_PE_MODE) && ((cpu->cpu_ctx.hflags & HFLG_CPL) > ((cpu->cpu_ctx.regs.eflags & IOPL_MASK) >> 12))) {
		BasicBlock *bb0 = getBB();
		BasicBlock *bb1 = getBB();
		BasicBlock *bb2 = getBB();
		BasicBlock *bb_exp = RAISE0(EXP_GP);
		Value *base = LD_SEG_HIDDEN(TR_idx, SEG_BASE_idx);
		Value *limit = LD_SEG_HIDDEN(TR_idx, SEG_LIMIT_idx);
		BR_COND(bb_exp, bb0, ICMP_ULT(limit, CONST32(103)));
		cpu->bb = bb0;
		Value *io_map_offset = LD_MEM(MEM_LD16_idx, ADD(base, CONST32(102)));
		Value *io_port_offset = ADD(ZEXT32(io_map_offset), SHR(port, CONST32(3)));
		BR_COND(bb_exp, bb1, ICMP_UGT(ADD(io_port_offset, CONST32(1)), limit));
		cpu->bb = bb1;
		Value *temp, *value = ALLOC32();
		temp = LD_MEM(MEM_LD16_idx, ADD(base, io_port_offset));
		ST(value, ZEXT32(temp));
		ST(value, SHR(LD(value, getIntegerType(32)), AND(port, CONST32(7))));
		BR_COND(bb_exp, bb2, ICMP_NE(AND(LD(value, getIntegerType(32)), CONST32((1 << op_size_to_mem_size[size_mode]) - 1)), CONST32(0)));
		cpu->bb = bb2;
	}
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

Value *
get_immediate_op(cpu_t *cpu, ZydisDecodedInstruction *instr, uint8_t idx, uint8_t size_mode)
{
	assert(instr->operands[idx].type == ZYDIS_OPERAND_TYPE_IMMEDIATE);
	Value *value;

	switch (size_mode)
	{
	case SIZE8:
		value = CONST8(instr->operands[idx].imm.value.u);
		break;

	case SIZE16:
		value = CONST16(instr->operands[idx].imm.value.u);
		break;

	case SIZE32:
		value = CONST32(instr->operands[idx].imm.value.u);
		break;

	default:
		LIB86CPU_ABORT_msg("Invalid size_mode \"%c\" used in %s", size_mode, __func__);
	}

	return value;
}

Value *
get_register_op(cpu_t *cpu, ZydisDecodedInstruction *instr, uint8_t idx)
{
	assert(instr->operands[idx].type == ZYDIS_OPERAND_TYPE_REGISTER);
	return get_operand(cpu, instr, idx);
}

void
set_flags_sum(cpu_t *cpu, Value *sum, Value *a, Value *b, uint8_t size_mode)
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
		LIB86CPU_ABORT_msg("Invalid size_mode \"%c\" used in %s", size_mode, __func__);
	}
}

void
set_flags_sub(cpu_t *cpu, Value *sub, Value *a, Value *b, uint8_t size_mode)
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
		LIB86CPU_ABORT_msg("Invalid size_mode \"%c\" used in %s", size_mode, __func__);
	}
}

void
set_flags(cpu_t *cpu, Value *res, Value *aux, uint8_t size_mode)
{
	size_mode == SIZE32 ? ST_FLG_RES(res) : ST_FLG_RES_ext(res);
	ST_FLG_AUX(aux);
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

Value *
get_operand(cpu_t *cpu, ZydisDecodedInstruction *instr, const unsigned opnum)
{
	ZydisDecodedOperand *operand = &instr->operands[opnum];

	switch (operand->type)
	{
	case ZYDIS_OPERAND_TYPE_MEMORY:
	{
		switch (operand->encoding)
		{
		case ZYDIS_OPERAND_ENCODING_DISP16_32_64:
			return ADD(CONST32(operand->mem.disp.value), LD_SEG_HIDDEN(GET_REG_idx(operand->mem.segment), SEG_BASE_idx));

		case ZYDIS_OPERAND_ENCODING_MODRM_RM: {
			Value *base, *temp, *disp;
			if (instr->address_width == 32) {
				if (operand->mem.base != ZYDIS_REGISTER_NONE) {
					base = LD_R32(GET_REG_idx(operand->mem.base));
				}
				else {
					base = CONST32(0);
				}

				if (operand->mem.scale != 0) {
					temp = ADD(base, MUL(LD_R32(GET_REG_idx(operand->mem.index)), CONST32(operand->mem.scale)));
				}
				else {
					temp = base;
				}

				if (operand->mem.disp.has_displacement) {
					if (instr->raw.modrm.mod == 1) {
						disp = SEXT32(CONST8(operand->mem.disp.value));
					}
					else {
						disp = CONST32(operand->mem.disp.value);
					}
					
					return ADD(ADD(temp, disp), LD_SEG_HIDDEN(GET_REG_idx(operand->mem.segment), SEG_BASE_idx));
				}
				
				return ADD(temp, LD_SEG_HIDDEN(GET_REG_idx(operand->mem.segment), SEG_BASE_idx));
			}
			else {
				if (operand->mem.base != ZYDIS_REGISTER_NONE) {
					base = LD_R16(GET_REG_idx(operand->mem.base));
				}
				else {
					base = CONST16(0);
				}

				if (operand->mem.scale != 0) {
					temp = ADD(base, MUL(LD_R16(GET_REG_idx(operand->mem.index)), CONST16(operand->mem.scale)));
				}
				else {
					temp = base;
				}

				if (operand->mem.disp.has_displacement) {
					if (instr->raw.modrm.mod == 1) {
						disp = SEXT16(CONST8(operand->mem.disp.value));
					}
					else {
						disp = CONST16(operand->mem.disp.value);
					}

					return ADD(ZEXT32(ADD(temp, disp)), LD_SEG_HIDDEN(GET_REG_idx(operand->mem.segment), SEG_BASE_idx));
				}

				return ADD(ZEXT32(temp), LD_SEG_HIDDEN(GET_REG_idx(operand->mem.segment), SEG_BASE_idx));
			}
		}
		break;

		default:
			LIB86CPU_ABORT_msg("Unhandled mem operand encoding %d in %s", operand->encoding, __func__);
		}
	}
	break;

	case ZYDIS_OPERAND_TYPE_REGISTER: {
		int idx = GET_REG_idx(operand->reg.value);
		switch (operand->size)
		{
		case 8: {
			ZyanU8 reg8;
			switch (operand->encoding)
			{
			case ZYDIS_OPERAND_ENCODING_MODRM_RM:
				reg8 = instr->raw.modrm.rm;
				break;

			case ZYDIS_OPERAND_ENCODING_MODRM_REG:
				reg8 = instr->raw.modrm.reg;
				break;

			case ZYDIS_OPERAND_ENCODING_OPCODE:
				reg8 = instr->opcode & 7;
				break;

			case ZYDIS_OPERAND_ENCODING_NONE:
				assert(operand->reg.value == ZYDIS_REGISTER_AL ||
					operand->reg.value == ZYDIS_REGISTER_AX ||
					operand->reg.value == ZYDIS_REGISTER_EAX);
				reg8 = 0;
				break;

			default:
				LIB86CPU_ABORT_msg("Unhandled reg operand encoding %d in %s", operand->encoding, __func__);
			}

			if (reg8 < 4) {
				auto reg_ptr = GetElementPtrInst::CreateInBounds(getRegType(), cpu->ptr_regs, { CONST32(0), CONST32(idx) }, "", cpu->bb);
				return GetElementPtrInst::CreateInBounds(getIntegerType(8), reg_ptr, CONST32(0), "", cpu->bb);
			}
			else {
				return GEP_R8H(idx);
			}
		}

		case 16: {
			auto reg_ptr = GetElementPtrInst::CreateInBounds(getRegType(), cpu->ptr_regs, { CONST32(0), CONST32(idx) }, "", cpu->bb);
			return GetElementPtrInst::CreateInBounds(getIntegerType(16), reg_ptr, CONST32(0), "", cpu->bb);
		}

		case 32:
			return GEP_REG_idx(idx);

		default:
			LIB86CPU_ABORT();
		}
	}
	break;

	case ZYDIS_OPERAND_TYPE_POINTER:
		LIB86CPU_ABORT_msg("Segment and offset of pointer type operand should be read directly by the translator instead of from %s", __func__);
		break;

	case ZYDIS_OPERAND_TYPE_IMMEDIATE: {
		switch (operand->encoding)
		{
		case ZYDIS_OPERAND_ENCODING_UIMM16:
			return CONST16(operand->imm.value.u);

		case ZYDIS_OPERAND_ENCODING_UIMM8:
		case ZYDIS_OPERAND_ENCODING_JIMM8:
			return CONST8(operand->imm.value.u);

		case ZYDIS_OPERAND_ENCODING_JIMM16_32_32:
			return (operand->size == 32) ? CONST32(operand->imm.value.u) : CONST16(operand->imm.value.u);

		default:
			LIB86CPU_ABORT_msg("Unhandled imm operand encoding %d in %s", operand->encoding, __func__);
		}
	}

	default:
		LIB86CPU_ABORT_msg("Unhandled operand type specified");
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
