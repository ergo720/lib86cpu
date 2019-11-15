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
#include "lib86cpu.h"
#include "x86_frontend.h"
#include "x86_internal.h"

#define getIntegerType(x) (IntegerType::get(_CTX(), x))
#define getVoidType() (Type::getVoidTy(_CTX()))

#define CONSTs(s,v) ConstantInt::get(getIntegerType(s), v)
#define CONST1(v) CONSTs(1,v)
#define CONST8(v) CONSTs(8,v)
#define CONST16(v) CONSTs(16,v)
#define CONST32(v) CONSTs(32,v)

#define ADD(a,b) BinaryOperator::Create(Instruction::Add, a, b, "", bb)


static StructType *
get_struct_reg(cpu_t *cpu, translated_code_t *tc)
{
	std::vector<Type *>type_struct_reg_t_fields;
	std::vector<Type *>type_struct_seg_t_fields;
	std::vector<Type *>type_struct_hiddenseg_t_fields;

	type_struct_hiddenseg_t_fields.push_back(getIntegerType(32));
	StructType *type_struct_hiddenseg_t = StructType::create(_CTX(), type_struct_hiddenseg_t_fields, "struct.hiddenseg_t", false);

	type_struct_seg_t_fields.push_back(getIntegerType(16));
	type_struct_seg_t_fields.push_back(type_struct_hiddenseg_t);
	StructType *type_struct_seg_t = StructType::create(_CTX(), type_struct_seg_t_fields, "struct.seg_t", false);

	for (uint8_t n = 0; n < CPU_NUM_REGS; n++) {
		switch (n)
		{
			case ES_idx:
			case CS_idx:
			case SS_idx:
			case DS_idx:
			case FS_idx:
			case GS_idx: {
				type_struct_reg_t_fields.push_back(type_struct_seg_t);
			}
			break;

			default:
				type_struct_reg_t_fields.push_back(getIntegerType(cpu->regs_layout[n].bits_size));
		}
	}

	return StructType::create(_CTX(), type_struct_reg_t_fields, "struct.regs_t", false);
}

static Value *
get_struct_member_pointer(Value *gep_start, const unsigned gep_index, translated_code_t *tc, BasicBlock *bb)
{
	std::vector<Value *> ptr_11_indices;
	ptr_11_indices.push_back(CONST32(0));
	ptr_11_indices.push_back(CONST32(gep_index));
	return static_cast<Value *>(GetElementPtrInst::CreateInBounds(gep_start, ptr_11_indices, "", bb));
}

#define GEP(ptr, idx)  (get_struct_member_pointer(ptr, idx, tc, bb))
#define GEP_EAX()      (GEP(cpu->ptr_regs, EAX_idx))
#define GEP_ECX()      (GEP(cpu->ptr_regs, ECX_idx))
#define GEP_EDX()      (GEP(cpu->ptr_regs, EDX_idx))
#define GEP_EBX()      (GEP(cpu->ptr_regs, EBX_idx))
#define GEP_ESP()      (GEP(cpu->ptr_regs, ESP_idx))
#define GEP_EBP()      (GEP(cpu->ptr_regs, EBP_idx))
#define GEP_ESI()      (GEP(cpu->ptr_regs, ESI_idx))
#define GEP_EDI()      (GEP(cpu->ptr_regs, EDI_idx))
#define GEP_CR0()      (GEP(cpu->ptr_regs, CR0_idx))
#define GEP_CR1()      (GEP(cpu->ptr_regs, CR1_idx))
#define GEP_CR2()      (GEP(cpu->ptr_regs, CR2_idx))
#define GEP_CR3()      (GEP(cpu->ptr_regs, CR3_idx))
#define GEP_CR4()      (GEP(cpu->ptr_regs, CR4_idx))
#define GEP_DR0()      (GEP(cpu->ptr_regs, DR0_idx))
#define GEP_DR1()      (GEP(cpu->ptr_regs, DR1_idx))
#define GEP_DR2()      (GEP(cpu->ptr_regs, DR2_idx))
#define GEP_DR3()      (GEP(cpu->ptr_regs, DR3_idx))
#define GEP_DR4()      (GEP(cpu->ptr_regs, DR4_idx))
#define GEP_DR5()      (GEP(cpu->ptr_regs, DR5_idx))
#define GEP_DR6()      (GEP(cpu->ptr_regs, DR6_idx))
#define GEP_DR7()      (GEP(cpu->ptr_regs, DR7_idx))
#define GEP_EFLAGS()   (GEP(cpu->ptr_regs, EFLAGS_idx))
#define GEP_EIP()      (GEP(cpu->ptr_regs, EIP_idx))

static void
calc_next_pc_emit(cpu_t *cpu, translated_code_t *tc, BasicBlock *bb, disas_ctx_t *disas_ctx)
{
	Value *next_eip = ADD(CONST32(cpu->regs.eip), CONST32(disas_ctx->tc_instr_size));
	new StoreInst(next_eip, GEP_EIP(), bb);
	disas_ctx->next_pc = ADD(CONST32(cpu->regs.cs_hidden.base), next_eip);
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

Function *
create_tc_prologue(cpu_t *cpu, translated_code_t *tc)
{
	PointerType *type_pi8 = PointerType::get(getIntegerType(8), 0);           // ram ptr
	StructType *type_struct_reg_t = get_struct_reg(cpu, tc);
	PointerType *type_pstruct_reg_t = PointerType::get(type_struct_reg_t, 0); // regs_t ptr

	std::vector<Type *> type_func_args;
	type_func_args.push_back(type_pi8);
	type_func_args.push_back(type_pstruct_reg_t);

	FunctionType *type_func = FunctionType::get(
		getVoidType(),    // void ret
		type_func_args,   // args
		false);

	// create the tranlsation function
	Function *func = Function::Create(
		type_func,                     // func type
		GlobalValue::ExternalLinkage,  // linkage
		"main",                        // name
		tc->mod);
	func->setCallingConv(CallingConv::C);
	func->addAttribute(1U, Attribute::NoCapture);

	Function::arg_iterator args = func->arg_begin();
	cpu->ptr_ram = args++;
	cpu->ptr_ram->setName("ram");
	cpu->ptr_regs = args++;
	cpu->ptr_regs->setName("regs");

	return func;
}

Function *
create_tc_epilogue(cpu_t *cpu, translated_code_t *tc, Function *func, disas_ctx_t *disas_ctx)
{
	IntegerType *type_i32 = getIntegerType(32);  // pc ptr
	std::vector<Type *> type_func_args;
	type_func_args.push_back(type_i32);

	FunctionType *type_func = FunctionType::get(
		getVoidType(),    // void ret
		type_func_args,   // args
		false);

	// create the tail function
	Function *tail = Function::Create(
		type_func,                     // func type
		GlobalValue::ExternalLinkage,  // linkage
		"tail",                        // name
		tc->mod);
	tail->setCallingConv(CallingConv::Fast);

	// create the bb of the tail function
	BasicBlock *bb = BasicBlock::Create(_CTX(), "", tail, 0);

	// emit some dummy instructions, these will be replaced by jumps when we link this tc to another
	FunctionType *type_func_asm = FunctionType::get(
		getVoidType(),  // void ret
		// no args
		false);

#if defined __i386 || defined _M_IX86

	InlineAsm *ia = InlineAsm::get(type_func_asm, "mov ecx, $$-1\n\tmov ecx, $$-2\n\tmov ecx, $$-3\n\tmov ecx, $$-4", "~{ecx}", true, false, InlineAsm::AsmDialect::AD_Intel);
	CallInst::Create(ia, "", bb);

#else
#error don't know how to construct the tc epilogue on this platform
#endif

	ReturnInst::Create(_CTX(), bb);

	// emit code to calculate the pc if required
	if (disas_ctx->emit_pc_code) {
		calc_next_pc_emit(cpu, tc, &func->getEntryBlock(), disas_ctx);
	}

	// insert a call to the tail function and a ret instr for the translation function
	CallInst *ci = CallInst::Create(tail, disas_ctx->next_pc, "", &func->getEntryBlock());
	ci->setCallingConv(CallingConv::Fast);
	ReturnInst::Create(_CTX(), &func->getEntryBlock());

	// finally, verify that the generated functions are good
	verifyFunction(*tail, &errs());
	verifyFunction(*func, &errs());

	return tail;
}
