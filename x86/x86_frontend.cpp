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
#include "x86_internal.h"
#include "x86_frontend.h"
#include "x86_memory.h"


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

void
get_mem_fn(cpu_t *cpu, translated_code_t *tc)
{
	// NOTE: trying to pass a void* results in an assertion failure in getOrInsertFunction ("Invalid type for pointer element!"). Reading online resources,
	// this seems to be because llvm doesn't support the void* type. Instead, this is usually handled by passing a i8* instead so we do that way

	static size_t bit_size[3] = { 8, 16, 32 };
	static const char *func_name[3] = { "mem_read8", "mem_read16", "mem_read32" };

	for (uint8_t i = 0; i < 3; i++) {
		cpu->ptr_mem_ldfn[i] = cast<Function>(tc->mod->getOrInsertFunction(func_name[i], getIntegerType(bit_size[i]), PointerType::get(getIntegerType(8), 0), getIntegerType(32)));
	}
}

Function *
create_tc_prologue(cpu_t *cpu, translated_code_t *tc, uint64_t func_idx)
{
	PointerType *type_pi8 = PointerType::get(getIntegerType(8), 0);            // cpu ptr
	StructType *type_struct_reg_t = get_struct_reg(cpu, tc);
	PointerType *type_pstruct_reg_t = PointerType::get(type_struct_reg_t, 0);  // regs_t ptr

	std::vector<Type *> type_func_args;
	type_func_args.push_back(type_pi8);
	type_func_args.push_back(type_pstruct_reg_t);

	FunctionType *type_func = FunctionType::get(
		getVoidType(),    // void ret
		type_func_args,   // args
		false);

	// create the tranlsation function
	Function *func = Function::Create(
		type_func,                           // func type
		GlobalValue::ExternalLinkage,        // linkage
		"main_" + std::to_string(func_idx),  // name
		tc->mod);
	func->setCallingConv(CallingConv::C);
	func->addAttribute(1U, Attribute::NoCapture);

	Function::arg_iterator args = func->arg_begin();
	cpu->ptr_cpu = args++;
	cpu->ptr_cpu->setName("cpu");
	cpu->ptr_regs = args++;
	cpu->ptr_regs->setName("regs");

	return func;
}

Function *
create_tc_epilogue(cpu_t *cpu, translated_code_t *tc, Function *func, disas_ctx_t *disas_ctx, uint64_t func_idx)
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
		type_func,                           // func type
		GlobalValue::ExternalLinkage,        // linkage
		"tail_" + std::to_string(func_idx),  // name
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
	tc->jmp_code_size = 20;

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

Value *
get_operand(cpu_t *cpu, x86_instr *instr , translated_code_t *tc, BasicBlock *bb, unsigned opnum, uint8_t addr_mode)
{
	assert(opnum < OPNUM_COUNT && "Invalid operand number specified\n");

	x86_operand *operand = &instr->operand[opnum];

	switch (operand->type) {
	case OPTYPE_IMM:
		if (instr->flags & (SRC_IMM8 | OP3_IMM8)) {
			return CONST8(operand->imm);
		}
		else if (instr->flags & DST_IMM16) {
			return CONST16(operand->imm);
		}
		switch (instr->flags & WIDTH_MASK) {
		case WIDTH_BYTE:
			return CONST8(operand->imm);
		case WIDTH_WORD:
			return CONST16(operand->imm);
		case WIDTH_DWORD:
			return CONST32(operand->imm);
		default:
			assert(0 && "Missing operand size in OPTYPE_IMM (calling %s on an instruction without operands?)\n");
			return nullptr;
		}
	case OPTYPE_MEM:
		if (addr_mode == ADDR32) {
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
			return ADD(LD_REG(reg_idx), LD_SEG_HIDDEN(instr->seg + SEG_offset, SEG_BASE_idx));
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
		if (instr->addr_size_override ^ CPU_PE_MODE) {
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
				reg = ADD(LD_REG(reg_idx), SEXT32(CONST8(operand->disp)));
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
				reg = ADD(LD_REG(reg_idx), CONST32(operand->disp));
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
			assert(0 && "Missing operand size in OPTYPE_REL (calling %s on an instruction without operands?)\n", __func__);
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
			idx = LD_REG(instr->idx);
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
			base = LD_REG(instr->base);
			break;
		case 5:
			switch (instr->mod) {
			case 0:
				return ADD(ADD(MUL(idx, scale), CONST32(instr->disp)), LD_SEG_HIDDEN(instr->seg + SEG_offset, SEG_BASE_idx));
			case 1:
				return ADD(ADD(ADD(MUL(idx, scale), SEXT32(CONST8(operand->disp))), LD_REG(EBP_idx)), LD_SEG_HIDDEN(instr->seg + SEG_offset, SEG_BASE_idx));
			case 2:
				return ADD(ADD(ADD(MUL(idx, scale), CONST32(operand->disp)), LD_REG(EBP_idx)), LD_SEG_HIDDEN(instr->seg + SEG_offset, SEG_BASE_idx));
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
