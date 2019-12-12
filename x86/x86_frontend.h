/*
 * x86 llvm frontend exports to translator
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once


Value *get_struct_member_pointer(Value *gep_start, const unsigned gep_index, translated_code_t *tc, BasicBlock *bb);
Value * get_r8h_pointer(Value *gep_start, translated_code_t *tc, BasicBlock *bb);

void get_ext_fn(cpu_t *cpu, translated_code_t *tc);
FunctionType * create_tc_fntype(cpu_t *cpu, translated_code_t *tc);
Function *create_tc_prologue(cpu_t *cpu, translated_code_t *tc, FunctionType *fntype, uint64_t func_idx);
Function *create_tc_epilogue(cpu_t *cpu, translated_code_t *tc, FunctionType *fntype, disas_ctx_t *disas_ctx, uint64_t func_idx);
void optimize(translated_code_t *tc, Function *func);
Value *get_operand(cpu_t *cpu, x86_instr *instr, translated_code_t *tc, BasicBlock *bb, unsigned opnum, uint8_t addr_mode);
Value *calc_next_pc_emit(cpu_t *cpu, translated_code_t *tc, BasicBlock *bb, size_t instr_size);


#define _CTX() (*tc->ctx)
#define getIntegerType(x) (IntegerType::get(_CTX(), x))
#define getVoidType() (Type::getVoidTy(_CTX()))
#define getIntegerArrayType(x, n) (ArrayType::get(getIntegerType(x), n))

#define MEM_LD8_idx  0
#define MEM_LD16_idx 1
#define MEM_LD32_idx 2
#define IO_LD8_idx   3
#define IO_LD16_idx  4
#define IO_LD32_idx  5
#define MEM_ST8_idx  0
#define MEM_ST16_idx 1
#define MEM_ST32_idx 2
#define IO_ST8_idx   3
#define IO_ST16_idx  4
#define IO_ST32_idx  5

#define GET_OP(op) get_operand(cpu, &instr, tc, bb, op, addr_mode)

#define GET_RM(idx, r, m) 	rm = GET_OP(idx); \
switch (instr.operand[idx].type) \
{ \
case OPTYPE_REG: \
	r \
	break; \
\
case OPTYPE_MEM: \
case OPTYPE_MEM_DISP: \
case OPTYPE_SIB_MEM: \
case OPTYPE_SIB_DISP: \
	m \
	break; \
\
default: \
	UNREACHABLE; \
}

#define CONSTs(s, v) ConstantInt::get(getIntegerType(s), v)
#define CONST1(v) CONSTs(1, v)
#define CONST8(v) CONSTs(8, v)
#define CONST16(v) CONSTs(16, v)
#define CONST32(v) CONSTs(32, v)
#define CONST64(v) CONSTs(64, v)

#define ZEXT(s, v) new ZExtInst(v, getIntegerType(s), "", bb)
#define ZEXT8(v) ZEXT(8, v)
#define ZEXT16(v) ZEXT(16, v)
#define ZEXT32(v) ZEXT(32, v)
#define ZEXT64(v) ZEXT(64, v)

#define SEXT(s, v) new SExtInst(v, getIntegerType(s), "", bb)
#define SEXT8(v) SEXT(8, v)
#define SEXT16(v) SEXT(16, v)
#define SEXT32(v) SEXT(32, v)
#define SEXT64(v) SEXT(64, v)

#define IBITCASTs(s, v) new BitCastInst(v, PointerType::getUnqual(getIntegerType(s)), "", bb)
#define IBITCAST8(v) IBITCASTs(8, v)
#define IBITCAST16(v) IBITCASTs(16, v)
#define IBITCAST32(v) IBITCASTs(32, v)

#define TRUNCs(s,v) new TruncInst(v, getIntegerType(s), "", bb)
#define TRUNC8(v) TRUNCs(8, v)
#define TRUNC16(v) TRUNCs(16, v)
#define TRUNC32(v) TRUNCs(32, v)

#define ADD(a,b) BinaryOperator::Create(Instruction::Add, a, b, "", bb)
#define SUB(a,b) BinaryOperator::Create(Instruction::Sub, a, b, "", bb)
#define MUL(a,b) BinaryOperator::Create(Instruction::Mul, a, b, "", bb)
#define UDIV(a,b) BinaryOperator::Create(Instruction::UDiv, a, b, "", bb)
#define UREM(a,b) BinaryOperator::Create(Instruction::URem, a, b, "", bb)
#define AND(a,b) BinaryOperator::Create(Instruction::And, a, b, "", bb)
#define XOR(a,b) BinaryOperator::Create(Instruction::Xor, a, b, "", bb)
#define OR(a,b) BinaryOperator::Create(Instruction::Or, a, b, "", bb)
#define NOT(a) BinaryOperator::CreateNot(a, "", bb)
#define SHR(a,sh) BinaryOperator::Create(Instruction::LShr, a, sh, "", bb)
#define SHL(a,sh) BinaryOperator::Create(Instruction::Shl, a, sh, "", bb)
#define BR_COND(t, f, val, bb) BranchInst::Create(t, f, val, bb)
#define BR_UNCOND(t, bb) BranchInst::Create(t, bb)
#define ICMP_EQ(a, b) new ICmpInst(*bb, ICmpInst::ICMP_EQ, a, b, "")
#define ICMP_NE(a, b) new ICmpInst(*bb, ICmpInst::ICMP_NE, a, b, "")
#define NOT_ZERO(s,v) AND(SHR(OR(v, SUB(CONSTs(s, 0), v)), CONSTs(s, s-1)), CONSTs(s, 1))

#define GEP(ptr, idx)  get_struct_member_pointer(ptr, idx, tc, bb)
#define GEP_R32(idx)   GEP(cpu->ptr_regs, idx)
#define GEP_R16(idx)   IBITCAST16(GEP(cpu->ptr_regs, idx))
#define GEP_R8L(idx)   IBITCAST8(GEP(cpu->ptr_regs, idx))
#define GEP_R8H(idx)   get_r8h_pointer(IBITCAST8(GEP(cpu->ptr_regs, idx)), tc, bb)
#define GEP_SEL(idx)   GEP(GEP(cpu->ptr_regs, idx), SEG_SEL_idx)
#define GEP_EAX()      GEP_R32(EAX_idx)
#define GEP_ECX()      GEP_R32(ECX_idx)
#define GEP_EDX()      GEP_R32(EDX_idx)
#define GEP_EBX()      GEP_R32(EBX_idx)
#define GEP_ESP()      GEP_R32(ESP_idx)
#define GEP_EBP()      GEP_R32(EBP_idx)
#define GEP_ESI()      GEP_R32(ESI_idx)
#define GEP_EDI()      GEP_R32(EDI_idx)
#define GEP_ES()       GEP_SEL(ES_idx)
#define GEP_CS()       GEP_SEL(CS_idx)
#define GEP_SS()       GEP_SEL(SS_idx)
#define GEP_DS()       GEP_SEL(DS_idx)
#define GEP_FS()       GEP_SEL(FS_idx)
#define GEP_GS()       GEP_SEL(GS_idx)
#define GEP_CR0()      GEP_R32(CR0_idx)
#define GEP_CR1()      GEP_R32(CR1_idx)
#define GEP_CR2()      GEP_R32(CR2_idx)
#define GEP_CR3()      GEP_R32(CR3_idx)
#define GEP_CR4()      GEP_R32(CR4_idx)
#define GEP_DR0()      GEP_R32(DR0_idx)
#define GEP_DR1()      GEP_R32(DR1_idx)
#define GEP_DR2()      GEP_R32(DR2_idx)
#define GEP_DR3()      GEP_R32(DR3_idx)
#define GEP_DR4()      GEP_R32(DR4_idx)
#define GEP_DR5()      GEP_R32(DR5_idx)
#define GEP_DR6()      GEP_R32(DR6_idx)
#define GEP_DR7()      GEP_R32(DR7_idx)
#define GEP_EFLAGS()   GEP_R32(EFLAGS_idx)
#define GEP_EIP()      GEP_R32(EIP_idx)
#define GEP_PARITY()   GEP(cpu->ptr_eflags, 2)

#define ST_R32(val, idx) new StoreInst(val, GEP(cpu->ptr_regs, idx), bb)
#define ST_R16(val, idx) new StoreInst(val, GEP_R16(idx), bb)
#define ST_R8L(val, idx) new StoreInst(val, GEP_R8L(idx), bb)
#define ST_REG_val(val, reg) new StoreInst(val, reg, bb)
#define ST_SEG(val, seg) new StoreInst(val, GEP_SEL(seg), bb)
#define ST_SEG_HIDDEN(val, seg, idx) new StoreInst(val, GEP(GEP(GEP(cpu->ptr_regs, seg), SEG_HIDDEN_idx), idx), bb)
#define LD_R32(idx) new LoadInst(GEP(cpu->ptr_regs, idx), "", false, bb)
#define LD_R16(idx) new LoadInst(GEP_R16(idx), "", false, bb)
#define LD_R8L(idx) new LoadInst(GEP_R8L(idx), "", false, bb)
#define LD_R8H(idx) new LoadInst(GEP_R8H(idx), "", false, bb)
#define LD_REG_val(reg) new LoadInst(reg, "", false, bb)
#define LD_SEG(seg) new LoadInst(GEP_SEL(seg), "", false, bb)
#define LD_SEG_HIDDEN(seg, idx) new LoadInst(GEP(GEP(GEP(cpu->ptr_regs, seg), SEG_HIDDEN_idx), idx), "", false, bb)

#define LD_MEM(idx, addr) CallInst::Create(cpu->ptr_mem_ldfn[idx], std::vector<Value *> { cpu->ptr_cpu, addr }, "", bb)
#define ST_MEM(idx, addr, val) CallInst::Create(cpu->ptr_mem_stfn[idx], std::vector<Value *> { cpu->ptr_cpu, addr, val }, "", bb)

#define LD_PARITY(idx) new LoadInst(GetElementPtrInst::CreateInBounds(GEP_PARITY(), std::vector<Value *> { CONST8(0), idx }, "", bb), "", false, bb)

#define RAISE(expno, eip) CallInst::Create(cpu->exp_fn, std::vector<Value *> { cpu->ptr_cpu, CONST8(expno), CONST32(eip) }, "", bb)

// the lazy eflags idea comes from reading these two papers:
// How Bochs Works Under the Hood (2nd edition) http://bochs.sourceforge.net/How%20the%20Bochs%20works%20under%20the%20hood%202nd%20edition.pdf
// A Proposal for Hardware-Assisted Arithmetic Overflow Detection for Array and Bitfield Operations http://www.emulators.com/docs/LazyOverflowDetect_Final.pdf
#define SUM_COUT_VEC(a, b, s) OR(AND(a, b), AND(OR(a, b), NOT(s)))
#define SUB_COUT_VEC(a, b, d) OR(AND(NOT(a), b), AND(NOT(XOR(a, b)), d))
#define MASK_FLG8(a) AND(OR(SHL(a, CONST32(24)), a), CONST32(0xC0000008))
#define MASK_FLG16(a) AND(OR(SHL(a, CONST32(16)), a), CONST32(0xC0000008))
#define MASK_FLG32(a) AND(a, CONST32(0xC0000008))
#define GEN_SUM_VEC8(a, b, r) MASK_FLG8(ZEXT32(SUM_COUT_VEC(a, b, r)))
#define GEN_SUM_VEC16(a, b, r) MASK_FLG16(ZEXT32(SUM_COUT_VEC(a, b, r)))
#define GEN_SUM_VEC32(a, b, r) MASK_FLG32(SUM_COUT_VEC(a, b, r))
#define GEN_SUB_VEC8(a, b, r) MASK_FLG8(ZEXT32(SUB_COUT_VEC(a, b, r)))
#define GEN_SUB_VEC16(a, b, r) MASK_FLG16(ZEXT32(SUB_COUT_VEC(a, b, r)))
#define GEN_SUB_VEC32(a, b, r) MASK_FLG32(SUB_COUT_VEC(a, b, r))
#define ST_FLG_SUM_AUX8(a, b, r) new StoreInst(GEN_SUM_VEC8(a, b, r), GEP(cpu->ptr_eflags, 1), bb)
#define ST_FLG_SUM_AUX16(a, b, r) new StoreInst(GEN_SUM_VEC16(a, b, r), GEP(cpu->ptr_eflags, 1), bb)
#define ST_FLG_SUM_AUX32(a, b, r) new StoreInst(GEN_SUM_VEC32(a, b, r), GEP(cpu->ptr_eflags, 1), bb)
#define ST_FLG_SUB_AUX8(a, b, r) new StoreInst(GEN_SUB_VEC8(a, b, r), GEP(cpu->ptr_eflags, 1), bb)
#define ST_FLG_SUB_AUX16(a, b, r) new StoreInst(GEN_SUB_VEC16(a, b, r), GEP(cpu->ptr_eflags, 1), bb)
#define ST_FLG_SUB_AUX32(a, b, r) new StoreInst(GEN_SUB_VEC32(a, b, r), GEP(cpu->ptr_eflags, 1), bb)
#define ST_FLG_AUX(val) new StoreInst(val, GEP(cpu->ptr_eflags, 1), bb)
#define ST_FLG_RES_ext(val) new StoreInst(SEXT32(val), GEP(cpu->ptr_eflags, 0), bb)
#define ST_FLG_RES(val) new StoreInst(val, GEP(cpu->ptr_eflags, 0), bb)
#define LD_FLG_RES() new LoadInst(GEP(cpu->ptr_eflags, 0), "", false, bb)
#define LD_FLG_AUX() new LoadInst(GEP(cpu->ptr_eflags, 1), "", false, bb)
#define LD_CF() AND(LD_FLG_AUX(), CONST32(0x80000000))
#define LD_OF() AND(XOR(LD_FLG_AUX(), SHL(LD_FLG_AUX(), CONST32(1))), CONST32(0x80000000))
#define LD_ZF() LD_FLG_RES()
#define LD_SF() XOR(SHR(LD_FLG_RES(), CONST32(31)), AND(LD_FLG_AUX(), CONST32(1)))
#define LD_PF() LD_PARITY(TRUNC8(XOR(LD_FLG_RES(), SHR(LD_FLG_AUX(), CONST32(8)))))
