/*
 * x86 llvm frontend exports to translator
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once


Value *get_struct_member_pointer(Value *gep_start, const unsigned gep_index, translated_code_t *tc, BasicBlock *bb);
Value * get_r8h_pointer(Value *gep_start, translated_code_t *tc, BasicBlock *bb);

void get_mem_fn(cpu_t *cpu, translated_code_t *tc);
Function *create_tc_prologue(cpu_t *cpu, translated_code_t *tc);
Function *create_tc_epilogue(cpu_t *cpu, translated_code_t *tc, Function *func, disas_ctx_t *disas_ctx);
void optimize(translated_code_t *tc, Function *func);
Value *get_operand(cpu_t *cpu, x86_instr *instr, translated_code_t *tc, BasicBlock *bb, unsigned opnum, uint8_t addr_mode);


#define _CTX() (*tc->ctx)
#define getIntegerType(x) (IntegerType::get(_CTX(), x))
#define getVoidType() (Type::getVoidTy(_CTX()))

#define MEM_LD8_idx  0
#define MEM_LD16_idx 1
#define MEM_LD32_idx 2

#define GET_OP(n, m) get_operand(cpu, &instr, tc, bb, n, m)

#define CONSTs(s, v) ConstantInt::get(getIntegerType(s), v)
#define CONST1(v) CONSTs(1, v)
#define CONST8(v) CONSTs(8, v)
#define CONST16(v) CONSTs(16, v)
#define CONST32(v) CONSTs(32, v)

#define ZEXT(s, v) new ZExtInst(v, getIntegerType(s), "", bb)
#define ZEXT8(v) ZEXT(8, v)
#define ZEXT16(v) ZEXT(16, v)
#define ZEXT32(v) ZEXT(32, v)

#define SEXT(s, v) new SExtInst(v, getIntegerType(s), "", bb)
#define SEXT8(v) SEXT(8, v)
#define SEXT16(v) SEXT(16, v)
#define SEXT32(v) SEXT(32, v)

#define IBITCASTs(s, v) new BitCastInst(v, PointerType::getUnqual(getIntegerType(s)), "", bb)
#define IBITCAST8(v) IBITCASTs(8, v)
#define IBITCAST16(v) IBITCASTs(16, v)
#define IBITCAST32(v) IBITCASTs(32, v)

#define TRUNCs(s,v) new TruncInst(v, getIntegerType(s), "", bb)
#define TRUNC8(v) TRUNCs(8, v)
#define TRUNC16(v) TRUNCs(16, v)
#define TRUNC32(v) TRUNCs(32, v)

#define ADD(a,b) BinaryOperator::Create(Instruction::Add, a, b, "", bb)
#define MUL(a,b) BinaryOperator::Create(Instruction::Mul, a, b, "", bb)
#define AND(a,b) BinaryOperator::Create(Instruction::And, a, b, "", bb)
#define SHR(a,sh) BinaryOperator::Create(Instruction::LShr, a, sh, "", bb)
#define SHL(a,sh) BinaryOperator::Create(Instruction::Shl, a, sh, "", bb)

#define GEP(ptr, idx)  get_struct_member_pointer(ptr, idx, tc, bb)
#define GEP_R32(idx)   GEP(cpu->ptr_regs, idx)
#define GEP_R16(idx)   IBITCAST16(GEP(cpu->ptr_regs, idx))
#define GEP_R8L(idx)   IBITCAST8(GEP(cpu->ptr_regs, idx))
#define GEP_R8H(idx)   get_r8h_pointer(IBITCAST8(GEP(cpu->ptr_regs, idx)), tc, bb) // XXX untested!
#define GEP_EAX()      GEP_R32(EAX_idx)
#define GEP_ECX()      GEP_R32(ECX_idx)
#define GEP_EDX()      GEP_R32(EDX_idx)
#define GEP_EBX()      GEP_R32(EBX_idx)
#define GEP_ESP()      GEP_R32(ESP_idx)
#define GEP_EBP()      GEP_R32(EBP_idx)
#define GEP_ESI()      GEP_R32(ESI_idx)
#define GEP_EDI()      GEP_R32(EDI_idx)
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

#define ST_REG(val, idx) new StoreInst(val, GEP(cpu->ptr_regs, idx), bb)
#define ST_SEG(val, seg) new StoreInst(val, GEP(GEP(cpu->ptr_regs, seg), SEG_SEL_idx), bb)
#define ST_SEG_HIDDEN(val, seg, idx) new StoreInst(val, GEP(GEP(GEP(cpu->ptr_regs, seg), SEG_HIDDEN_idx), idx), bb)
#define LD_REG(idx) new LoadInst(GEP(cpu->ptr_regs, idx), "", false, bb)
#define LD_R16(idx) new LoadInst(GEP_R16(idx), "", false, bb)
#define LD_SEG(seg) new LoadInst(GEP(GEP(cpu->ptr_regs, seg), SEG_SEL_idx), "", false, bb)
#define LD_SEG_HIDDEN(seg, idx) new LoadInst(GEP(GEP(GEP(cpu->ptr_regs, seg), SEG_HIDDEN_idx), idx), "", false, bb)
