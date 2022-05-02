/*
 * x86 llvm frontend exports to translator
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once


std::vector<BasicBlock *> gen_bbs(cpu_t *cpu, const unsigned num);
void gen_exp_fn(cpu_t *cpu);
void optimize(cpu_t *cpu);
void get_ext_fn(cpu_t *cpu);
StructType *get_struct_reg(cpu_t *cpu);
StructType *get_struct_eflags(cpu_t *cpu);
Value *gep_emit(cpu_t *cpu, Value *gep_start, const int gep_index);
Value *gep_emit(cpu_t *cpu, Value *gep_start, Value *gep_index);
Value *gep_emit(cpu_t *cpu, Value *gep_start, const std::vector<Value *> &vec_index);
Value *get_r8h_pointer(cpu_t *cpu, Value *gep_start);
Value *get_operand(cpu_t *cpu, ZydisDecodedInstruction *instr, const unsigned opnum);
int get_reg_idx(ZydisRegister reg);
int get_seg_prfx_idx(ZydisDecodedInstruction *instr);
Value *mem_read_emit(cpu_t *cpu, Value *addr, const unsigned idx, const unsigned is_priv);
void mem_write_emit(cpu_t *cpu, Value *addr, Value *value, const unsigned idx, const unsigned is_priv);
void check_io_priv_emit(cpu_t *cpu, Value *port, uint8_t size_mode);
void stack_push_emit(cpu_t *cpu, const std::vector<Value *> &vec, uint32_t size_mode);
std::vector<Value *> stack_pop_emit(cpu_t *cpu, uint32_t size_mode, const unsigned num, const unsigned pop_at = 0);
void link_direct_emit(cpu_t *cpu, const std::vector<addr_t> &vec_addr, Value *target_addr);
void link_dst_only_emit(cpu_t *cpu);
Value *calc_next_pc_emit(cpu_t *cpu, size_t instr_size);
Value *floor_division_emit(cpu_t *cpu, Value *D, Value *d, size_t q_bits);
void raise_exp_inline_emit(cpu_t *cpu, const std::vector<Value *> &exp_data);
BasicBlock *raise_exception_emit(cpu_t *cpu, const std::vector<Value *> &exp_data);
void lcall_pe_emit(cpu_t *cpu, std::vector<Value *> vec, uint8_t size_mode, uint32_t ret_eip);
void ljmp_pe_emit(cpu_t *cpu, Value *sel, uint8_t size_mode, uint32_t eip);
void ret_pe_emit(cpu_t *cpu, uint8_t size_mode, bool is_iret);
std::vector<Value *> check_ss_desc_priv_emit(cpu_t *cpu, Value *sel, Value *cs = nullptr, Value *cpl = nullptr, BasicBlock *bb_exp = nullptr);
std::vector<Value *> check_seg_desc_priv_emit(cpu_t *cpu, Value *sel);
void set_access_flg_seg_desc_emit(cpu_t *cpu, Value *desc, Value *desc_addr);
std::vector<Value *> read_seg_desc_emit(cpu_t *cpu, Value *sel, BasicBlock *bb_exp = nullptr);
Value *read_seg_desc_base_emit(cpu_t *cpu, Value *desc);
Value *read_seg_desc_limit_emit(cpu_t *cpu, Value *desc);
Value *read_seg_desc_flags_emit(cpu_t *cpu, Value *desc);
std::vector<Value *> read_tss_desc_emit(cpu_t *cpu, Value *sel);
std::vector<Value *> read_stack_ptr_from_tss_emit(cpu_t *cpu, Value *cpl, BasicBlock *bb_exp = nullptr);
void write_seg_reg_emit(cpu_t *cpu, const unsigned reg, const std::vector<Value *> &vec);
Value *get_immediate_op(cpu_t *cpu, ZydisDecodedInstruction *instr, uint8_t idx, uint8_t size_mode);
Value *get_register_op(cpu_t *cpu, ZydisDecodedInstruction *instr, uint8_t idx);
void set_flags_sum(cpu_t *cpu, const std::vector<Value *> &vec, uint8_t size_mode);
void set_flags_sub(cpu_t *cpu, const std::vector<Value *> &vec, uint8_t size_mode);
void set_flags(cpu_t *cpu, Value *res, Value *aux, uint8_t size_mode);
void update_fpu_state_after_mmx_emit(cpu_t *cpu, int idx, Value *tag, bool is_write);
void write_eflags(cpu_t *cpu, Value *eflags, Value *mask);
void hook_emit(cpu_t *cpu, hook *obj);


#define CTX() (*cpu->ctx)
#define getBB() BasicBlock::Create(CTX(), "", cpu->bb->getParent(), 0)
#define getBBs(n) gen_bbs(cpu, n)
#define getIntegerType(x) (IntegerType::get(CTX(), x))
#define getPointerType(x) (PointerType::getUnqual(x))
#define getIntegerPointerType() (cpu->dl->getIntPtrType(CTX()))
#define getVoidType() (Type::getVoidTy(CTX()))
#define getArrayType(x, n) (ArrayType::get(x, n))

#define MEM_LD8_idx  0
#define MEM_LD16_idx 1
#define MEM_LD32_idx 2
#define MEM_LD64_idx 3
#define IO_LD8_idx   4
#define IO_LD16_idx  5
#define IO_LD32_idx  6
#define MEM_ST8_idx  0
#define MEM_ST16_idx 1
#define MEM_ST32_idx 2
#define MEM_ST64_idx 3
#define IO_ST8_idx   4
#define IO_ST16_idx  5
#define IO_ST32_idx  6

#define GET_REG_idx(reg) get_reg_idx(reg)
#define GET_IMM() get_immediate_op(cpu, &instr, OPNUM_SRC, size_mode)
#define GET_IMM8() get_immediate_op(cpu, &instr, OPNUM_SRC, SIZE8)
#define GET_REG(idx) get_register_op(cpu, &instr, idx)
#define GET_OP(op) get_operand(cpu, &instr, op)
#define GET_RM(idx, r, m) 	rm = GET_OP(idx); \
switch (instr.operands[idx].type) \
{ \
case ZYDIS_OPERAND_TYPE_REGISTER: \
	r \
	break; \
\
case ZYDIS_OPERAND_TYPE_MEMORY: \
	m \
	break; \
\
default: \
	LIB86CPU_ABORT_msg("Invalid operand type used in GET_RM macro!"); \
}

#define INTPTR(v) ConstantInt::get(getIntegerPointerType(), reinterpret_cast<uintptr_t>(v))
#define CONSTs(s, v) ConstantInt::get(getIntegerType(s), v)
#define CONST1(v) CONSTs(1, v)
#define CONST8(v) CONSTs(8, v)
#define CONST16(v) CONSTs(16, v)
#define CONST32(v) CONSTs(32, v)
#define CONST64(v) CONSTs(64, v)

#define ALLOC(ty) new AllocaInst(ty, 0, "", cpu->bb)
#define ALLOCs(s) ALLOC(getIntegerType(s))
#define ALLOC8() ALLOCs(8)
#define ALLOC16() ALLOCs(16)
#define ALLOC32() ALLOCs(32)
#define ALLOC64() ALLOCs(64)

#define ST(ptr, v) new StoreInst(v, ptr, cpu->bb)
#define LD(ptr) new LoadInst(ptr, "", false, cpu->bb)

#define UNREACH() new UnreachableInst(CTX(), cpu->bb)
#define INTRINSIC(id) CallInst::Create(Intrinsic::getDeclaration(cpu->mod, Intrinsic::id), "", cpu->bb)
#define INTRINSIC_ty(id, ty, arg) CallInst::Create(Intrinsic::getDeclaration(cpu->mod, Intrinsic::id, ty), arg, "", cpu->bb)

#define ZEXTs(s, v) new ZExtInst(v, getIntegerType(s), "", cpu->bb)
#define ZEXT8(v) ZEXTs(8, v)
#define ZEXT16(v) ZEXTs(16, v)
#define ZEXT32(v) ZEXTs(32, v)
#define ZEXT64(v) ZEXTs(64, v)

#define SEXTs(s, v) new SExtInst(v, getIntegerType(s), "", cpu->bb)
#define SEXT8(v) SEXTs(8, v)
#define SEXT16(v) SEXTs(16, v)
#define SEXT32(v) SEXTs(32, v)
#define SEXT64(v) SEXTs(64, v)

#define IBITCASTs(s, v) new BitCastInst(v, getPointerType(getIntegerType(s)), "", cpu->bb)
#define IBITCAST8(v) IBITCASTs(8, v)
#define IBITCAST16(v) IBITCASTs(16, v)
#define IBITCAST32(v) IBITCASTs(32, v)

#define TRUNCs(s,v) new TruncInst(v, getIntegerType(s), "", cpu->bb)
#define TRUNC8(v) TRUNCs(8, v)
#define TRUNC16(v) TRUNCs(16, v)
#define TRUNC32(v) TRUNCs(32, v)

#define ADD(a, b) BinaryOperator::Create(Instruction::Add, a, b, "", cpu->bb)
#define SUB(a, b) BinaryOperator::Create(Instruction::Sub, a, b, "", cpu->bb)
#define MUL(a, b) BinaryOperator::Create(Instruction::Mul, a, b, "", cpu->bb)
#define UDIV(a, b) BinaryOperator::Create(Instruction::UDiv, a, b, "", cpu->bb)
#define SDIV(a, b) BinaryOperator::Create(Instruction::SDiv, a, b, "", cpu->bb)
#define FLOOR_DIV(a, b, bits) floor_division_emit(cpu, a, b, bits)
#define UREM(a, b) BinaryOperator::Create(Instruction::URem, a, b, "", cpu->bb)
#define SREM(a, b) BinaryOperator::Create(Instruction::SRem, a, b, "", cpu->bb)
#define AND(a, b) BinaryOperator::Create(Instruction::And, a, b, "", cpu->bb)
#define XOR(a, b) BinaryOperator::Create(Instruction::Xor, a, b, "", cpu->bb)
#define OR(a, b) BinaryOperator::Create(Instruction::Or, a, b, "", cpu->bb)
#define NOT(a) BinaryOperator::CreateNot(a, "", cpu->bb)
#define NEG(a) BinaryOperator::CreateNeg(a, "", cpu->bb)
#define ASHR(a, sh) BinaryOperator::Create(Instruction::AShr, a, sh, "", cpu->bb)
#define SHR(a, sh) BinaryOperator::Create(Instruction::LShr, a, sh, "", cpu->bb)
#define SHL(a, sh) BinaryOperator::Create(Instruction::Shl, a, sh, "", cpu->bb)
#define BR_COND(t, f, val) BranchInst::Create(t, f, val, cpu->bb)
#define BR_UNCOND(t) BranchInst::Create(t, cpu->bb)
#define ICMP_EQ(a, b) new ICmpInst(*cpu->bb, ICmpInst::ICMP_EQ, a, b, "")
#define ICMP_NE(a, b) new ICmpInst(*cpu->bb, ICmpInst::ICMP_NE, a, b, "")
#define ICMP_UGT(a, b) new ICmpInst(*cpu->bb, ICmpInst::ICMP_UGT, a, b, "")
#define ICMP_UGE(a, b) new ICmpInst(*cpu->bb, ICmpInst::ICMP_UGE, a, b, "")
#define ICMP_ULT(a, b) new ICmpInst(*cpu->bb, ICmpInst::ICMP_ULT, a, b, "")
#define ICMP_ULE(a, b) new ICmpInst(*cpu->bb, ICmpInst::ICMP_ULE, a, b, "")
#define ICMP_SGE(a, b) new ICmpInst(*cpu->bb, ICmpInst::ICMP_SGE, a, b, "")
#define ICMP_SGT(a, b) new ICmpInst(*cpu->bb, ICmpInst::ICMP_SGT, a, b, "")
#define ICMP_SLT(a, b) new ICmpInst(*cpu->bb, ICmpInst::ICMP_SLT, a, b, "")
#define NOT_ZERO(s, v) AND(SHR(OR(v, SUB(CONSTs(s, 0), v)), CONSTs(s, s-1)), CONSTs(s, 1))
#define SWITCH_new(n, v, def) SwitchInst::Create(v, def, n, cpu->bb)
#define SWITCH_add(s, v, bb) addCase(CONSTs(s, v), bb)
#define INT2PTR(ty, v) new IntToPtrInst(v, ty, "", cpu->bb)

#define GEP(ptr, idx)  gep_emit(cpu, ptr, idx)
#define GEP_R32(idx)   GEP(cpu->ptr_regs, idx)
#define GEP_R16(idx)   IBITCAST16(GEP(cpu->ptr_regs, idx))
#define GEP_R8L(idx)   IBITCAST8(GEP(cpu->ptr_regs, idx))
#define GEP_R8H(idx)   get_r8h_pointer(cpu, IBITCAST8(GEP(cpu->ptr_regs, idx)))
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

#define ST_R32(val, idx) ST(GEP_R32(idx), val)
#define ST_R16(val, idx) ST(GEP_R16(idx), val)
#define ST_R8L(val, idx) ST(GEP_R8L(idx), val)
#define ST_R8H(val, idx) ST(GEP_R8H(idx), val)
#define ST_REG_val(val, reg) ST(reg, val)
#define ST_SEG(val, seg) ST(GEP_SEL(seg), val)
#define ST_SEG_HIDDEN(val, seg, idx) ST(GEP(GEP(GEP(cpu->ptr_regs, seg), SEG_HIDDEN_idx), idx), val)
#define ST_MM64(val, idx) ST(GEP(GEP(cpu->ptr_regs, idx), F80_LOW_idx), val)
#define ST_MM_HIGH(val, idx) ST(GEP(GEP(cpu->ptr_regs, idx), F80_HIGH_idx), val)
#define LD_R32(idx) LD(GEP_R32(idx))
#define LD_R16(idx) LD(GEP_R16(idx))
#define LD_R8L(idx) LD(GEP_R8L(idx))
#define LD_R8H(idx) LD(GEP_R8H(idx))
#define LD_REG_val(reg) LD(reg)
#define LD_SEG(seg) LD(GEP_SEL(seg))
#define LD_SEG_HIDDEN(seg, idx) LD(GEP(GEP(GEP(cpu->ptr_regs, seg), SEG_HIDDEN_idx), idx))
#define LD_MM32(idx) LD(IBITCAST32(GEP(GEP(cpu->ptr_regs, idx), F80_LOW_idx)))

#define LD_MEM(idx, addr) mem_read_emit(cpu, addr, idx, 0)
#define ST_MEM(idx, addr, val) mem_write_emit(cpu, addr, val, idx, 0)
#define LD_MEM_PRIV(idx, addr) mem_read_emit(cpu, addr, idx, 2)
#define ST_MEM_PRIV(idx, addr, val) mem_write_emit(cpu, addr, val, idx, 2)
#define MEM_PUSH(vec) stack_push_emit(cpu, vec, size_mode)
#define MEM_POP(n) stack_pop_emit(cpu, size_mode, n)
#define MEM_POP_AT(n, at) stack_pop_emit(cpu, size_mode, n, at)
#define LD_IO(idx, port) CallInst::Create(cpu->ptr_mem_ldfn[idx], std::vector<Value *> { cpu->ptr_cpu_ctx, port }, "", cpu->bb)
#define ST_IO(idx, port, val) CallInst::Create(cpu->ptr_mem_stfn[idx], std::vector<Value *> { cpu->ptr_cpu_ctx, port, val }, "", cpu->bb)

#define LD_PARITY(idx) LD(GetElementPtrInst::CreateInBounds(GEP_PARITY(), std::vector<Value *> { CONST32(0), idx }, "", cpu->bb))
#define RAISE(code, idx) raise_exception_emit(cpu, std::vector<Value *> { CONST32(0), code, CONST16(idx), cpu->instr_eip })
#define RAISE0(idx) raise_exception_emit(cpu, std::vector<Value *> { CONST32(0), CONST16(0), CONST16(idx), cpu->instr_eip })
#define RAISEin(addr, code, idx, eip) raise_exp_inline_emit(cpu, std::vector<Value *> { CONST32(addr), CONST16(code), CONST16(idx), CONST32(eip) }); \
cpu->bb = getBBs(1)[0]
#define RAISEin0(idx) raise_exp_inline_emit(cpu, std::vector<Value *> { CONST32(0), CONST16(0), CONST16(idx), cpu->instr_eip }); \
cpu->bb = getBBs(1)[0]
#define SET_FLG_SUM(sum, a, b) set_flags_sum(cpu, std::vector<Value *> { sum, a , b }, size_mode)
#define SET_FLG_SUB(sub, a, b) set_flags_sub(cpu, std::vector<Value *> { sub, a , b }, size_mode)
#define SET_FLG(res, aux) set_flags(cpu, res, aux, size_mode)
#define UPDATE_FPU_AFTER_MMX(tag, idx, w) update_fpu_state_after_mmx_emit(cpu, idx, tag, w)
#define UPDATE_FPU_AFTER_MMX_w(tag, idx) UPDATE_FPU_AFTER_MMX(tag, idx, true)
#define UPDATE_FPU_AFTER_MMX_r(tag, idx) UPDATE_FPU_AFTER_MMX(tag, idx, false)

#define REP_start() vec_bb.push_back(BasicBlock::Create(CTX(), "", cpu->bb->getParent(), 0)); \
Value *ecx, *zero; \
if (addr_mode == ADDR16) { \
	ecx = LD_R16(ECX_idx); \
	zero = CONST16(0); \
} \
else { \
	ecx = LD_R32(ECX_idx); \
	zero = CONST32(0); \
} \
BR_COND(vec_bb[3], vec_bb[2], ICMP_NE(ecx, zero)); \
cpu->bb = vec_bb[3];

#define REP() Value *ecx, *zero, *one; \
if (addr_mode == ADDR16) { \
	ecx = LD_R16(ECX_idx); \
	zero = CONST16(0); \
	one = CONST16(1); \
	ecx = SUB(ecx, one); \
	ST_R16(ecx, ECX_idx); \
} \
else { \
	ecx = LD_R32(ECX_idx); \
	zero = CONST32(0); \
	one = CONST32(1); \
	ecx = SUB(ecx, one); \
	ST_R32(ecx, ECX_idx); \
} \
BR_COND(vec_bb[3], vec_bb[2], ICMP_NE(ecx, zero))

#define REPNZ() Value *ecx, *zero, *one; \
if (addr_mode == ADDR16) { \
	ecx = LD_R16(ECX_idx); \
	zero = CONST16(0); \
	one = CONST16(1); \
	ecx = SUB(ecx, one); \
	ST_R16(ecx, ECX_idx); \
} \
else { \
	ecx = LD_R32(ECX_idx); \
	zero = CONST32(0); \
	one = CONST32(1); \
	ecx = SUB(ecx, one); \
	ST_R32(ecx, ECX_idx); \
} \
BR_COND(vec_bb[3], vec_bb[2], AND(ICMP_NE(ecx, zero), ICMP_NE(LD_ZF(), CONST32(0))))

#define REPZ() Value *ecx, *zero, *one; \
if (addr_mode == ADDR16) { \
	ecx = LD_R16(ECX_idx); \
	zero = CONST16(0); \
	one = CONST16(1); \
	ecx = SUB(ecx, one); \
	ST_R16(ecx, ECX_idx); \
} \
else { \
	ecx = LD_R32(ECX_idx); \
	zero = CONST32(0); \
	one = CONST32(1); \
	ecx = SUB(ecx, one); \
	ST_R32(ecx, ECX_idx); \
} \
BR_COND(vec_bb[3], vec_bb[2], AND(ICMP_NE(ecx, zero), ICMP_EQ(LD_ZF(), CONST32(0))))

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
#define ST_FLG_SUM_AUX8(a, b, r) ST(GEP(cpu->ptr_eflags, 1), GEN_SUM_VEC8(a, b, r))
#define ST_FLG_SUM_AUX16(a, b, r) ST(GEP(cpu->ptr_eflags, 1), GEN_SUM_VEC16(a, b, r))
#define ST_FLG_SUM_AUX32(a, b, r) ST(GEP(cpu->ptr_eflags, 1), GEN_SUM_VEC32(a, b, r))
#define ST_FLG_SUB_AUX8(a, b, r) ST(GEP(cpu->ptr_eflags, 1), GEN_SUB_VEC8(a, b, r))
#define ST_FLG_SUB_AUX16(a, b, r) ST(GEP(cpu->ptr_eflags, 1), GEN_SUB_VEC16(a, b, r))
#define ST_FLG_SUB_AUX32(a, b, r) ST(GEP(cpu->ptr_eflags, 1), GEN_SUB_VEC32(a, b, r))
#define ST_FLG_AUX(val) ST(GEP(cpu->ptr_eflags, 1), val)
#define ST_FLG_RES_ext(val) ST(GEP(cpu->ptr_eflags, 0), SEXT32(val))
#define ST_FLG_RES(val) ST(GEP(cpu->ptr_eflags, 0), val)
#define LD_FLG_RES() LD(GEP(cpu->ptr_eflags, 0))
#define LD_FLG_AUX() LD(GEP(cpu->ptr_eflags, 1))
#define LD_CF() AND(LD_FLG_AUX(), CONST32(0x80000000))
#define LD_OF() AND(XOR(LD_FLG_AUX(), SHL(LD_FLG_AUX(), CONST32(1))), CONST32(0x80000000))
#define LD_ZF() LD_FLG_RES()
#define LD_SF() XOR(SHR(LD_FLG_RES(), CONST32(31)), AND(LD_FLG_AUX(), CONST32(1)))
#define LD_PF() LD_PARITY(AND(XOR(LD_FLG_RES(), SHR(LD_FLG_AUX(), CONST32(8))), CONST32(0xFF)))
#define LD_AF() AND(LD_FLG_AUX(), CONST32(8))

#define ABORT(str) \
do { \
    CallInst *ci = CallInst::Create(cpu->ptr_abort_fn, ConstantExpr::getIntToPtr(INTPTR(str), getPointerType(getIntegerType(8))), "", cpu->bb); \
    ci->setCallingConv(CallingConv::C); \
} while (0)
