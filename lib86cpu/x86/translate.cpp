/*
 * x86 translation code
 *
 * ergo720                Copyright (c) 2019
 */

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Verifier.h"
#include "internal.h"
#include "frontend.h"
#include "memory.h"
#include "jit.h"

#define BAD LIB86CPU_ABORT_msg("Encountered unimplemented instruction %s", log_instr("", disas_ctx->virt_pc - bytes, &instr).c_str())


static inline addr_t
get_pc(cpu_ctx_t *cpu_ctx)
{
	return cpu_ctx->regs.cs_hidden.base + cpu_ctx->regs.eip;
}

translated_code_t::translated_code_t(cpu_t *cpu) noexcept
{
	this->cpu = cpu;
	this->size = 0;
	this->flags = 0;
	this->ptr_code = nullptr;
}

translated_code_t::~translated_code_t()
{
	this->cpu->jit->free_code_block(this->ptr_code);
}

static translated_code_t *
tc_run_code(cpu_ctx_t *cpu_ctx, translated_code_t *tc)
{
	try {
		// run the translated code
		return tc->ptr_code(cpu_ctx);
	}
	catch (host_exp_t type) {
		switch (type)
		{
		case host_exp_t::pf_exp: {
			// page fault while excecuting the translated code
			try {
				// the exception handler always returns nullptr
				return cpu_ctx->exp_fn(cpu_ctx);
			}
			catch (host_exp_t type) {
				assert(type == host_exp_t::pf_exp);

				// page fault while delivering another exception
				// NOTE: we abort because we don't support double/triple faults yet
				LIB86CPU_ABORT();
			}
		}
		break;

		case host_exp_t::de_exp:
			// debug exception trap while excecuting the translated code
			// we first remove the watchpoint for the faulting address, execute the trapping instruction,
			// reinstall the watchpoint and jump to the debug handler
			assert(cpu_ctx->exp_info.exp_data.idx == EXP_DB);

			cpu_ctx->cpu->cpu_flags |= (CPU_DISAS_ONE | CPU_DBG_TRAP);
			cpu_ctx->tlb[cpu_ctx->exp_info.exp_data.fault_addr >> PAGE_SHIFT] &= ~TLB_WATCH;
			cpu_ctx->regs.eip = cpu_ctx->exp_info.exp_data.eip;
			tc_invalidate(cpu_ctx, nullptr, get_pc(cpu_ctx), 1, cpu_ctx->regs.eip); // force retranslation
			[[fallthrough]];

		case host_exp_t::cpu_mode_changed:
		case host_exp_t::halt_tc:
			return nullptr;

		default:
			LIB86CPU_ABORT_msg("Unknown host exception in %s", __func__);
		}
	}
}

static inline uint32_t
tc_hash(addr_t pc)
{
	return pc & (CODE_CACHE_MAX_SIZE - 1);
}

void
tc_invalidate(cpu_ctx_t *cpu_ctx, translated_code_t *tc, uint32_t addr, uint8_t size, uint32_t eip)
{
	bool halt_tc = false;
	std::vector<std::unordered_set<translated_code_t *>::iterator> tc_to_delete;

	if ((tc != nullptr) && !(tc->flags & TC_FLG_HOOK) &&
		!(std::min(addr + size - 1, tc->pc + tc->size - 1) < std::max(addr, tc->pc))) {
		// worst case: the write overlaps with the tc we are currently executing
		halt_tc = true;
		cpu_ctx->cpu->cpu_flags |= (CPU_DISAS_ONE | CPU_ALLOW_CODE_WRITE);
	}

	// find all tc's in the page addr belongs to
	auto it_map = cpu_ctx->cpu->tc_page_map.find(addr >> PAGE_SHIFT);
	if (it_map != cpu_ctx->cpu->tc_page_map.end()) {
		auto it_set = it_map->second.begin();
		// iterate over all tc's found in the page
		while (it_set != it_map->second.end()) {
			translated_code_t *tc_in_page = *it_set;
			// only invalidate the tc if addr is included in the translated address range of the tc
			if (!(std::min(addr + size - 1, tc_in_page->pc + tc_in_page->size - 1) < std::max(addr, tc_in_page->pc))) {
				auto it_list = tc_in_page->linked_tc.begin();
				// now unlink all other tc's which jump to this tc
				while (it_list != tc_in_page->linked_tc.end()) {
					if ((*it_list)->jmp_offset[0] == tc_in_page->ptr_code) {
						(*it_list)->jmp_offset[0] = (*it_list)->jmp_offset[2];
					}
					if ((*it_list)->jmp_offset[1] == tc_in_page->ptr_code) {
						(*it_list)->jmp_offset[1] = (*it_list)->jmp_offset[2];
					}
					it_list++;
				}

				// delete the found tc from the code cache
				uint32_t idx = tc_hash(tc_in_page->pc);
				auto it = cpu_ctx->cpu->code_cache[idx].begin();
				auto it_prev = it;
				uint8_t found = 0;
				while (it != cpu_ctx->cpu->code_cache[idx].end()) {
					translated_code_t *tc = it->get();
					if (tc == tc_in_page) {
						found = 1;
						(it == cpu_ctx->cpu->code_cache[idx].begin()) ?
							cpu_ctx->cpu->code_cache[idx].pop_front() :
							cpu_ctx->cpu->code_cache[idx].erase_after(it_prev);
						cpu_ctx->cpu->num_tc--;
						break;
					}
					it_prev = it;
					it++;
				}

				assert(found);
				// we can't delete the tc in tc_page_map right now because it would invalidate its iterator, which is still needed below
				tc_to_delete.push_back(it_set);
			}
			it_set++;
		}

		// delete the found tc's from the tc_page_map
		for (auto &it : tc_to_delete) {
			it_map->second.erase(it);
		}

		// if the tc_page_map for addr is now empty, also clear TLB_CODE and its key in the map
		if (it_map->second.empty()) {
			cpu_ctx->tlb[addr >> PAGE_SHIFT] &= ~TLB_CODE;
			cpu_ctx->cpu->tc_page_map.erase(it_map);
		}
	}

	if (halt_tc) {
		// in this case the tc we were executing has been destroyed and thus we must return to the translator with an exception
		cpu_ctx->regs.eip = eip;
		throw host_exp_t::halt_tc;
	}
}

static translated_code_t *
tc_cache_search(cpu_t *cpu, addr_t pc)
{
	uint32_t flags = cpu->cpu_ctx.hflags | (cpu->cpu_ctx.regs.eflags & (TF_MASK | IOPL_MASK | RF_MASK | AC_MASK));
	uint32_t idx = tc_hash(pc);
	auto it = cpu->code_cache[idx].begin();
	while (it != cpu->code_cache[idx].end()) {
		translated_code_t *tc = it->get();
		if (tc->cs_base == cpu->cpu_ctx.regs.cs_hidden.base &&
			tc->pc == pc &&
			tc->cpu_flags == flags) {
			return tc;
		}
		it++;
	}

	return nullptr;
}

static void
tc_cache_insert(cpu_t *cpu, addr_t pc, std::shared_ptr<translated_code_t> &&tc)
{
	cpu->num_tc++;
	if (!(tc->flags & TC_FLG_HOOK)) {
		cpu->tc_page_map[pc >> PAGE_SHIFT].insert(tc.get());
	}
	cpu->code_cache[tc_hash(pc)].push_front(std::move(tc));
}

static void
tc_cache_clear(cpu_t *cpu)
{
	cpu->num_tc = 0;
	cpu->tc_page_map.clear();
	for (auto &bucket : cpu->code_cache) {
		bucket.clear();
	}
}

static void
tc_link_direct(translated_code_t *prev_tc, translated_code_t *ptr_tc)
{
	uint32_t num_jmp = prev_tc->flags & TC_FLG_NUM_JMP;

	switch (num_jmp)
	{
	case 0:
		break;

	case 1:
	case 2:
		switch ((prev_tc->flags & TC_FLG_JMP_TAKEN) >> 4)
		{
		case TC_FLG_DST_PC:
			prev_tc->jmp_offset[0] = ptr_tc->ptr_code;
			ptr_tc->linked_tc.push_front(prev_tc);
			break;

		case TC_FLG_NEXT_PC:
			prev_tc->jmp_offset[1] = ptr_tc->ptr_code;
			ptr_tc->linked_tc.push_front(prev_tc);
			break;

		case TC_FLG_RET:
			if (num_jmp == 1) {
				break;
			}
			[[fallthrough]];

		default:
			LIB86CPU_ABORT();
		}
		break;

	default:
		LIB86CPU_ABORT();
	}
}

void
tc_link_dst_only(translated_code_t *prev_tc, translated_code_t *ptr_tc)
{
	switch (prev_tc->flags & TC_FLG_NUM_JMP)
	{
	case 0:
		break;

	case 1:
		prev_tc->jmp_offset[0] = ptr_tc->ptr_code;
		ptr_tc->linked_tc.push_front(prev_tc);
		break;

	default:
		LIB86CPU_ABORT();
	}
}

static void
create_tc_prologue(cpu_t *cpu)
{
	// create the translation function, it will hold all the translated code
	StructType *cpu_ctx_struct_type = StructType::create(CTX(), "struct.cpu_ctx_t");
	std::vector<Type *> type_struct_exp_data_t_fields;
	type_struct_exp_data_t_fields.push_back(getIntegerType(32));
	type_struct_exp_data_t_fields.push_back(getIntegerType(16));
	type_struct_exp_data_t_fields.push_back(getIntegerType(16));
	type_struct_exp_data_t_fields.push_back(getIntegerType(32));
	StructType *type_exp_data_t = StructType::create(CTX(),
		type_struct_exp_data_t_fields, "struct.exp_data_t", false);

	std::vector<Type*> type_struct_exp_info_t_fields;
	type_struct_exp_info_t_fields.push_back(type_exp_data_t);
	type_struct_exp_info_t_fields.push_back(getIntegerType(8));
	StructType* type_exp_info_t = StructType::create(CTX(),
		type_struct_exp_info_t_fields, "struct.exp_info_t", false);

	StructType *tc_struct_type = StructType::create(CTX(), "struct.tc_t");  // NOTE: opaque tc struct
	FunctionType *type_exp_t = FunctionType::get(
		getPointerType(tc_struct_type),       // tc ret
		getPointerType(cpu_ctx_struct_type),  // cpu_ctx
		false);

	std::vector<Type *> type_struct_cpu_ctx_t_fields;
	type_struct_cpu_ctx_t_fields.push_back(getPointerType(StructType::create(CTX(), "struct.cpu_t")));  // NOTE: opaque cpu struct
	type_struct_cpu_ctx_t_fields.push_back(get_struct_reg(cpu));
	type_struct_cpu_ctx_t_fields.push_back(get_struct_eflags(cpu));
	type_struct_cpu_ctx_t_fields.push_back(getIntegerType(32));
	type_struct_cpu_ctx_t_fields.push_back(getArrayType(getIntegerType(32), TLB_MAX_SIZE));
	type_struct_cpu_ctx_t_fields.push_back(getPointerType(getIntegerType(8)));
	type_struct_cpu_ctx_t_fields.push_back(getPointerType(type_exp_t));
	type_struct_cpu_ctx_t_fields.push_back(type_exp_info_t);
	cpu_ctx_struct_type->setBody(type_struct_cpu_ctx_t_fields, false);
	PointerType *type_pcpu_ctx_t = getPointerType(cpu_ctx_struct_type);

	FunctionType *type_entry_t = FunctionType::get(
		getPointerType(tc_struct_type),   // tc ret
		type_pcpu_ctx_t,                  // cpu_ctx arg
		false);

	Function *func = Function::Create(
		type_entry_t,                        // func type
		GlobalValue::ExternalLinkage,        // linkage
		"main",                              // name
		cpu->mod);
	func->setCallingConv(CallingConv::C);

	cpu->bb = BasicBlock::Create(CTX(), "", func, 0);
	cpu->ptr_cpu_ctx = cpu->bb->getParent()->arg_begin();
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
}

static void
create_tc_epilogue(cpu_t *cpu)
{
	Value *tc_ptr1 = new IntToPtrInst(INTPTR(cpu->tc), cpu->bb->getParent()->getReturnType(), "", cpu->bb);
	ReturnInst::Create(CTX(), tc_ptr1, cpu->bb);

	// create the function that returns to the translator
	Function *exit = Function::Create(
		cpu->bb->getParent()->getFunctionType(),  // func type
		GlobalValue::ExternalLinkage,             // linkage
		"exit",                                   // name
		cpu->mod);
	exit->setCallingConv(CallingConv::C);

	BasicBlock *bb = BasicBlock::Create(CTX(), "", exit, 0);
	Value *tc_ptr2 = new IntToPtrInst(INTPTR(cpu->tc), exit->getReturnType(), "", bb);
	ReturnInst::Create(CTX(), tc_ptr2, bb);
}

uint8_t
cpu_update_crN(cpu_ctx_t *cpu_ctx, uint32_t new_cr, uint8_t idx, uint32_t eip, uint32_t bytes)
{
	switch (idx)
	{
	case 0:
		if (((new_cr & CR0_PE_MASK) == 0 && (new_cr & CR0_PG_MASK) >> 31 == 1) ||
			((new_cr & CR0_CD_MASK) == 0 && (new_cr & CR0_NW_MASK) >> 29 == 1)) {
			return 1;
		}

		cpu_ctx->hflags = (((new_cr & CR0_EM_MASK) << 3) | (cpu_ctx->hflags & ~HFLG_CR0_EM));

		if ((cpu_ctx->regs.cr0 & CR0_PE_MASK) != (new_cr & CR0_PE_MASK)) {
			tc_cache_clear(cpu_ctx->cpu);
			tlb_flush(cpu_ctx->cpu, TLB_zero);
			if (new_cr & CR0_PE_MASK) {
				if (cpu_ctx->regs.cs_hidden.flags & SEG_HIDDEN_DB) {
					cpu_ctx->hflags |= HFLG_CS32;
				}
				if (cpu_ctx->regs.ss_hidden.flags & SEG_HIDDEN_DB) {
					cpu_ctx->hflags |= HFLG_SS32;
				}
				cpu_ctx->hflags |= (HFLG_PE_MODE | (cpu_ctx->regs.cs & HFLG_CPL));
			}
			else {
				cpu_ctx->hflags &= ~(HFLG_CPL | HFLG_CS32 | HFLG_SS32 | HFLG_PE_MODE);
			}

			// since tc_cache_clear has deleted the calling code block, we must return to the translator with an exception
			cpu_ctx->regs.eip = (eip + bytes);
			cpu_ctx->regs.cr0 = ((new_cr & CR0_FLG_MASK) | CR0_ET_MASK);
			cpu_ctx->cpu->jit->free_code_block(cpu_ctx->exp_fn);
			gen_exp_fn(cpu_ctx->cpu);
			throw host_exp_t::cpu_mode_changed;
		}

		if ((cpu_ctx->regs.cr0 & (CR0_WP_MASK | CR0_PG_MASK)) != (new_cr & (CR0_WP_MASK | CR0_PG_MASK))) {
			tlb_flush(cpu_ctx->cpu, TLB_keep_rc);
		}

		// mov cr0, reg always terminates the tc, so we must update the eip here
		cpu_ctx->regs.eip = (eip + bytes);
		cpu_ctx->regs.cr0 = ((new_cr & CR0_FLG_MASK) | CR0_ET_MASK);
		break;

	case 3:
		if (cpu_ctx->regs.cr0 & CR0_PG_MASK) {
			tlb_flush(cpu_ctx->cpu, TLB_no_g);
		}

		cpu_ctx->regs.cr3 = (new_cr & CR3_FLG_MASK);
		break;

	case 4: {
		if (new_cr & CR4_RES_MASK) {
			return 1;
		}

		if (new_cr & CR4_PAE_MASK) {
			LIB86CPU_ABORT_msg("PAE mode is not supported");
		}

		if ((cpu_ctx->regs.cr4 & (CR4_PSE_MASK | CR4_PGE_MASK)) != (new_cr & (CR4_PSE_MASK | CR4_PGE_MASK))) {
			tlb_flush(cpu_ctx->cpu, TLB_keep_rc);
		}

		cpu_ctx->regs.cr4 = new_cr;
	}
	break;

	case 2:
	default:
		LIB86CPU_ABORT();
	}

	return 0;
}

void
cpu_msr_read(cpu_ctx_t *cpu_ctx)
{
	uint64_t val;

	switch (cpu_ctx->regs.ecx)
	{
	case IA32_APIC_BASE:
		// hardcoded value for now
		val = 0xFEE00000 | (1 << 11) | (1 << 8);
		break;

	case IA32_MTRR_PHYSBASE(0):
	case IA32_MTRR_PHYSBASE(1):
	case IA32_MTRR_PHYSBASE(2):
	case IA32_MTRR_PHYSBASE(3):
	case IA32_MTRR_PHYSBASE(4):
	case IA32_MTRR_PHYSBASE(5):
	case IA32_MTRR_PHYSBASE(6):
	case IA32_MTRR_PHYSBASE(7):
		val = cpu_ctx->cpu->mtrr.phys_var[(cpu_ctx->regs.ecx - MTRR_PHYSBASE_base) / 2].base;
		break;

	case IA32_MTRR_PHYSMASK(0):
	case IA32_MTRR_PHYSMASK(1):
	case IA32_MTRR_PHYSMASK(2):
	case IA32_MTRR_PHYSMASK(3):
	case IA32_MTRR_PHYSMASK(4):
	case IA32_MTRR_PHYSMASK(5):
	case IA32_MTRR_PHYSMASK(6):
	case IA32_MTRR_PHYSMASK(7):
		val = cpu_ctx->cpu->mtrr.phys_var[(cpu_ctx->regs.ecx - MTRR_PHYSMASK_base) / 2].mask;
		break;

	default:
		LIB86CPU_ABORT_msg("Unhandled msr read to register at address 0x%X", cpu_ctx->regs.ecx);
	}

	cpu_ctx->regs.edx = (val >> 32);
	cpu_ctx->regs.eax = val;
}

static void
cpu_translate(cpu_t *cpu, disas_ctx_t *disas_ctx)
{
	uint8_t translate_next = 1;
	uint8_t size_mode;
	uint8_t addr_mode;
	cpu_ctx_t *cpu_ctx = &cpu->cpu_ctx;
	size_t bytes;
	addr_t pc = disas_ctx->virt_pc;
	// we can use the same indexes for both loads and stores because they have the same order in cpu->ptr_mem_xxfn
	static const uint8_t fn_idx[3] = { MEM_LD32_idx, MEM_LD16_idx, MEM_LD8_idx };
	static const uint8_t fn_io_idx[3] = { IO_LD32_idx, IO_LD16_idx, IO_LD8_idx };

	ZydisDecodedInstruction instr;
	ZydisDecoder decoder;
	ZyanStatus status;

	init_instr_decoder(disas_ctx, &decoder);

	// clear rf if it was set by the previous tc. Note that the cpu does this after having checked for instr breakpoints but before executing the instr. If we do
	// this at the end of the tc, it's possible that one of the instr in the tc raise an exp and that wil prevent us from clearing the flag
	if (cpu->cpu_ctx.regs.eflags & RF_MASK) {
		assert(disas_ctx->flags & DISAS_FLG_ONE_INSTR);
		ST(GEP_EFLAGS(), AND(LD(GEP_EFLAGS()), CONST32(~RF_MASK)));
	}

	do {
		cpu->instr_eip = CONST32(pc - cpu_ctx->regs.cs_hidden.base);

		try {
			status = decode_instr(cpu, disas_ctx, &decoder, &instr);
		}
		catch (host_exp_t type) {
			assert(type == host_exp_t::de_exp);
			RAISEin0(EXP_DB);
			return;
		}

		if (ZYAN_SUCCESS(status)) {
			// successfully decoded

			bytes = instr.length;
			disas_ctx->flags |= ((disas_ctx->virt_pc & ~PAGE_MASK) != ((disas_ctx->virt_pc + bytes - 1) & ~PAGE_MASK)) << 2;
			disas_ctx->pc += bytes;
			disas_ctx->virt_pc += bytes;

			LOG(log_level::debug, instr_logfn("0x%08X  ", disas_ctx->virt_pc - bytes, &instr).c_str(), disas_ctx->virt_pc - bytes);
		}
		else {
			switch (status)
			{
			case ZYDIS_STATUS_BAD_REGISTER:
			case ZYDIS_STATUS_ILLEGAL_LOCK:
			case ZYDIS_STATUS_DECODING_ERROR:
				// illegal and/or undefined instruction, or lock prefix used on an instruction which does not accept it or used as source operand,
				// or the instruction encodes a register that cannot be used (e.g. mov cs, edx)
				RAISEin0(EXP_UD);
				return;

			case ZYDIS_STATUS_NO_MORE_DATA:
				// buffer < 15 bytes
				cpu->cpu_flags &= ~(CPU_DISAS_ONE | CPU_ALLOW_CODE_WRITE);
				if (disas_ctx->exp_data.idx == EXP_PF) {
					// buffer size reduced because of page fault on second page
					disas_ctx->flags |= DISAS_FLG_FETCH_FAULT;
					RAISEin(disas_ctx->exp_data.fault_addr, disas_ctx->exp_data.code, disas_ctx->exp_data.idx, disas_ctx->exp_data.eip);
					return;
				}
				else {
					// buffer size reduced because ram/rom region ended
					LIB86CPU_ABORT_msg("Attempted to execute code outside of ram/rom!");
				}

			case ZYDIS_STATUS_INSTRUCTION_TOO_LONG: {
				// instruction length > 15 bytes
				cpu->cpu_flags &= ~(CPU_DISAS_ONE | CPU_ALLOW_CODE_WRITE);
				volatile addr_t addr = get_code_addr(cpu, disas_ctx->virt_pc + X86_MAX_INSTR_LENGTH, disas_ctx->virt_pc - cpu->cpu_ctx.regs.cs_hidden.base, disas_ctx);
				if (disas_ctx->exp_data.idx == EXP_PF) {
					disas_ctx->flags |= DISAS_FLG_FETCH_FAULT;
					RAISEin(disas_ctx->exp_data.fault_addr, disas_ctx->exp_data.code, disas_ctx->exp_data.idx, disas_ctx->exp_data.eip);
				}
				else {
					RAISEin(0, 0, EXP_GP, disas_ctx->virt_pc - cpu->cpu_ctx.regs.cs_hidden.base);
				}
				return;
			}

			default:
				LIB86CPU_ABORT_msg("Unhandled zydis decode return status");
			}
		}


		if ((disas_ctx->flags & DISAS_FLG_CS32) ^ ((instr.attributes & ZYDIS_ATTRIB_HAS_OPERANDSIZE) >> 34)) {
			size_mode = SIZE32;
		}
		else {
			size_mode = SIZE16;
		}

		if ((disas_ctx->flags & DISAS_FLG_CS32) ^ ((instr.attributes & ZYDIS_ATTRIB_HAS_ADDRESSSIZE) >> 35)) {
			addr_mode = ADDR32;
		}
		else {
			addr_mode = ADDR16;
		}

		switch (instr.mnemonic) {
		case ZYDIS_MNEMONIC_AAA: {
			std::vector<BasicBlock *> vec_bb = getBBs(3);
			BR_COND(vec_bb[0], vec_bb[1], OR(ICMP_UGT(AND(LD_R8L(EAX_idx), CONST8(0xF)), CONST8(9)), ICMP_NE(LD_AF(), CONST32(0))));
			cpu->bb = vec_bb[0];
			ST_R16(ADD(LD_R16(EAX_idx), CONST16(0x106)), EAX_idx);
			ST_FLG_AUX(CONST32(0x80000008));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[1];
			ST_FLG_AUX(CONST32(0));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[2];
			ST_R8L(AND(LD_R8L(EAX_idx), CONST8(0xF)), EAX_idx);
		}
		break;

		case ZYDIS_MNEMONIC_AAD: {
			Value *al = LD_R8L(EAX_idx);
			Value *ah = LD_R8H(EAX_idx);
			ST_R8L(ADD(al, MUL(ah, CONST8(instr.operands[OPNUM_SINGLE].imm.value.u))), EAX_idx);
			ST_R8H(CONST8(0), EAX_idx);
			ST_FLG_RES_ext(LD_R8L(EAX_idx));
			ST_FLG_AUX(CONST32(0));
		}
		break;

		case ZYDIS_MNEMONIC_AAM: {
			if (instr.operands[OPNUM_SINGLE].imm.value.u == 0) {
				RAISEin0(EXP_DE);
				translate_next = 0;
			}
			else {
				Value *al = LD_R8L(EAX_idx);
				ST_R8H(UDIV(al, CONST8(instr.operands[OPNUM_SINGLE].imm.value.u)), EAX_idx);
				ST_R8L(UREM(al, CONST8(instr.operands[OPNUM_SINGLE].imm.value.u)), EAX_idx);
				ST_FLG_RES_ext(LD_R8L(EAX_idx));
				ST_FLG_AUX(CONST32(0));
			}
		}
		break;

		case ZYDIS_MNEMONIC_AAS: {
			std::vector<BasicBlock *> vec_bb = getBBs(3);
			BR_COND(vec_bb[0], vec_bb[1], OR(ICMP_UGT(AND(LD_R8L(EAX_idx), CONST8(0xF)), CONST8(9)), ICMP_NE(LD_AF(), CONST32(0))));
			cpu->bb = vec_bb[0];
			ST_R16(SUB(LD_R16(EAX_idx), CONST16(6)), EAX_idx);
			ST_R8H(SUB(LD_R8H(EAX_idx), CONST8(1)), EAX_idx);
			ST_FLG_AUX(CONST32(0x80000008));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[1];
			ST_FLG_AUX(CONST32(0));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[2];
			ST_R8L(AND(LD_R8L(EAX_idx), CONST8(0xF)), EAX_idx);
		}
		break;

		case ZYDIS_MNEMONIC_ADC: {
			Value *src, *sum1, *sum2, *dst, *rm, *cf, *sum_cout;
			switch (instr.opcode)
			{
			case 0x14:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x15: {
				switch (size_mode)
				{
				case SIZE8:
					src = CONST8(instr.operands[OPNUM_SRC].imm.value.u);
					rm = GEP_R8L(EAX_idx);
					dst = LD(rm);
					break;

				case SIZE16:
					src = CONST16(instr.operands[OPNUM_SRC].imm.value.u);
					rm = GEP_R16(EAX_idx);
					dst = LD(rm);
					break;

				case SIZE32:
					src = CONST32(instr.operands[OPNUM_SRC].imm.value.u);
					rm = GEP_R32(EAX_idx);
					dst = LD(rm);
					break;

				default:
					LIB86CPU_ABORT();
				}
			}
			break;

			case 0x80:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x81:
			case 0x83: {
				assert(instr.raw.modrm.reg == 2);

				if (instr.opcode == 0x83) {
					src = (size_mode == SIZE16) ? SEXT16(CONST8(instr.operands[OPNUM_SRC].imm.value.u)) :
						SEXT32(CONST8(instr.operands[OPNUM_SRC].imm.value.u));
				}
				else {
					src = GET_IMM();
				}

				GET_RM(OPNUM_DST, dst = LD_REG_val(rm);, dst = LD_MEM(fn_idx[size_mode], rm););
			}
			break;

			case 0x10:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x11: {
				src = LD_REG_val(GET_REG(OPNUM_SRC));
				GET_RM(OPNUM_DST, dst = LD_REG_val(rm);, dst = LD_MEM(fn_idx[size_mode], rm););
			}
			break;

			case 0x12:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x13: {
				GET_RM(OPNUM_SRC, src = LD_REG_val(rm);, src = LD_MEM(fn_idx[size_mode], rm););
				rm = GET_REG(OPNUM_DST);
				dst = LD_REG_val(rm);
			}
			break;

			default:
				LIB86CPU_ABORT();
			}

			switch (size_mode)
			{
			case SIZE8:
				cf = TRUNC8(SHR(LD_CF(), CONST32(31)));
				sum1 = ADD(dst, src);
				sum2 = ADD(sum1, cf);
				sum_cout = GEN_SUM_VEC8(dst, src, sum2);
				break;

			case SIZE16:
				cf = TRUNC16(SHR(LD_CF(), CONST32(31)));
				sum1 = ADD(dst, src);
				sum2 = ADD(sum1, cf);
				sum_cout = GEN_SUM_VEC16(dst, src, sum2);
				break;

			case SIZE32:
				cf = SHR(LD_CF(), CONST32(31));
				sum1 = ADD(dst, src);
				sum2 = ADD(sum1, cf);
				sum_cout = GEN_SUM_VEC32(dst, src, sum2);
				break;

			default:
				LIB86CPU_ABORT();
			}

			if (instr.operands[OPNUM_DST].type == ZYDIS_OPERAND_TYPE_REGISTER) {
				ST_REG_val(sum2, rm);
			}
			else {
				ST_MEM(fn_idx[size_mode], rm, sum2);
			}

			SET_FLG(sum2, sum_cout);
		}
		break;

		case ZYDIS_MNEMONIC_ADD: {
			switch (instr.opcode)
			{
			case 0x00:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x01: {
				Value *rm, *dst, *sum, *val;
				val = LD_REG_val(GET_REG(OPNUM_SRC));
				GET_RM(OPNUM_DST, dst = LD_REG_val(rm); sum = ADD(dst, val); ST_REG_val(sum, rm);,
					dst = LD_MEM(fn_idx[size_mode], rm); sum = ADD(dst, val); ST_MEM(fn_idx[size_mode], rm, sum););
				SET_FLG_SUM(sum, dst, val);
			}
			break;

			case 0x02:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x03: {
				Value *rm, *dst, *sum, *val, *reg;
				reg = GET_REG(OPNUM_DST);
				dst = LD_REG_val(reg);
				GET_RM(OPNUM_SRC, val = LD_REG_val(rm); sum = ADD(dst, val); ST_REG_val(sum, reg);,
					val = LD_MEM(fn_idx[size_mode], rm); sum = ADD(dst, val); ST_REG_val(sum, reg););
				SET_FLG_SUM(sum, dst, val);
			}
			break;

			case 0x04:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x05: {
				Value *val, *sum, *eax, *dst;
				val = GET_IMM();
				dst = GET_REG(OPNUM_DST);
				eax = LD_REG_val(dst);
				sum = ADD(eax, val);
				ST_REG_val(sum, dst);
				SET_FLG_SUM(sum, eax, val);
			}
			break;

			case 0x80:
			case 0x82:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x81:
			case 0x83: {
				assert(instr.raw.modrm.reg == 0);

				Value *rm, *dst, *sum, *val;
				if (instr.opcode == 0x83) {
					val = size_mode == SIZE16 ? SEXT16(GET_IMM8()) : SEXT32(GET_IMM8());
				}
				else {
					val = GET_IMM();
				}
				GET_RM(OPNUM_DST, dst = LD_REG_val(rm); sum = ADD(dst, val); ST_REG_val(sum, rm);,
					dst = LD_MEM(fn_idx[size_mode], rm); sum = ADD(dst, val); ST_MEM(fn_idx[size_mode], rm, sum););
				SET_FLG_SUM(sum, dst, val);
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_AND: {
			switch (instr.opcode)
			{
			case 0x20:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x21: {
				Value *val, *reg, *rm;
				reg = LD_REG_val(GET_REG(OPNUM_SRC));
				GET_RM(OPNUM_DST, val = LD_REG_val(rm); val = AND(val, reg); ST_REG_val(val, rm);, val = LD_MEM(fn_idx[size_mode], rm);
				val = AND(val, reg); ST_MEM(fn_idx[size_mode], rm, val););
				SET_FLG(val, CONST32(0));
			}
			break;

			case 0x22:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x23: {
				Value *val, *reg, *rm;
				reg = GET_OP(OPNUM_DST);
				GET_RM(OPNUM_SRC, val = LD_REG_val(rm); val = AND(LD(reg), val);, val = LD_MEM(fn_idx[size_mode], rm); val = AND(LD(reg), val););
				ST_REG_val(val, reg);
				SET_FLG(val, CONST32(0));
			}
			break;

			case 0x24:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x25: {
				Value *val, *eax;
				eax = GET_REG(OPNUM_DST);
				val = AND(LD_REG_val(eax), GET_IMM());
				ST_REG_val(val, eax);
				SET_FLG(val, CONST32(0));
			}
			break;

			case 0x80:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x81:
			case 0x83: {
				assert(instr.raw.modrm.reg == 4);

				Value *val, *rm, *src;
				if (instr.opcode == 0x83) {
					src = size_mode == SIZE16 ? SEXT16(GET_IMM8()) : SEXT32(GET_IMM8());
				}
				else {
					src = GET_IMM();
				}
				GET_RM(OPNUM_DST, val = LD_REG_val(rm); val = AND(val, src); ST_REG_val(val, rm);, val = LD_MEM(fn_idx[size_mode], rm);
				val = AND(val, src); ST_MEM(fn_idx[size_mode], rm, val););
				SET_FLG(val, CONST32(0));
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_ARPL: {
			assert((instr.operands[OPNUM_DST].size == 16) && (instr.operands[OPNUM_SRC].size == 16));

			Value *rm, *rpl_dst, *rpl_src = LD_REG_val(GET_REG(OPNUM_SRC));
			GET_RM(OPNUM_DST, rpl_dst = LD_REG_val(rm);, rpl_dst = LD_MEM(MEM_LD16_idx, rm););
			std::vector<BasicBlock *> vec_bb = getBBs(3);
			BR_COND(vec_bb[0], vec_bb[1], ICMP_ULT(AND(rpl_dst, CONST16(3)), AND(rpl_src, CONST16(3))));
			cpu->bb = vec_bb[0];
			Value *new_rpl = OR(AND(rpl_dst, CONST16(0xFFFC)), AND(rpl_src, CONST16(3)));
			(instr.operands[OPNUM_DST].type == ZYDIS_OPERAND_TYPE_REGISTER) ? ST_REG_val(new_rpl, rm) : ST_MEM(MEM_LD16_idx, rm, new_rpl);
			Value *new_sfd = XOR(LD_SF(), CONST32(0));
			Value *new_pdb = SHL(XOR(AND(XOR(LD_FLG_RES(), SHR(LD_FLG_AUX(), CONST32(8))), CONST32(0xFF)), CONST32(0)), CONST32(8));
			ST_FLG_AUX(OR(AND(LD_FLG_AUX(), CONST32(0xFFFF00FE)), OR(new_sfd, new_pdb)));
			ST_FLG_RES(CONST32(0));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[1];
			ST_FLG_RES(OR(LD_FLG_RES(), CONST32(0x100)));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[2];
		}
		break;

		case ZYDIS_MNEMONIC_BOUND: {
			Value *idx = LD_REG_val(GET_REG(OPNUM_DST));
			Value *idx_addr = GET_OP(OPNUM_SRC);
			Value *lower_idx = LD_MEM(fn_idx[size_mode], idx_addr);
			Value *upper_idx = LD_MEM(fn_idx[size_mode], ADD(idx_addr, (size_mode == SIZE16) ? CONST32(2) : CONST32(4)));
			std::vector<BasicBlock *> vec_bb = getBBs(2);
			BR_COND(vec_bb[0], vec_bb[1], OR(ICMP_SLT(idx, lower_idx), ICMP_SGT(idx, upper_idx)));
			cpu->bb = vec_bb[0];
			RAISEin0(EXP_BR);
			UNREACH();
			cpu->bb = vec_bb[1];
		}
		break;

		case ZYDIS_MNEMONIC_BSF: {
			Value *rm, *src;
			std::vector<BasicBlock *> vec_bb = getBBs(3);
			GET_RM(OPNUM_SRC, src = LD_REG_val(rm);, src = LD_MEM(fn_idx[size_mode], rm););
			BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(src, CONSTs(instr.operands[OPNUM_SRC].size, 0)));
			cpu->bb = vec_bb[0];
			ST_FLG_RES(CONST32(0));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[1];
			ST_REG_val(INTRINSIC_ty(cttz, getIntegerType(instr.operands[OPNUM_SRC].size), (std::vector<Value *> { src, CONSTs(1, 1) })), GET_REG(OPNUM_DST));
			ST_FLG_RES(CONST32(1));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[2];
		}
		break;

		case ZYDIS_MNEMONIC_BSR: {
			Value *rm, *src;
			std::vector<BasicBlock *> vec_bb = getBBs(3);
			GET_RM(OPNUM_SRC, src = LD_REG_val(rm);, src = LD_MEM(fn_idx[size_mode], rm););
			BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(src, CONSTs(instr.operands[OPNUM_SRC].size, 0)));
			cpu->bb = vec_bb[0];
			ST_FLG_RES(CONST32(0));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[1];
			ST_REG_val(SUB(CONSTs(instr.operands[OPNUM_SRC].size, instr.operands[OPNUM_SRC].size - 1),
				INTRINSIC_ty(ctlz, getIntegerType(instr.operands[OPNUM_SRC].size), (std::vector<Value *> { src, CONSTs(1, 1) }))), GET_REG(OPNUM_DST));
			ST_FLG_RES(CONST32(1));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[2];
		}
		break;

		case ZYDIS_MNEMONIC_BSWAP: {
			int reg_idx = GET_REG_idx(instr.operands[OPNUM_SINGLE].reg.value);
			Value *temp = LD_R32(reg_idx);
			temp = INTRINSIC_ty(bswap, getIntegerType(32), temp);
			ST_R32(temp, reg_idx);
		}
		break;

		case ZYDIS_MNEMONIC_BT:
		case ZYDIS_MNEMONIC_BTC:
		case ZYDIS_MNEMONIC_BTR:
		case ZYDIS_MNEMONIC_BTS: {
			Value *rm, *base, *offset, *idx, *cf, *cf2;
			size_t op_size = instr.operands[OPNUM_DST].size;
			if (instr.opcode != 0xBA) {
				offset = LD_REG_val(GET_REG(OPNUM_SRC));
			}
			else {
				offset = ZEXTs(op_size, GET_IMM8());
			}

			// NOTE: we can't use llvm's SDIV when the base is a memory operand because that rounds towards zero, while the instruction rounds the
			// offset towards negative infinity, that is, it does a floored division
			GET_RM(OPNUM_DST, base = LD_REG_val(rm); offset = UREM(offset, CONSTs(op_size, op_size));,
				offset = UREM(offset, CONSTs(op_size, 8)); idx = FLOOR_DIV(offset, CONSTs(op_size, 8), op_size);
				idx = (op_size == 16) ? ZEXT32(idx) : idx; base = LD_MEM(fn_idx[size_mode], ADD(rm, idx)););
			if (op_size == 16) {
				cf = AND(SHR(base, offset), CONST16(1));
				cf2 = ZEXT32(cf);
			}
			else {
				cf = AND(SHR(base, offset), CONST32(1));
				cf2 = cf;
			}

			switch (instr.operands[OPNUM_DST].type)
			{
			case ZYDIS_OPERAND_TYPE_REGISTER:
				switch (instr.mnemonic)
				{
				case ZYDIS_MNEMONIC_BTC:
					ST_REG_val(OR(AND(base, NOT(SHL(CONSTs(op_size, 1), offset))), SHL(AND(NOT(cf), CONSTs(op_size, 1)), offset)), rm);
					break;

				case ZYDIS_MNEMONIC_BTR:
					ST_REG_val(AND(base, NOT(SHL(CONSTs(op_size, 1), offset))), rm);
					break;

				case ZYDIS_MNEMONIC_BTS:
					ST_REG_val(OR(AND(base, NOT(SHL(CONSTs(op_size, 1), offset))), SHL(CONSTs(op_size, 1), offset)), rm);
					break;
				}
				break;

			case ZYDIS_OPERAND_TYPE_MEMORY:
				switch (instr.mnemonic)
				{
				case ZYDIS_MNEMONIC_BTC:
					ST_MEM(fn_idx[size_mode], ADD(rm, idx), OR(AND(base, NOT(SHL(CONSTs(op_size, 1), offset))), SHL(AND(NOT(cf), CONSTs(op_size, 1)), offset)));
					break;

				case ZYDIS_MNEMONIC_BTR:
					ST_MEM(fn_idx[size_mode], ADD(rm, idx), AND(base, NOT(SHL(CONSTs(op_size, 1), offset))));
					break;

				case ZYDIS_MNEMONIC_BTS:
					ST_MEM(fn_idx[size_mode], ADD(rm, idx), OR(AND(base, NOT(SHL(CONSTs(op_size, 1), offset))), SHL(CONSTs(op_size, 1), offset)));
					break;
				}
				break;

			default:
				LIB86CPU_ABORT_msg("Invalid operand type used in GET_RM macro!");
			}


			ST_FLG_AUX(SHL(cf2, CONST32(31)));
		}
		break;

		case ZYDIS_MNEMONIC_CALL: {
			switch (instr.opcode)
			{
			case 0x9A: {
				uint32_t ret_eip = (pc - cpu_ctx->regs.cs_hidden.base) + bytes;
				uint32_t call_eip = instr.operands[OPNUM_SINGLE].ptr.offset;
				uint16_t new_sel = instr.operands[OPNUM_SINGLE].ptr.segment;
				Value *cs, *eip;
				if (size_mode == SIZE16) {
					cs = CONST16(cpu_ctx->regs.cs);
					eip = CONST16(ret_eip);
					call_eip &= 0x0000FFFF;
				}
				else {
					cs = CONST32(cpu_ctx->regs.cs);
					eip = CONST32(ret_eip);
				}
				if (cpu_ctx->hflags & HFLG_PE_MODE) {
					lcall_pe_emit(cpu, std::vector<Value *> { CONST16(new_sel), CONST32(call_eip), cs, eip }, size_mode, ret_eip);
					cpu->tc->flags |= TC_FLG_INDIRECT;
				}
				else {
					MEM_PUSH((std::vector<Value *> { cs, eip }));
					ST_SEG(CONST16(new_sel), CS_idx);
					ST_R32(CONST32(call_eip), EIP_idx);
					ST_SEG_HIDDEN(CONST32(static_cast<uint32_t>(new_sel) << 4), CS_idx, SEG_BASE_idx);
					link_direct_emit(cpu, std::vector <addr_t> { pc, (static_cast<uint32_t>(new_sel) << 4) + call_eip },
						CONST32((static_cast<uint32_t>(new_sel) << 4) + call_eip));
					cpu->tc->flags |= TC_FLG_DIRECT;
				}
			}
			break;

			case 0xE8: {
				addr_t ret_eip = (pc - cpu_ctx->regs.cs_hidden.base) + bytes;
				addr_t call_eip = ret_eip + instr.operands[OPNUM_SINGLE].imm.value.s;
				if (size_mode == SIZE16) {
					call_eip &= 0x0000FFFF;
				}

				std::vector<Value *> vec;
				vec.push_back(size_mode == SIZE16 ? CONST16(ret_eip) : CONST32(ret_eip));
				MEM_PUSH(vec);
				ST_R32(CONST32(call_eip), EIP_idx);
				link_direct_emit(cpu, std::vector <addr_t> { pc, cpu_ctx->regs.cs_hidden.base + call_eip, pc + bytes },
					CONST32(cpu_ctx->regs.cs_hidden.base + call_eip));
				cpu->tc->flags |= TC_FLG_DIRECT;
			}
			break;

			case 0xFF: {
				if (instr.raw.modrm.reg == 2) {
					Value *call_eip, *rm, *sp;
					addr_t ret_eip = (pc - cpu_ctx->regs.cs_hidden.base) + bytes;
					GET_RM(OPNUM_SINGLE, call_eip = LD_REG_val(rm);, call_eip = LD_MEM(fn_idx[size_mode], rm););
					std::vector<Value *> vec;
					vec.push_back(size_mode == SIZE16 ? CONST16(ret_eip) : CONST32(ret_eip));
					MEM_PUSH(vec);
					if (size_mode == SIZE16) {
						call_eip = ZEXT32(call_eip);
					}
					ST_R32(call_eip, EIP_idx);
					cpu->tc->flags |= TC_FLG_INDIRECT;
				}
				else if (instr.raw.modrm.reg == 3) {
					assert(instr.operands[OPNUM_SINGLE].type == ZYDIS_OPERAND_TYPE_MEMORY);

					Value *cs, *eip, *call_eip, *call_cs, *cs_addr, *offset_addr = GET_OP(OPNUM_SINGLE);
					addr_t ret_eip = (pc - cpu_ctx->regs.cs_hidden.base) + bytes;
					if (size_mode == SIZE16) {
						Value *temp = LD_MEM(MEM_LD16_idx, offset_addr);
						call_eip = ZEXT32(temp);
						cs_addr = ADD(offset_addr, CONST32(2));
						cs = CONST16(cpu_ctx->regs.cs);
						eip = CONST16(ret_eip);
					}
					else {
						call_eip = LD_MEM(MEM_LD32_idx, offset_addr);
						cs_addr = ADD(offset_addr, CONST32(4));
						cs = CONST32(cpu_ctx->regs.cs);
						eip = CONST32(ret_eip);
					}
					call_cs = LD_MEM(MEM_LD16_idx, cs_addr);
					if (cpu_ctx->hflags & HFLG_PE_MODE) {
						lcall_pe_emit(cpu, std::vector<Value *> { call_cs, call_eip, cs, eip }, size_mode, ret_eip);
					}
					else {
						std::vector<Value *> vec;
						vec.push_back(cs);
						vec.push_back(eip);
						MEM_PUSH(vec);
						ST_SEG(call_cs, CS_idx);
						ST_R32(call_eip, EIP_idx);
						ST_SEG_HIDDEN(SHL(ZEXT32(call_cs), CONST32(4)), CS_idx, SEG_BASE_idx);
					}
					cpu->tc->flags |= TC_FLG_INDIRECT;
				}
				else {
					LIB86CPU_ABORT();
				}
			}
			break;

			default:
				LIB86CPU_ABORT();
			}

			translate_next = 0;
		}
		break;

		case ZYDIS_MNEMONIC_CBW: {
			ST_R16(SEXT16(LD_R8L(EAX_idx)), EAX_idx);
		}
		break;

		case ZYDIS_MNEMONIC_CDQ: {
			ST_R32(TRUNC32(SHR(SEXT64(LD_R32(EAX_idx)), CONST64(32))), EDX_idx);
		}
		break;

		case ZYDIS_MNEMONIC_CLC: {
			assert(instr.opcode == 0xF8);

			Value *of_new = SHR(XOR(CONST32(0), LD_OF()), CONST32(1));
			ST_FLG_AUX(OR(AND(LD_FLG_AUX(), CONST32(0x3FFFFFFF)), of_new));
		}
		break;

		case ZYDIS_MNEMONIC_CLD: {
			assert(instr.opcode == 0xFC);

			Value *eflags = LD_R32(EFLAGS_idx);
			eflags = AND(eflags, CONST32(~DF_MASK));
			ST_R32(eflags, EFLAGS_idx);
		}
		break;

		case ZYDIS_MNEMONIC_CLI: {
			assert(instr.opcode == 0xFA);

			Value *eflags = LD_R32(EFLAGS_idx);
			if (cpu_ctx->hflags & HFLG_PE_MODE) {

				// we don't support virtual 8086 mode, so we don't need to check for it
				if (((cpu->cpu_ctx.regs.eflags & IOPL_MASK) >> 12) >= (cpu->cpu_ctx.hflags & HFLG_CPL)) {
					eflags = AND(eflags, CONST32(~IF_MASK));
					ST_R32(eflags, EFLAGS_idx);
				}
				else {
					RAISEin0(EXP_GP);
					translate_next = 0;
				}
			}
			else {
				eflags = AND(eflags, CONST32(~IF_MASK));
				ST_R32(eflags, EFLAGS_idx);
			}
		}
		break;

		case ZYDIS_MNEMONIC_CLTS:        BAD;
		case ZYDIS_MNEMONIC_CMC:         BAD;
		case ZYDIS_MNEMONIC_CMOVB:
		case ZYDIS_MNEMONIC_CMOVBE:
		case ZYDIS_MNEMONIC_CMOVL:
		case ZYDIS_MNEMONIC_CMOVLE:
		case ZYDIS_MNEMONIC_CMOVNB:
		case ZYDIS_MNEMONIC_CMOVNBE:
		case ZYDIS_MNEMONIC_CMOVNL:
		case ZYDIS_MNEMONIC_CMOVNLE:
		case ZYDIS_MNEMONIC_CMOVNO:
		case ZYDIS_MNEMONIC_CMOVNP:
		case ZYDIS_MNEMONIC_CMOVNS:
		case ZYDIS_MNEMONIC_CMOVNZ:
		case ZYDIS_MNEMONIC_CMOVO:
		case ZYDIS_MNEMONIC_CMOVP:
		case ZYDIS_MNEMONIC_CMOVS:
		case ZYDIS_MNEMONIC_CMOVZ: {
			Value *val;
			switch (instr.opcode)
			{
			case 0x40:
				val = ICMP_NE(LD_OF(), CONST32(0)); // OF != 0
				break;

			case 0x41:
				val = ICMP_EQ(LD_OF(), CONST32(0)); // OF == 0
				break;

			case 0x42:
				val = ICMP_NE(LD_CF(), CONST32(0)); // CF != 0
				break;

			case 0x43:
				val = ICMP_EQ(LD_CF(), CONST32(0)); // CF == 0
				break;

			case 0x44:
				val = ICMP_EQ(LD_ZF(), CONST32(0)); // ZF != 0
				break;

			case 0x45:
				val = ICMP_NE(LD_ZF(), CONST32(0)); // ZF == 0
				break;

			case 0x46:
				val = OR(ICMP_NE(LD_CF(), CONST32(0)), ICMP_EQ(LD_ZF(), CONST32(0))); // CF != 0 OR ZF != 0
				break;

			case 0x47:
				val = AND(ICMP_EQ(LD_CF(), CONST32(0)), ICMP_NE(LD_ZF(), CONST32(0))); // CF == 0 AND ZF == 0
				break;

			case 0x48:
				val = ICMP_NE(LD_SF(), CONST32(0)); // SF != 0
				break;

			case 0x49:
				val = ICMP_EQ(LD_SF(), CONST32(0)); // SF == 0
				break;

			case 0x4A:
				val = ICMP_EQ(LD_PF(), CONST8(0)); // PF != 0
				break;

			case 0x4B:
				val = ICMP_NE(LD_PF(), CONST8(0)); // PF == 0
				break;

			case 0x4C:
				val = ICMP_NE(LD_SF(), SHR(LD_OF(), CONST32(31))); // SF != OF
				break;

			case 0x4D:
				val = ICMP_EQ(LD_SF(), SHR(LD_OF(), CONST32(31))); // SF == OF
				break;

			case 0x4E:
				val = OR(ICMP_EQ(LD_ZF(), CONST32(0)), ICMP_NE(LD_SF(), SHR(LD_OF(), CONST32(31)))); // ZF != 0 OR SF != OF
				break;

			case 0x4F:
				val = AND(ICMP_NE(LD_ZF(), CONST32(0)), ICMP_EQ(LD_SF(), SHR(LD_OF(), CONST32(31)))); // ZF == 0 AND SF == OF
				break;

			default:
				LIB86CPU_ABORT();
			}

			Value *rm, *src;
			std::vector<BasicBlock *>vec_bb = getBBs(2);
			BR_COND(vec_bb[0], vec_bb[1], val);
			cpu->bb = vec_bb[0];
			GET_RM(OPNUM_SRC, src = LD_REG_val(rm);, src = LD_MEM(fn_idx[size_mode], rm););
			ST_REG_val(src, GET_REG(OPNUM_DST));
			BR_UNCOND(vec_bb[1]);
			cpu->bb = vec_bb[1];
		}
		break;

		case ZYDIS_MNEMONIC_CMP: {
			Value *val, *cmp, *sub, *rm;
			switch (instr.opcode)
			{
			case 0x38:
				size_mode = SIZE8;
				cmp = LD_REG_val(GET_REG(OPNUM_SRC));
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				break;

			case 0x39:
				cmp = LD_REG_val(GET_REG(OPNUM_SRC));
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				break;

			case 0x3A:
				size_mode = SIZE8;
				val = LD_REG_val(GET_REG(OPNUM_DST));
				GET_RM(OPNUM_SRC, cmp = LD_REG_val(rm);, cmp = LD_MEM(fn_idx[size_mode], rm););
				break;

			case 0x3B:
				val = LD_REG_val(GET_REG(OPNUM_DST));
				GET_RM(OPNUM_SRC, cmp = LD_REG_val(rm);, cmp = LD_MEM(fn_idx[size_mode], rm););
				break;

			case 0x3C:
				size_mode = SIZE8;
				val = LD_REG_val(GET_REG(OPNUM_DST));
				cmp = GET_IMM8();
				break;

			case 0x3D:
				val = LD_REG_val(GET_REG(OPNUM_DST));
				cmp = GET_IMM();
				break;

			case 0x80:
			case 0x82:
				assert(instr.raw.modrm.reg == 7);
				size_mode = SIZE8;
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				cmp = GET_IMM8();
				break;

			case 0x81:
				assert(instr.raw.modrm.reg == 7);
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				cmp = GET_IMM();
				break;

			case 0x83:
				assert(instr.raw.modrm.reg == 7);
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				cmp = SEXTs(size_mode == SIZE16 ? 16 : 32, GET_IMM8());
				break;

			default:
				LIB86CPU_ABORT();
			}

			sub = SUB(val, cmp);
			SET_FLG_SUB(sub, val, cmp);
		}
		break;

		case ZYDIS_MNEMONIC_CMPSB:
		case ZYDIS_MNEMONIC_CMPSW:
		case ZYDIS_MNEMONIC_CMPSD: {
			switch (instr.opcode)
			{
			case 0xA6:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xA7: {
				Value *val, *df, *sub, *addr1, *addr2, *src1, *src2, *esi, *edi;
				std::vector<BasicBlock *> vec_bb = getBBs(3);

				if ((instr.attributes & ZYDIS_ATTRIB_HAS_REPNZ) || (instr.attributes & ZYDIS_ATTRIB_HAS_REPZ)) {
					REP_start();
				}

				switch (addr_mode)
				{
				case ADDR16:
					esi = ZEXT32(LD_R16(ESI_idx));
					addr1 = ADD(LD_SEG_HIDDEN(get_seg_prfx_idx(&instr), SEG_BASE_idx), esi);
					edi = ZEXT32(LD_R16(EDI_idx));
					addr2 = ADD(LD_SEG_HIDDEN(ES_idx, SEG_BASE_idx), edi);
					break;

				case ADDR32:
					esi = LD_R32(ESI_idx);
					addr1 = ADD(LD_SEG_HIDDEN(get_seg_prfx_idx(&instr), SEG_BASE_idx), esi);
					edi = LD_R32(EDI_idx);
					addr2 = ADD(LD_SEG_HIDDEN(ES_idx, SEG_BASE_idx), edi);
					break;

				default:
					LIB86CPU_ABORT();
				}

				switch (size_mode)
				{
				case SIZE8:
					val = CONST32(1);
					src1 = LD_MEM(fn_idx[size_mode], addr1);
					src2 = LD_MEM(fn_idx[size_mode], addr2);
					sub = SUB(src1, src2);
					break;

				case SIZE16:
					val = CONST32(2);
					src1 = LD_MEM(fn_idx[size_mode], addr1);
					src2 = LD_MEM(fn_idx[size_mode], addr2);
					sub = SUB(src1, src2);
					break;

				case SIZE32:
					val = CONST32(4);
					src1 = LD_MEM(fn_idx[size_mode], addr1);
					src2 = LD_MEM(fn_idx[size_mode], addr2);
					sub = SUB(src1, src2);
					break;

				default:
					LIB86CPU_ABORT();
				}

				SET_FLG_SUB(sub, src1, src2);

				df = AND(LD_R32(EFLAGS_idx), CONST32(DF_MASK));
				BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(df, CONST32(0)));

				cpu->bb = vec_bb[0];
				Value *esi_sum = ADD(esi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(esi_sum), ESI_idx) : ST_R32(esi_sum, ESI_idx);
				Value *edi_sum = ADD(edi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(edi_sum), EDI_idx) : ST_R32(edi_sum, EDI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REPNZ) {
					REPNZ();
				}
				else if (instr.attributes & ZYDIS_ATTRIB_HAS_REPZ) {
					REPZ();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[1];
				Value *esi_sub = SUB(esi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(esi_sub), ESI_idx) : ST_R32(esi_sub, ESI_idx);
				Value *edi_sub = SUB(edi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(edi_sub), EDI_idx) : ST_R32(edi_sub, EDI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REPNZ) {
					REPNZ();
				}
				else if (instr.attributes & ZYDIS_ATTRIB_HAS_REPZ) {
					REPZ();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[2];
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_CMPXCHG8B:   BAD;
		case ZYDIS_MNEMONIC_CMPXCHG:     BAD;
		case ZYDIS_MNEMONIC_CPUID:       BAD;
		case ZYDIS_MNEMONIC_CWD: {
			ST_R16(TRUNC16(SHR(SEXT32(LD_R16(EAX_idx)), CONST32(16))), EDX_idx);
		}
		break;

		case ZYDIS_MNEMONIC_CWDE: {
			ST_R32(SEXT32(LD_R16(EAX_idx)), EAX_idx);
		}
		break;

		case ZYDIS_MNEMONIC_DAA: {
			Value *old_al = LD_R8L(EAX_idx);
			Value *old_cf = LD_CF();
			ST_FLG_AUX(AND(LD_FLG_AUX(), CONST32(8)));
			std::vector<BasicBlock *> vec_bb = getBBs(6);
			BR_COND(vec_bb[0], vec_bb[1], OR(ICMP_UGT(AND(old_al, CONST8(0xF)), CONST8(9)), ICMP_NE(LD_AF(), CONST32(0))));
			cpu->bb = vec_bb[0];
			Value *sum = ADD(old_al, CONST8(6));
			ST_R8L(sum, EAX_idx);
			ST_FLG_AUX(OR(OR(AND(GEN_SUM_VEC8(old_al, CONST8(6), sum), CONST32(0x80000000)), old_cf), CONST32(8)));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[1];
			ST_FLG_AUX(CONST32(0));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[2];
			BR_COND(vec_bb[3], vec_bb[4], OR(ICMP_UGT(old_al, CONST8(0x99)), ICMP_NE(old_cf, CONST32(0))));
			cpu->bb = vec_bb[3];
			ST_R8L(ADD(LD_R8L(EAX_idx), CONST8(0x60)), EAX_idx);
			ST_FLG_AUX(OR(LD_FLG_AUX(), CONST32(0x80000000)));
			BR_UNCOND(vec_bb[5]);
			cpu->bb = vec_bb[4];
			ST_FLG_AUX(AND(LD_FLG_AUX(), CONST32(0x7FFFFFFF)));
			BR_UNCOND(vec_bb[5]);
			cpu->bb = vec_bb[5];
			ST_FLG_RES_ext(LD_R8L(EAX_idx));
		}
		break;

		case ZYDIS_MNEMONIC_DAS: {
			Value *old_al = LD_R8L(EAX_idx);
			Value *old_cf = LD_CF();
			ST_FLG_AUX(AND(LD_FLG_AUX(), CONST32(8)));
			std::vector<BasicBlock *> vec_bb = getBBs(5);
			BR_COND(vec_bb[0], vec_bb[1], OR(ICMP_UGT(AND(old_al, CONST8(0xF)), CONST8(9)), ICMP_NE(LD_AF(), CONST32(0))));
			cpu->bb = vec_bb[0];
			Value *sub = SUB(old_al, CONST8(6));
			ST_R8L(sub, EAX_idx);
			ST_FLG_AUX(OR(OR(AND(GEN_SUB_VEC8(old_al, CONST8(6), sub), CONST32(0x80000000)), old_cf), CONST32(8)));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[1];
			ST_FLG_AUX(CONST32(0));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[2];
			BR_COND(vec_bb[3], vec_bb[4], OR(ICMP_UGT(old_al, CONST8(0x99)), ICMP_NE(old_cf, CONST32(0))));
			cpu->bb = vec_bb[3];
			ST_R8L(SUB(LD_R8L(EAX_idx), CONST8(0x60)), EAX_idx);
			ST_FLG_AUX(OR(LD_FLG_AUX(), CONST32(0x80000000)));
			BR_UNCOND(vec_bb[4]);
			cpu->bb = vec_bb[4];
			ST_FLG_RES_ext(LD_R8L(EAX_idx));
		}
		break;

		case ZYDIS_MNEMONIC_DEC: {
			switch (instr.opcode)
			{
			case 0xFE:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x48:
			case 0x49:
			case 0x4A:
			case 0x4B:
			case 0x4C:
			case 0x4D:
			case 0x4E:
			case 0x4F:
			case 0xFF: {
				Value *sub, *val, *one, *cf_old, *rm;
				switch (size_mode)
				{
				case SIZE8:
					one = CONST8(1);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm); sub = SUB(val, one); ST_REG_val(sub, rm);,
						val = LD_MEM(fn_idx[size_mode], rm); sub = SUB(val, one); ST_MEM(fn_idx[size_mode], rm, sub););
					break;

				case SIZE16:
					one = CONST16(1);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm); sub = SUB(val, one); ST_REG_val(sub, rm);,
						val = LD_MEM(fn_idx[size_mode], rm); sub = SUB(val, one); ST_MEM(fn_idx[size_mode], rm, sub););
					break;

				case SIZE32:
					one = CONST32(1);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm); sub = SUB(val, one); ST_REG_val(sub, rm);,
						val = LD_MEM(fn_idx[size_mode], rm); sub = SUB(val, one); ST_MEM(fn_idx[size_mode], rm, sub););
					break;

				default:
					LIB86CPU_ABORT();
				}

				cf_old = LD_CF();
				SET_FLG_SUB(sub, val, one);
				ST_FLG_AUX(OR(OR(cf_old, SHR(XOR(cf_old, LD_OF()), CONST32(1))), AND(LD_FLG_AUX(), CONST32(0x3FFFFFFF))));
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_DIV: {
			switch (instr.opcode)
			{
			case 0xF6:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xF7: {
				assert(instr.raw.modrm.reg == 6);

				Value *val, *reg, *rm, *div;
				std::vector<BasicBlock *> vec_bb = getBBs(3);
				switch (size_mode)
				{
				case SIZE8:
					reg = LD_R16(EAX_idx);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(val, CONST8(0)));
					cpu->bb = vec_bb[0];
					RAISEin0(EXP_DE);
					UNREACH();
					cpu->bb = vec_bb[1];
					div = UDIV(reg, ZEXT16(val));
					BR_COND(vec_bb[0], vec_bb[2], ICMP_UGT(div, CONST16(0xFF)));
					cpu->bb = vec_bb[2];
					ST_REG_val(TRUNC8(div), GEP_R8L(EAX_idx));
					ST_REG_val(TRUNC8(UREM(reg, ZEXT16(val))), GEP_R8H(EAX_idx));
					break;

				case SIZE16:
					reg = OR(SHL(ZEXT32(LD_R16(EDX_idx)), CONST32(16)), ZEXT32(LD_R16(EAX_idx)));
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(val, CONST16(0)));
					cpu->bb = vec_bb[0];
					RAISEin0(EXP_DE);
					UNREACH();
					cpu->bb = vec_bb[1];
					div = UDIV(reg, ZEXT32(val));
					BR_COND(vec_bb[0], vec_bb[2], ICMP_UGT(div, CONST32(0xFFFF)));
					cpu->bb = vec_bb[2];
					ST_REG_val(TRUNC16(div), GEP_R16(EAX_idx));
					ST_REG_val(TRUNC16(UREM(reg, ZEXT32(val))), GEP_R16(EDX_idx));
					break;

				case SIZE32:
					reg = OR(SHL(ZEXT64(LD_R32(EDX_idx)), CONST64(32)), ZEXT64(LD_R32(EAX_idx)));
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(val, CONST32(0)));
					cpu->bb = vec_bb[0];
					RAISEin0(EXP_DE);
					UNREACH();
					cpu->bb = vec_bb[1];
					div = UDIV(reg, ZEXT64(val));
					BR_COND(vec_bb[0], vec_bb[2], ICMP_UGT(div, CONST64(0xFFFFFFFF)));
					cpu->bb = vec_bb[2];
					ST_REG_val(TRUNC32(div), GEP_R32(EAX_idx));
					ST_REG_val(TRUNC32(UREM(reg, ZEXT64(val))), GEP_R32(EDX_idx));
					break;

				default:
					LIB86CPU_ABORT();
				}
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_ENTER: {
			uint32_t nesting_lv = instr.operands[OPNUM_SRC].imm.value.u % 32;
			uint32_t stack_sub, push_tot_size = 0;
			Value *frame_esp, *ebp_addr, *esp_ptr, *ebp_ptr;
			std::vector<Value *> args;

			switch ((size_mode << 1) | ((cpu->cpu_ctx.hflags & HFLG_SS32) >> SS32_SHIFT))
			{
			case 0: { // sp, push 32
				stack_sub = 4;
				esp_ptr = GEP_R32(ESP_idx);
				ebp_ptr = GEP_R32(EBP_idx);
				ebp_addr = ALLOC32();
				ST(ebp_addr, ZEXT32(LD_R16(EBP_idx)));
				frame_esp = OR(ZEXT32(SUB(LD_R16(ESP_idx), CONST16(4))), AND(LD_R32(ESP_idx), CONST32(0xFFFF0000)));
				args.push_back(LD_R32(EBP_idx));
			}
			break;

			case 1: { // esp, push 32
				stack_sub = 4;
				esp_ptr = GEP_R32(ESP_idx);
				ebp_ptr = GEP_R32(EBP_idx);
				ebp_addr = ALLOC32();
				ST(ebp_addr, LD_R32(EBP_idx));
				frame_esp = SUB(LD_R32(ESP_idx), CONST32(4));
				args.push_back(LD_R32(EBP_idx));
			}
			break;

			case 2: { // sp, push 16
				stack_sub = 2;
				esp_ptr = GEP_R16(ESP_idx);
				ebp_ptr = GEP_R16(EBP_idx);
				ebp_addr = ALLOC32();
				ST(ebp_addr, ZEXT32(LD_R16(EBP_idx)));
				frame_esp = SUB(LD_R16(ESP_idx), CONST16(2));
				args.push_back(LD_R16(EBP_idx));
			}
			break;

			case 3: { // esp, push 16
				stack_sub = 2;
				esp_ptr = GEP_R16(ESP_idx);
				ebp_ptr = GEP_R16(EBP_idx);
				ebp_addr = ALLOC32();
				ST(ebp_addr, LD_R32(EBP_idx));
				frame_esp = TRUNC16(SUB(LD_R32(ESP_idx), CONST32(2)));
				args.push_back(LD_R16(EBP_idx));
			}
			break;

			default:
				LIB86CPU_ABORT();
			}

			if (nesting_lv > 0) {
				for (uint32_t i = 1; i < nesting_lv; ++i) {
					ST(ebp_addr, SUB(LD(ebp_addr), CONST32(stack_sub)));
					Value *new_ebp = LD_MEM(fn_idx[size_mode], ADD(LD(ebp_addr), LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)));
					args.push_back(new_ebp);
					push_tot_size += stack_sub;
				}
				args.push_back(frame_esp);
				push_tot_size += stack_sub;
			}
			MEM_PUSH(args);

			ST(ebp_ptr, frame_esp);
			ST(esp_ptr, SUB(SUB(frame_esp, CONSTs(stack_sub << 3, push_tot_size)), CONSTs(stack_sub << 3, instr.operands[OPNUM_DST].imm.value.u)));
		}
		break;

		case ZYDIS_MNEMONIC_HLT: {
			if (cpu_ctx->hflags & HFLG_CPL) {
				RAISEin0(EXP_GP);
				translate_next = 0;
			}
			else {
				// we don't implement interrupts yet, so if we reach here, we will just abort for now
				BAD;
			}
		}
		break;

		case ZYDIS_MNEMONIC_IDIV: {
			switch (instr.opcode)
			{
			case 0xF6:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xF7: {
				assert(instr.raw.modrm.reg == 7);

				Value *val, *reg, *rm, *div;
				std::vector<BasicBlock *> vec_bb = getBBs(3);
				switch (size_mode)
				{
				case SIZE8:
					reg = LD_R16(EAX_idx);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(val, CONST8(0)));
					cpu->bb = vec_bb[0];
					RAISEin0(EXP_DE);
					UNREACH();
					cpu->bb = vec_bb[1];
					div = SDIV(reg, SEXT16(val));
					BR_COND(vec_bb[0], vec_bb[2], ICMP_NE(div, SEXT16(TRUNC8(div))));
					cpu->bb = vec_bb[2];
					ST_REG_val(TRUNC8(div), GEP_R8L(EAX_idx));
					ST_REG_val(TRUNC8(SREM(reg, SEXT16(val))), GEP_R8H(EAX_idx));
					break;

				case SIZE16:
					reg = OR(SHL(ZEXT32(LD_R16(EDX_idx)), CONST32(16)), ZEXT32(LD_R16(EAX_idx)));
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(val, CONST16(0)));
					cpu->bb = vec_bb[0];
					RAISEin0(EXP_DE);
					UNREACH();
					cpu->bb = vec_bb[1];
					div = SDIV(reg, SEXT32(val));
					BR_COND(vec_bb[0], vec_bb[2], ICMP_NE(div, SEXT32(TRUNC16(div))));
					cpu->bb = vec_bb[2];
					ST_REG_val(TRUNC16(div), GEP_R16(EAX_idx));
					ST_REG_val(TRUNC16(SREM(reg, SEXT32(val))), GEP_R16(EDX_idx));
					break;

				case SIZE32:
					reg = OR(SHL(ZEXT64(LD_R32(EDX_idx)), CONST64(32)), ZEXT64(LD_R32(EAX_idx)));
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(val, CONST32(0)));
					cpu->bb = vec_bb[0];
					RAISEin0(EXP_DE);
					UNREACH();
					cpu->bb = vec_bb[1];
					div = SDIV(reg, SEXT64(val));
					BR_COND(vec_bb[0], vec_bb[2], ICMP_NE(div, SEXT64(TRUNC32(div))));
					cpu->bb = vec_bb[2];
					ST_REG_val(TRUNC32(div), GEP_R32(EAX_idx));
					ST_REG_val(TRUNC32(SREM(reg, SEXT64(val))), GEP_R32(EDX_idx));
					break;

				default:
					LIB86CPU_ABORT();
				}
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_IMUL: {
			switch (instr.opcode)
			{
			case 0xF6:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xF7: {
				assert(instr.raw.modrm.reg == 5);

				Value *val, *reg, *rm, *out;
				switch (size_mode)
				{
				case SIZE8:
					reg = LD_R8L(EAX_idx);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(SEXT16(reg), SEXT16(val));
					ST_REG_val(out, GEP_R16(EAX_idx));
					ST_FLG_AUX(SHL(ZEXT32(NOT_ZERO(16, XOR(SEXT16(LD_R8L(EAX_idx)), out))), CONST32(31)));
					break;

				case SIZE16:
					reg = LD_R16(EAX_idx);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(SEXT32(reg), SEXT32(val));
					ST_REG_val(TRUNC16(SHR(out, CONST32(16))), GEP_R16(EDX_idx));
					ST_REG_val(TRUNC16(out), GEP_R16(EAX_idx));
					ST_FLG_AUX(SHL(NOT_ZERO(32, XOR(SEXT32(LD_R16(EAX_idx)), out)), CONST32(31)));
					break;

				case SIZE32:
					reg = LD_R32(EAX_idx);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(SEXT64(reg), SEXT64(val));
					ST_REG_val(TRUNC32(SHR(out, CONST64(32))), GEP_R32(EDX_idx));
					ST_REG_val(TRUNC32(out), GEP_R32(EAX_idx));
					ST_FLG_AUX(SHL(TRUNC32(NOT_ZERO(64, XOR(SEXT64(LD_R32(EAX_idx)), out))), CONST32(31)));
					break;

				default:
					LIB86CPU_ABORT();
				}
			}
			break;

			case 0xAF: {
				Value *val, *reg, *reg_ptr, *rm, *out;
				switch (size_mode)
				{
				case SIZE16:
					reg_ptr = GET_REG(OPNUM_DST);
					reg = LD_REG_val(reg_ptr);
					GET_RM(OPNUM_SRC, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(SEXT32(reg), SEXT32(val));
					ST_REG_val(TRUNC16(out), reg_ptr);
					ST_FLG_AUX(SHL(NOT_ZERO(32, XOR(SEXT32(LD_REG_val(reg_ptr)), out)), CONST32(31)));
					break;

				case SIZE32:
					reg_ptr = GET_REG(OPNUM_DST);
					reg = LD_REG_val(reg_ptr);
					GET_RM(OPNUM_SRC, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(SEXT64(reg), SEXT64(val));
					ST_REG_val(TRUNC32(out), reg_ptr);
					ST_FLG_AUX(SHL(TRUNC32(NOT_ZERO(64, XOR(SEXT64(LD_REG_val(reg_ptr)), out))), CONST32(31)));
					break;

				default:
					LIB86CPU_ABORT();
				}
			}
			break;

			case 0x6B:
			case 0x69: {
				Value *imm = CONSTs(instr.operands[OPNUM_THIRD].size, instr.operands[OPNUM_THIRD].imm.value.u);
				Value *val, *reg_ptr, *rm, *out;
				switch (size_mode)
				{
				case SIZE16:
					reg_ptr = GET_REG(OPNUM_DST);
					GET_RM(OPNUM_SRC, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(SEXT32(val), SEXT32(imm));
					ST_REG_val(TRUNC16(out), reg_ptr);
					ST_FLG_AUX(SHL(NOT_ZERO(32, XOR(SEXT32(LD_REG_val(reg_ptr)), out)), CONST32(31)));
					break;

				case SIZE32:
					reg_ptr = GET_REG(OPNUM_DST);
					GET_RM(OPNUM_SRC, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(SEXT64(val), SEXT64(imm));
					ST_REG_val(TRUNC32(out), reg_ptr);
					ST_FLG_AUX(SHL(TRUNC32(NOT_ZERO(64, XOR(SEXT64(LD_REG_val(reg_ptr)), out))), CONST32(31)));
					break;

				default:
					LIB86CPU_ABORT();
				}
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_IN: {
			switch (instr.opcode)
			{
			case 0xE4:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xE5: {
				Value *port = GET_IMM8();
				check_io_priv_emit(cpu, ZEXT32(port), size_mode);
				Value *val = LD_IO(fn_io_idx[size_mode], ZEXT16(port));
				size_mode == SIZE16 ? ST_R16(val, EAX_idx) : size_mode == SIZE32 ? ST_R32(val, EAX_idx) : ST_R8L(val, EAX_idx);
			}
			break;

			case 0xEC:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xED: {
				Value *port = LD_R16(EDX_idx);
				check_io_priv_emit(cpu, ZEXT32(port), size_mode);
				Value *val = LD_IO(fn_io_idx[size_mode], port);
				size_mode == SIZE16 ? ST_R16(val, EAX_idx) : size_mode == SIZE32 ? ST_R32(val, EAX_idx) : ST_R8L(val, EAX_idx);
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_INC: {
			switch (instr.opcode)
			{
			case 0xFE:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x40:
			case 0x41:
			case 0x42:
			case 0x43:
			case 0x44:
			case 0x45:
			case 0x46:
			case 0x47:
			case 0xFF: {
				Value *sum, *val, *one, *cf_old, *rm;
				switch (size_mode)
				{
				case SIZE8:
					one = CONST8(1);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm); sum = ADD(val, one); ST_REG_val(sum, rm);,
						val = LD_MEM(fn_idx[size_mode], rm); sum = ADD(val, one); ST_MEM(fn_idx[size_mode], rm, sum););
					break;

				case SIZE16:
					one = CONST16(1);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm); sum = ADD(val, one); ST_REG_val(sum, rm);,
						val = LD_MEM(fn_idx[size_mode], rm); sum = ADD(val, one); ST_MEM(fn_idx[size_mode], rm, sum););
					break;

				case SIZE32:
					one = CONST32(1);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm); sum = ADD(val, one); ST_REG_val(sum, rm);,
						val = LD_MEM(fn_idx[size_mode], rm); sum = ADD(val, one); ST_MEM(fn_idx[size_mode], rm, sum););
					break;

				default:
					LIB86CPU_ABORT();
				}

				cf_old = LD_CF();
				SET_FLG_SUM(sum, val, one);
				ST_FLG_AUX(OR(OR(cf_old, SHR(XOR(cf_old, LD_OF()), CONST32(1))), AND(LD_FLG_AUX(), CONST32(0x3FFFFFFF))));
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_INSB:
		case ZYDIS_MNEMONIC_INSD:
		case ZYDIS_MNEMONIC_INSW: {
			switch (instr.opcode)
			{
			case 0x6C:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x6D: {
				Value *val, *df, *addr, *src, *edi, *io_val, *port = LD_R16(EDX_idx);
				check_io_priv_emit(cpu, ZEXT32(port), size_mode);
				std::vector<BasicBlock *> vec_bb = getBBs(3);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP_start();
				}

				switch (addr_mode)
				{
				case ADDR16:
					edi = ZEXT32(LD_R16(EDI_idx));
					addr = ADD(LD_SEG_HIDDEN(ES_idx, SEG_BASE_idx), edi);
					break;

				case ADDR32:
					edi = LD_R32(EDI_idx);
					addr = ADD(LD_SEG_HIDDEN(ES_idx, SEG_BASE_idx), edi);
					break;

				default:
					LIB86CPU_ABORT();
				}

				switch (size_mode)
				{
				case SIZE8:
					val = CONST32(1);
					io_val = LD_IO(IO_LD8_idx, port);
					ST_MEM(MEM_LD8_idx, addr, io_val);
					break;

				case SIZE16:
					val = CONST32(2);
					io_val = LD_IO(IO_LD16_idx, port);
					ST_MEM(MEM_LD16_idx, addr, io_val);
					break;

				case SIZE32:
					val = CONST32(4);
					io_val = LD_IO(IO_LD32_idx, port);
					ST_MEM(MEM_LD32_idx, addr, io_val);
					break;

				default:
					LIB86CPU_ABORT();
				}

				df = AND(LD_R32(EFLAGS_idx), CONST32(DF_MASK));
				BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(df, CONST32(0)));

				cpu->bb = vec_bb[0];
				Value *edi_sum = ADD(edi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(edi_sum), EDI_idx) : ST_R32(edi_sum, EDI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[1];
				Value *edi_sub = SUB(edi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(edi_sub), EDI_idx) : ST_R32(edi_sub, EDI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[2];
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_INT3:        BAD;
		case ZYDIS_MNEMONIC_INT:         BAD;
		case ZYDIS_MNEMONIC_INTO:        BAD;
		case ZYDIS_MNEMONIC_INVD:        BAD;
		case ZYDIS_MNEMONIC_INVLPG:      BAD;
		case ZYDIS_MNEMONIC_IRET:
		case ZYDIS_MNEMONIC_IRETD: {
			assert(instr.opcode == 0xCF);

			if (cpu->cpu_ctx.hflags & HFLG_PE_MODE) {
				ret_pe_emit(cpu, size_mode, true);
			}
			else {
				std::vector<Value *> vec = MEM_POP(3);
				Value *eip = vec[0];
				Value *cs = vec[1];
				Value *eflags = vec[2];
				Value *mask;

				if (size_mode == SIZE16) {
					eip = ZEXT32(eip);
					eflags = ZEXT32(eflags);
					mask = CONST32(NT_MASK | IOPL_MASK | DF_MASK | IF_MASK | TF_MASK);
				}
				else {
					cs = TRUNC16(cs);
					mask = CONST32(ID_MASK | AC_MASK | RF_MASK | NT_MASK | IOPL_MASK | DF_MASK | IF_MASK | TF_MASK);
				}

				ST_REG_val(vec[3], vec[4]);
				ST_R32(eip, EIP_idx);
				ST_SEG(cs, CS_idx);
				ST_SEG_HIDDEN(SHL(ZEXT32(cs), CONST32(4)), CS_idx, SEG_BASE_idx);
				write_eflags(cpu, eflags, mask);
			}

			cpu->tc->flags |= TC_FLG_INDIRECT;
			translate_next = 0;
		}
		break;

		case ZYDIS_MNEMONIC_JCXZ:
		case ZYDIS_MNEMONIC_JECXZ:
		case ZYDIS_MNEMONIC_JO:
		case ZYDIS_MNEMONIC_JNO:
		case ZYDIS_MNEMONIC_JB:
		case ZYDIS_MNEMONIC_JNB:
		case ZYDIS_MNEMONIC_JZ:
		case ZYDIS_MNEMONIC_JNZ:
		case ZYDIS_MNEMONIC_JBE:
		case ZYDIS_MNEMONIC_JNBE:
		case ZYDIS_MNEMONIC_JS:
		case ZYDIS_MNEMONIC_JNS:
		case ZYDIS_MNEMONIC_JP:
		case ZYDIS_MNEMONIC_JNP:
		case ZYDIS_MNEMONIC_JL:
		case ZYDIS_MNEMONIC_JNL:
		case ZYDIS_MNEMONIC_JLE:
		case ZYDIS_MNEMONIC_JNLE: {
			Value *val;
			switch (instr.opcode)
			{
			case 0x70:
			case 0x80:
				val = ICMP_NE(LD_OF(), CONST32(0)); // OF != 0
				break;

			case 0x71:
			case 0x81:
				val = ICMP_EQ(LD_OF(), CONST32(0)); // OF == 0
				break;

			case 0x72:
			case 0x82:
				val = ICMP_NE(LD_CF(), CONST32(0)); // CF != 0
				break;

			case 0x73:
			case 0x83:
				val = ICMP_EQ(LD_CF(), CONST32(0)); // CF == 0
				break;

			case 0x74:
			case 0x84:
				val = ICMP_EQ(LD_ZF(), CONST32(0)); // ZF != 0
				break;

			case 0x75:
			case 0x85:
				val = ICMP_NE(LD_ZF(), CONST32(0)); // ZF == 0
				break;

			case 0x76:
			case 0x86:
				val = OR(ICMP_NE(LD_CF(), CONST32(0)), ICMP_EQ(LD_ZF(), CONST32(0))); // CF != 0 OR ZF != 0
				break;

			case 0x77:
			case 0x87:
				val = AND(ICMP_EQ(LD_CF(), CONST32(0)), ICMP_NE(LD_ZF(), CONST32(0))); // CF == 0 AND ZF == 0
				break;

			case 0x78:
			case 0x88:
				val = ICMP_NE(LD_SF(), CONST32(0)); // SF != 0
				break;

			case 0x79:
			case 0x89:
				val = ICMP_EQ(LD_SF(), CONST32(0)); // SF == 0
				break;

			case 0x7A:
			case 0x8A:
				val = ICMP_EQ(LD_PF(), CONST8(0)); // PF != 0
				break;

			case 0x7B:
			case 0x8B:
				val = ICMP_NE(LD_PF(), CONST8(0)); // PF == 0
				break;

			case 0x7C:
			case 0x8C:
				val = ICMP_NE(LD_SF(), SHR(LD_OF(), CONST32(31))); // SF != OF
				break;

			case 0x7D:
			case 0x8D:
				val = ICMP_EQ(LD_SF(), SHR(LD_OF(), CONST32(31))); // SF == OF
				break;

			case 0x7E:
			case 0x8E:
				val = OR(ICMP_EQ(LD_ZF(), CONST32(0)), ICMP_NE(LD_SF(), SHR(LD_OF(), CONST32(31)))); // ZF != 0 OR SF != OF
				break;

			case 0x7F:
			case 0x8F:
				val = AND(ICMP_NE(LD_ZF(), CONST32(0)), ICMP_EQ(LD_SF(), SHR(LD_OF(), CONST32(31)))); // ZF == 0 AND SF == OF
				break;

			case 0xE3:
				val = addr_mode == ADDR16 ? ICMP_EQ(LD_R16(ECX_idx), CONST16(0)) : ICMP_EQ(LD_R32(ECX_idx), CONST32(0)); // ECX == 0
				break;

			default:
				LIB86CPU_ABORT();
			}

			Value *dst_pc = ALLOC32();
			std::vector<BasicBlock *> vec_bb = getBBs(3);
			BR_COND(vec_bb[0], vec_bb[1], val);

			cpu->bb = vec_bb[1];
			Value *next_pc = calc_next_pc_emit(cpu, bytes);
			ST(dst_pc, next_pc);
			BR_UNCOND(vec_bb[2]);

			addr_t jump_eip = (pc - cpu_ctx->regs.cs_hidden.base) + bytes + instr.operands[OPNUM_SINGLE].imm.value.s;
			if (size_mode == SIZE16) {
				jump_eip &= 0x0000FFFF;
			}
			cpu->bb = vec_bb[0];
			ST(GEP_EIP(), CONST32(jump_eip));
			ST(dst_pc, CONST32(jump_eip + cpu_ctx->regs.cs_hidden.base));
			BR_UNCOND(vec_bb[2]);

			cpu->bb = vec_bb[2];
			link_direct_emit(cpu, std::vector <addr_t> { pc, cpu_ctx->regs.cs_hidden.base + jump_eip, pc + bytes }, LD(dst_pc));
			cpu->tc->flags |= TC_FLG_DIRECT;
			translate_next = 0;
		}
		break;

		case ZYDIS_MNEMONIC_JMP: {
			switch (instr.opcode)
			{
			case 0xE9:
			case 0xEB: {
				addr_t new_eip = (pc - cpu_ctx->regs.cs_hidden.base) + bytes + instr.operands[OPNUM_SINGLE].imm.value.s;
				if (size_mode == SIZE16) {
					new_eip &= 0x0000FFFF;
				}
				ST_R32(CONST32(new_eip), EIP_idx);
				link_direct_emit(cpu, std::vector <addr_t> { pc, cpu_ctx->regs.cs_hidden.base + new_eip }, CONST32(cpu_ctx->regs.cs_hidden.base + new_eip));
				cpu->tc->flags |= TC_FLG_DIRECT;
			}
			break;

			case 0xEA: {
				addr_t new_eip = instr.operands[OPNUM_SINGLE].ptr.offset;
				uint16_t new_sel = instr.operands[OPNUM_SINGLE].ptr.segment;
				if (cpu_ctx->hflags & HFLG_PE_MODE) {
					ljmp_pe_emit(cpu, CONST16(new_sel), size_mode, new_eip);
					cpu->tc->flags |= TC_FLG_INDIRECT;
				}
				else {
					new_eip = size_mode == SIZE16 ? new_eip & 0xFFFF : new_eip;
					ST_SEG(CONST16(new_sel), CS_idx);
					ST_R32(CONST32(new_eip), EIP_idx);
					ST_SEG_HIDDEN(CONST32(static_cast<uint32_t>(new_sel) << 4), CS_idx, SEG_BASE_idx);
					link_direct_emit(cpu, std::vector <addr_t> { pc, (static_cast<uint32_t>(new_sel) << 4) + new_eip }, CONST32((static_cast<uint32_t>(new_sel) << 4) + new_eip));
					cpu->tc->flags |= TC_FLG_DIRECT;
				}
			}
			break;

			case 0xFF: {
				if (instr.raw.modrm.reg == 4) {
					Value *rm, *offset, *new_eip;
					GET_RM(OPNUM_SINGLE, offset = LD_REG_val(rm); , offset = LD_MEM(fn_idx[size_mode], rm););
					if (size_mode == SIZE16) {
						new_eip = ZEXT32(offset);
						ST_R32(new_eip, EIP_idx);
					}
					else {
						new_eip = offset;
						ST_R32(new_eip, EIP_idx);
					}
					cpu->tc->flags |= TC_FLG_INDIRECT;
				}
				else if (instr.raw.modrm.reg == 5) {
					BAD;
				}
				else {
					LIB86CPU_ABORT();
				}
			}
			break;

			default:
				LIB86CPU_ABORT();
			}

			translate_next = 0;
		}
		break;

		case ZYDIS_MNEMONIC_LAHF: {
			Value *flags = OR(OR(OR(OR(OR(SHR(LD_CF(), CONST32(31)),
				SHL(XOR(NOT_ZERO(32, LD_ZF()), CONST32(1)), CONST32(6))),
				SHL(LD_SF(), CONST32(7))),
				SHL(XOR(ZEXT32(LD_PF()), CONST32(1)), CONST32(2))),
				SHL(LD_AF(), CONST32(1))),
				CONST32(2)
			);

			ST_R8H(TRUNC8(flags), EAX_idx);
		}
		break;

		case ZYDIS_MNEMONIC_LAR:         BAD;
		case ZYDIS_MNEMONIC_LEA: {
			Value *rm, *reg, *offset;
			GET_RM(OPNUM_SRC, assert(0);, offset = SUB(rm, LD_SEG_HIDDEN(get_reg_idx(instr.operands[OPNUM_SRC].mem.segment), SEG_BASE_idx));
			offset = addr_mode == ADDR16 ? TRUNC16(offset) : offset;);
			reg = GET_REG(OPNUM_DST);

			switch (size_mode)
			{
			case SIZE16:
				addr_mode == ADDR16 ? ST_REG_val(offset, reg) : ST_REG_val(TRUNC16(offset), reg);
				break;

			case SIZE32:
				addr_mode == ADDR16 ? ST_REG_val(ZEXT32(offset), reg) : ST_REG_val(offset, reg);
				break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_LEAVE: {
			switch ((size_mode << 1) | ((cpu->cpu_ctx.hflags & HFLG_SS32) >> SS32_SHIFT))
			{
			case 0: { // sp, pop 32
				ST_R16(LD_R16(EBP_idx), ESP_idx);
				std::vector<Value *> vec_pop = MEM_POP(1);
				ST_R32(vec_pop[0], EBP_idx);
				ST_R16(vec_pop[1], ESP_idx);
			}
			break;

			case 1: { // esp, pop 32
				ST_R32(LD_R32(EBP_idx), ESP_idx);
				std::vector<Value *> vec_pop = MEM_POP(1);
				ST_R32(vec_pop[0], EBP_idx);
				ST_R32(vec_pop[1], ESP_idx);
			}
			break;

			case 2: { // sp, pop 16
				ST_R16(LD_R16(EBP_idx), ESP_idx);
				std::vector<Value *> vec_pop = MEM_POP(1);
				ST_R16(vec_pop[0], EBP_idx);
				ST_R16(vec_pop[1], ESP_idx);
			}
			break;

			case 3: { // esp, pop 16
				ST_R32(LD_R32(EBP_idx), ESP_idx);
				std::vector<Value *> vec_pop = MEM_POP(1);
				ST_R16(vec_pop[0], EBP_idx);
				ST_R32(vec_pop[1], ESP_idx);
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_LGDT:
		case ZYDIS_MNEMONIC_LIDT: {
			Value *rm, *limit, *base;
			uint8_t reg_idx;
			if (instr.mnemonic == ZYDIS_MNEMONIC_LGDT) {
				assert(instr.raw.modrm.reg == 2);
				reg_idx = GDTR_idx;
			}
			else {
				assert(instr.raw.modrm.reg == 3);
				reg_idx = IDTR_idx;
			}
			GET_RM(OPNUM_SINGLE, assert(0);, limit = LD_MEM(MEM_LD16_idx, rm); rm = ADD(rm, CONST32(2)); base = LD_MEM(MEM_LD32_idx, rm););
			if (size_mode == SIZE16) {
				base = AND(base, CONST32(0x00FFFFFF));
			}
			ST_SEG_HIDDEN(base, reg_idx, SEG_BASE_idx);
			ST_SEG_HIDDEN(ZEXT32(limit), reg_idx, SEG_LIMIT_idx);
		}
		break;

		case ZYDIS_MNEMONIC_LLDT: {
			assert(instr.raw.modrm.reg == 2);

			if (cpu_ctx->hflags & HFLG_CPL) {
				RAISEin0(EXP_GP);
				translate_next = 0;
			}
			else {
				Value *sel, *rm;
				std::vector<BasicBlock *> vec_bb = getBBs(5);
				GET_RM(OPNUM_SINGLE, sel = LD_REG_val(rm);, sel = LD_MEM(MEM_LD16_idx, rm););
				BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(SHR(sel, CONST16(2)), CONST16(0)));
				cpu->bb = vec_bb[0];
				write_seg_reg_emit(cpu, LDTR_idx, std::vector<Value *> { sel, CONST32(0), CONST32(0), CONST32(0) });
				BR_UNCOND(vec_bb[4]);
				cpu->bb = vec_bb[1];
				Value *desc = read_seg_desc_emit(cpu, sel)[1];
				Value *s = SHR(AND(desc, CONST64(SEG_DESC_S)), CONST64(40));
				Value *ty = SHR(AND(desc, CONST64(SEG_DESC_TY)), CONST64(40));
				BasicBlock *bb_exp = RAISE(AND(sel, CONST16(0xFFFC)), EXP_GP);
				BR_COND(bb_exp, vec_bb[2], ICMP_NE(XOR(OR(s, ty), CONST64(SEG_DESC_LDT)), CONST64(0))); // must be ldt type
				cpu->bb = vec_bb[2];
				Value *p = AND(desc, CONST64(SEG_DESC_P));
				bb_exp = RAISE(AND(sel, CONST16(0xFFFC)), EXP_NP);
				BR_COND(bb_exp, vec_bb[3], ICMP_EQ(p, CONST64(0))); // segment not present
				cpu->bb = vec_bb[3];
				write_seg_reg_emit(cpu, LDTR_idx, std::vector<Value *> { sel, read_seg_desc_base_emit(cpu, desc),
					read_seg_desc_limit_emit(cpu, desc), read_seg_desc_flags_emit(cpu, desc)});
				BR_UNCOND(vec_bb[4]);
				cpu->bb = vec_bb[4];
			}
		}
		break;

		case ZYDIS_MNEMONIC_LMSW:        BAD;
		case ZYDIS_MNEMONIC_LODSB:
		case ZYDIS_MNEMONIC_LODSD:
		case ZYDIS_MNEMONIC_LODSW: {
			switch (instr.opcode)
			{
			case 0xAC:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xAD: {
				Value *val, *df, *addr, *src, *esi;
				std::vector<BasicBlock *> vec_bb = getBBs(3);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP_start();
				}

				switch (addr_mode)
				{
				case ADDR16:
					esi = ZEXT32(LD_R16(ESI_idx));
					addr = ADD(LD_SEG_HIDDEN(get_seg_prfx_idx(&instr), SEG_BASE_idx), esi);
					break;

				case ADDR32:
					esi = LD_R32(ESI_idx);
					addr = ADD(LD_SEG_HIDDEN(get_seg_prfx_idx(&instr), SEG_BASE_idx), esi);
					break;

				default:
					LIB86CPU_ABORT();
				}

				switch (size_mode)
				{
				case SIZE8:
					val = CONST32(1);
					src = LD_MEM(fn_idx[size_mode], addr);
					ST_R8L(src, EAX_idx);
					break;

				case SIZE16:
					val = CONST32(2);
					src = LD_MEM(fn_idx[size_mode], addr);
					ST_R16(src, EAX_idx);
					break;

				case SIZE32:
					val = CONST32(4);
					src = LD_MEM(fn_idx[size_mode], addr);
					ST_R32(src, EAX_idx);
					break;

				default:
					LIB86CPU_ABORT();
				}

				df = AND(LD_R32(EFLAGS_idx), CONST32(DF_MASK));
				BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(df, CONST32(0)));

				cpu->bb = vec_bb[0];
				Value *esi_sum = ADD(esi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(esi_sum), ESI_idx) : ST_R32(esi_sum, ESI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[1];
				Value *esi_sub = SUB(esi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(esi_sub), ESI_idx) : ST_R32(esi_sub, ESI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[2];
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_LOOP:
		case ZYDIS_MNEMONIC_LOOPE:
		case ZYDIS_MNEMONIC_LOOPNE: {
			Value *val, *zero, *zf;
			switch (instr.opcode)
			{
			case 0xE0:
				zf = ICMP_NE(LD_ZF(), CONST32(0));
				break;

			case 0xE1:
				zf = ICMP_EQ(LD_ZF(), CONST32(0));
				break;

			case 0xE2:
				zf = CONSTs(1, 1);
				break;

			default:
				LIB86CPU_ABORT();
			}

			switch (addr_mode)
			{
			case ADDR16:
				val = SUB(LD_R16(ECX_idx), CONST16(1));
				ST_R16(val, ECX_idx);
				zero = CONST16(0);
				break;

			case ADDR32:
				val = SUB(LD_R32(ECX_idx), CONST32(1));
				ST_R32(val, ECX_idx);
				zero = CONST32(0);
				break;

			default:
				LIB86CPU_ABORT();
			}

			Value *dst_pc = ALLOC32();
			std::vector<BasicBlock *> vec_bb = getBBs(3);
			BR_COND(vec_bb[0], vec_bb[1], AND(ICMP_NE(val, zero), zf));

			cpu->bb = vec_bb[1];
			Value *exit_pc = calc_next_pc_emit(cpu, bytes);
			ST(dst_pc, exit_pc);
			BR_UNCOND(vec_bb[2]);

			addr_t loop_eip = (pc - cpu_ctx->regs.cs_hidden.base) + bytes + instr.operands[OPNUM_SINGLE].imm.value.s;
			if (size_mode == SIZE16) {
				loop_eip &= 0x0000FFFF;
			}
			cpu->bb = vec_bb[0];
			ST(GEP_EIP(), CONST32(loop_eip));
			ST(dst_pc, CONST32(loop_eip + cpu_ctx->regs.cs_hidden.base));
			BR_UNCOND(vec_bb[2]);

			cpu->bb = vec_bb[2];
			link_direct_emit(cpu, std::vector <addr_t> { pc, cpu_ctx->regs.cs_hidden.base + loop_eip, pc + bytes }, LD(dst_pc));
			cpu->tc->flags |= TC_FLG_DIRECT;
			translate_next = 0;
		}
		break;

		case ZYDIS_MNEMONIC_LSL:         BAD;
		case ZYDIS_MNEMONIC_LDS:
		case ZYDIS_MNEMONIC_LES:
		case ZYDIS_MNEMONIC_LFS:
		case ZYDIS_MNEMONIC_LGS:
		case ZYDIS_MNEMONIC_LSS: {
			Value *offset, *sel, *rm;
			unsigned sel_idx;
			GET_RM(OPNUM_SRC, assert(0);, offset = LD_MEM(fn_idx[size_mode], rm);
			rm = size_mode == SIZE16 ? ADD(rm, CONST32(2)) : ADD(rm, CONST32(4));
			sel = LD_MEM(MEM_LD16_idx, rm););

			switch (instr.opcode)
			{
			case 0xB2:
				sel_idx = SS_idx;
				break;

			case 0xB4:
				sel_idx = FS_idx;
				break;

			case 0xB5:
				sel_idx = GS_idx;
				break;

			case 0xC4:
				sel_idx = ES_idx;
				break;

			case 0xC5:
				sel_idx = DS_idx;
				break;

			default:
				LIB86CPU_ABORT();
			}

			if (cpu_ctx->hflags & HFLG_PE_MODE) {
				std::vector<Value *> vec;

				if (sel_idx == SS_idx) {
					vec = check_ss_desc_priv_emit(cpu, sel);
					set_access_flg_seg_desc_emit(cpu, vec[1], vec[0]);
					write_seg_reg_emit(cpu, sel_idx, std::vector<Value *> { sel, read_seg_desc_base_emit(cpu, vec[1]),
						read_seg_desc_limit_emit(cpu, vec[1]), read_seg_desc_flags_emit(cpu, vec[1])});
					ST(GEP_EIP(), ADD(cpu->instr_eip, CONST32(bytes)));
					ST_REG_val(offset, GET_REG(OPNUM_DST));
					if (((pc + bytes) & ~PAGE_MASK) == (pc & ~PAGE_MASK)) {
						std:: vector<BasicBlock *> vec_bb = getBBs(2);
						BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(CONST32(cpu->cpu_ctx.hflags & HFLG_SS32), AND(LD(cpu->ptr_hflags), CONST32(HFLG_SS32))));
						cpu->bb = vec_bb[0];
						link_dst_only_emit(cpu);
						cpu->bb = vec_bb[1];
						cpu->tc->flags |= TC_FLG_DST_ONLY;
					}
					translate_next = 0;
				}
				else {
					std::vector<BasicBlock *> vec_bb = getBBs(3);
					BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(SHR(sel, CONST16(2)), CONST16(0)));
					cpu->bb = vec_bb[0];
					write_seg_reg_emit(cpu, sel_idx, std::vector<Value *> { sel, CONST32(0), CONST32(0), CONST32(0) });
					BR_UNCOND(vec_bb[2]);
					cpu->bb = vec_bb[1];
					vec = check_seg_desc_priv_emit(cpu, sel);
					set_access_flg_seg_desc_emit(cpu, vec[1], vec[0]);
					write_seg_reg_emit(cpu, sel_idx, std::vector<Value *> { sel /* & rpl?? */, read_seg_desc_base_emit(cpu, vec[1]),
						read_seg_desc_limit_emit(cpu, vec[1]), read_seg_desc_flags_emit(cpu, vec[1])});
					BR_UNCOND(vec_bb[2]);
					cpu->bb = vec_bb[2];
					ST_REG_val(offset, GET_REG(OPNUM_DST));
				}
			}
			else {
				ST_SEG(sel, sel_idx);
				ST_SEG_HIDDEN(SHL(ZEXT32(sel), CONST32(4)), sel_idx, SEG_BASE_idx);
				ST_REG_val(offset, GET_REG(OPNUM_DST));
			}
		}
		break;

		case ZYDIS_MNEMONIC_LTR: {
			assert(instr.raw.modrm.reg == 3);

			if (cpu_ctx->hflags & HFLG_CPL) {
				RAISEin0(EXP_GP);
				translate_next = 0;
			}
			else {
				Value *sel, *rm;
				std::vector<BasicBlock *> vec_bb = getBBs(5);
				GET_RM(OPNUM_SINGLE, sel = LD_REG_val(rm);, sel = LD_MEM(MEM_LD16_idx, rm););
				BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(SHR(sel, CONST16(2)), CONST16(0)));
				cpu->bb = vec_bb[0];
				write_seg_reg_emit(cpu, TR_idx, std::vector<Value *> { sel, CONST32(0), CONST32(0), CONST32(0) });
				BR_UNCOND(vec_bb[4]);
				cpu->bb = vec_bb[1];
				std::vector<Value *> vec = read_tss_desc_emit(cpu, sel);
				Value *desc = vec[1];
				Value *s = SHR(AND(desc, CONST64(SEG_DESC_S)), CONST64(40));
				Value *ty = SHR(AND(desc, CONST64(SEG_DESC_TY)), CONST64(40));
				BasicBlock *bb_exp = RAISE(AND(sel, CONST16(0xFFFC)), EXP_GP);
				Value *val = OR(ICMP_EQ(OR(s, ty), CONST64(SEG_DESC_TSS16AV)), ICMP_EQ(OR(s, ty), CONST64(SEG_DESC_TSS32AV)));
				BR_COND(bb_exp, vec_bb[2], ICMP_EQ(val, CONSTs(1, 0))); // must be an available tss
				cpu->bb = vec_bb[2];
				Value *p = AND(desc, CONST64(SEG_DESC_P));
				bb_exp = RAISE(AND(sel, CONST16(0xFFFC)), EXP_NP);
				BR_COND(bb_exp, vec_bb[3], ICMP_EQ(p, CONST64(0))); // segment not present
				cpu->bb = vec_bb[3];
				ST_MEM_PRIV(MEM_LD64_idx, vec[0], OR(desc, CONST64(SEG_DESC_BY)));
				write_seg_reg_emit(cpu, TR_idx, std::vector<Value *> { sel, read_seg_desc_base_emit(cpu, desc),
					read_seg_desc_limit_emit(cpu, desc), read_seg_desc_flags_emit(cpu, desc)});
				BR_UNCOND(vec_bb[4]);
				cpu->bb = vec_bb[4];
			}
		}
		break;

		case ZYDIS_MNEMONIC_MOV:
			switch (instr.opcode)
			{
			case 0x20: {
				if (cpu_ctx->hflags & HFLG_CPL) {
					RAISEin0(EXP_GP);
					translate_next = 0;
				}
				else {
					ST_R32(LD_REG_val(GET_REG(OPNUM_SRC)), GET_REG_idx(instr.operands[OPNUM_DST].reg.value));
				}
			}
			break;

			case 0x21: {
				std::vector<BasicBlock *> vec_bb = getBBs(2);
				BR_COND(vec_bb[0], vec_bb[1], ICMP_NE(AND(LD_R32(DR7_idx), CONST32(DR7_GD_MASK)), CONST32(0)));
				cpu->bb = vec_bb[0];
				ST_R32(OR(LD_R32(DR6_idx), CONST32(DR6_BD_MASK)), DR6_idx); // can't just use RAISE0 because we need to set bd in dr6
				RAISEin0(EXP_DB);
				UNREACH();
				cpu->bb = vec_bb[1];
				if (cpu_ctx->hflags & HFLG_CPL) {
					RAISEin0(EXP_GP);
					translate_next = 0;
				}
				else {
					int dr_offset = 0;
					if (((instr.operands[OPNUM_SRC].reg.value == ZYDIS_REGISTER_DR4) || (instr.operands[OPNUM_SRC].reg.value == ZYDIS_REGISTER_DR5))) {
						BasicBlock *bb = getBB();
						BR_COND(RAISE0(EXP_UD), bb, ICMP_NE(AND(LD_R32(CR4_idx), CONST32(CR4_DE_MASK)), CONST32(0)));
						cpu->bb = bb;
						dr_offset = 2; // turns dr4/5 to dr6/7
					}
					ST_R32(LD_R32(GET_REG_idx(instr.operands[OPNUM_SRC].reg.value) + dr_offset),
						GET_REG_idx(instr.operands[OPNUM_DST].reg.value));
				}
			}
			break;

			case 0x22: {
				if (cpu_ctx->hflags & HFLG_CPL) {
					RAISEin0(EXP_GP);
					translate_next = 0;
				}
				else {
					Value *val = LD_REG_val(GET_REG(OPNUM_SRC));
					switch (instr.operands[OPNUM_DST].reg.value)
					{
					case ZYDIS_REGISTER_CR0:
						translate_next = 0;
						[[fallthrough]];

					case ZYDIS_REGISTER_CR3:
					case ZYDIS_REGISTER_CR4: {
						Function *crN_fn = cast<Function>(cpu->mod->getOrInsertFunction("cpu_update_crN", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
							getIntegerType(32), getIntegerType(8), getIntegerType(32), getIntegerType(32)));
						CallInst *ci = CallInst::Create(crN_fn, std::vector<Value *>{ cpu->ptr_cpu_ctx, val, CONST8(GET_REG_idx(instr.operands[OPNUM_DST].reg.value) - CR_offset),
							cpu->instr_eip, CONST32(bytes) }, "", cpu->bb);
						std::vector<BasicBlock *> vec_bb = getBBs(1);
						BR_COND(RAISE(CONST16(0), EXP_GP), vec_bb[0], ICMP_NE(ci, CONST8(0)));
						cpu->bb = vec_bb[0];
					}
					break;

					case ZYDIS_REGISTER_CR2:
						ST_R32(val, CR2_idx);
						break;

					default:
						LIB86CPU_ABORT();
					}
				}
			}
			break;

			case 0x23: {
				std::vector<BasicBlock *> vec_bb = getBBs(2);
				BR_COND(vec_bb[0], vec_bb[1], ICMP_NE(AND(LD_R32(DR7_idx), CONST32(DR7_GD_MASK)), CONST32(0)));
				cpu->bb = vec_bb[0];
				ST_R32(OR(LD_R32(DR6_idx), CONST32(DR6_BD_MASK)), DR6_idx); // can't just use RAISE0 because we need to set bd in dr6
				RAISEin0(EXP_DB);
				UNREACH();
				cpu->bb = vec_bb[1];
				if (cpu_ctx->hflags & HFLG_CPL) {
					RAISEin0(EXP_GP);
					translate_next = 0;
				}
				else {
					int dr_offset = 0, dr_idx = GET_REG_idx(instr.operands[OPNUM_DST].reg.value);
					Value *reg = ALLOC32();
					ST(reg, LD_R32(GET_REG_idx(instr.operands[OPNUM_SRC].reg.value)));
					switch (dr_idx)
					{
					case DR0_idx:
					case DR1_idx:
					case DR2_idx:
					case DR3_idx: {
						// we cannot just look for the single watchpoint we are updating because it's possible that other watchpoints exist in the same page
						for (int idx = 0; idx < 4; ++idx) {
							std::vector<BasicBlock *> vec_bb = getBBs(2);
							Value *tlb_old_idx = GEP(cpu->ptr_tlb, SHR(LD_R32(idx), CONST32(PAGE_SHIFT)));
							Value *tlb_new_idx = GEP(cpu->ptr_tlb, SHR(LD(reg), CONST32(PAGE_SHIFT)));
							ST(tlb_old_idx, AND(LD(tlb_old_idx), CONST32(~TLB_WATCH))); // remove existing watchpoint
							BR_COND(vec_bb[0], vec_bb[1], ICMP_NE(AND(SHR(LD_R32(DR7_idx), CONST32(idx * 2)), CONST32(3)), CONST32(0)));
							cpu->bb = vec_bb[0];
							ST(tlb_new_idx, OR(LD(tlb_new_idx), CONST32(TLB_WATCH))); // install new watchpoint if enabled
							BR_UNCOND(vec_bb[1]);
							cpu->bb = vec_bb[1];
						}
						// invalidate the tc if it is an instr breakpoint. This, because those are only checked at translation time and not at runtime. If we don't, the existing
						// tc's will stil break on the old address. Note that this is not a problem for data watchpoints because those are signaled as a flag in the tlb, which is
						// always checked at runtime by the tc's
						std::vector<BasicBlock *> vec_bb = getBBs(2);
						BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(AND(SHR(LD_R32(DR7_idx), CONST32(DR7_TYPE_SHIFT + (dr_idx - DR_offset) * 4)), CONST32(3)), CONST32(DR7_TYPE_INSTR)));
						cpu->bb = vec_bb[0];
						CallInst::Create(cpu->ptr_invtc_fn, std::vector<Value *> { cpu->ptr_cpu_ctx, ConstantExpr::getIntToPtr(INTPTR(cpu->tc), cpu->bb->getParent()->getReturnType()),
							LD_R32(dr_idx), CONST8(1), cpu->instr_eip }, "", cpu->bb);
						BR_UNCOND(vec_bb[1]);
						cpu->bb = vec_bb[1];
					}
					break;

					case DR4_idx: {
						BasicBlock *bb = getBB();
						BR_COND(RAISE0(EXP_UD), bb, ICMP_NE(AND(LD_R32(CR4_idx), CONST32(CR4_DE_MASK)), CONST32(0)));
						cpu->bb = bb;
						dr_offset = 2; // turns dr4 to dr6
					}
					[[fallthrough]];

					case DR6_idx:
						ST(reg, OR(LD(reg), CONST32(DR6_RES_MASK)));
						break;

					case DR5_idx: {
						BasicBlock *bb = getBB();
						BR_COND(RAISE0(EXP_UD), bb, ICMP_NE(AND(LD_R32(CR4_idx), CONST32(CR4_DE_MASK)), CONST32(0)));
						cpu->bb = bb;
						dr_offset = 2; // turns dr5 to dr7
					}
					[[fallthrough]];

					case DR7_idx: {
						ST(reg, OR(LD(reg), CONST32(DR7_RES_MASK)));
						for (int idx = 0; idx < 4; ++idx) {
							std::vector<BasicBlock *> vec_bb = getBBs(7);
							Value *curr_watch_addr = LD_R32(DR_offset + idx);
							Value *tlb_idx = GEP(cpu->ptr_tlb, SHR(curr_watch_addr, CONST32(PAGE_SHIFT)));
							// we don't support task switches, so local and global enable flags are the same for now
							BR_COND(vec_bb[0], vec_bb[1], ICMP_NE(AND(SHR(LD(reg), CONST32(idx * 2)), CONST32(3)), CONST32(0)));
							cpu->bb = vec_bb[0];
							BR_COND(vec_bb[2], vec_bb[3], ICMP_EQ(OR(AND(SHR(LD(reg), CONST32(DR7_TYPE_SHIFT + idx * 4)), CONST32(3)),
								AND(LD_R32(CR4_idx), CONST32(CR4_DE_MASK))), CONST32(DR7_TYPE_IO_RW | CR4_DE_MASK)));
							cpu->bb = vec_bb[2];
							// we don't support io watchpoints yet so for now we just abort
							ABORT("Io watchpoints are not supported");
							UNREACH();
							cpu->bb = vec_bb[3];
							ST(tlb_idx, OR(LD(tlb_idx), CONST32(TLB_WATCH))); // install watchpoint
							BR_UNCOND(vec_bb[4]);
							cpu->bb = vec_bb[1];
							ST(tlb_idx, AND(LD(tlb_idx), CONST32(~TLB_WATCH))); // remove watchpoint
							BR_UNCOND(vec_bb[4]);
							cpu->bb = vec_bb[4];
							BR_COND(vec_bb[5], vec_bb[6], ICMP_EQ(AND(SHR(LD(reg), CONST32(DR7_TYPE_SHIFT + idx * 4)), CONST32(3)), CONST32(DR7_TYPE_INSTR)));
							cpu->bb = vec_bb[5];
							// invalidate the tc if it is an instr breakpoint. Same as above
							CallInst::Create(cpu->ptr_invtc_fn, std::vector<Value *> { cpu->ptr_cpu_ctx, ConstantExpr::getIntToPtr(INTPTR(cpu->tc), cpu->bb->getParent()->getReturnType()),
								curr_watch_addr, CONST8(1), cpu->instr_eip }, "", cpu->bb);
							BR_UNCOND(vec_bb[6]);
							cpu->bb = vec_bb[6];
						}
					}
					break;

					default:
						LIB86CPU_ABORT();
					}

					ST_R32(LD(reg), dr_idx + dr_offset);
					ST(GEP_EIP(), ADD(cpu->instr_eip, CONST32(bytes)));
					if (((pc + bytes) & ~PAGE_MASK) == (pc & ~PAGE_MASK)) {
						link_dst_only_emit(cpu);
						cpu->bb = getBB();
						cpu->tc->flags |= TC_FLG_DST_ONLY;
					}
					translate_next = 0;
				}
			}
			break;

			case 0x88:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x89: {
				Value *reg, *rm;
				reg = LD_REG_val(GET_REG(OPNUM_SRC));
				GET_RM(OPNUM_DST, ST_REG_val(reg, rm);, ST_MEM(fn_idx[size_mode], rm, reg););
			}
			break;

			case 0x8A:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x8B: {
				Value *reg, *rm, *temp;
				reg = GET_REG(OPNUM_DST);
				GET_RM(OPNUM_SRC, ST_REG_val(LD_REG_val(rm), reg);, temp = LD_MEM(fn_idx[size_mode], rm); ST_REG_val(temp, reg););
			}
			break;

			case 0x8C: {
				Value *val, *rm;
				val = LD_SEG(GET_REG_idx(instr.operands[OPNUM_SRC].reg.value));
				GET_RM(OPNUM_DST, ST_REG_val(ZEXT32(val), IBITCAST32(rm));, ST_MEM(MEM_LD16_idx, rm, val););
			}
			break;

			case 0x8E: {
				Value *sel, *rm;
				const unsigned sel_idx = GET_REG_idx(instr.operands[OPNUM_DST].reg.value);
				GET_RM(OPNUM_SRC, sel = LD_REG_val(rm);, sel = LD_MEM(MEM_LD16_idx, rm););

				if (cpu_ctx->hflags & HFLG_PE_MODE) {
					std::vector<Value *> vec;

					if (sel_idx == SS_idx) {
						vec = check_ss_desc_priv_emit(cpu, sel);
						set_access_flg_seg_desc_emit(cpu, vec[1], vec[0]);
						write_seg_reg_emit(cpu, sel_idx, std::vector<Value *> { sel, read_seg_desc_base_emit(cpu, vec[1]),
							read_seg_desc_limit_emit(cpu, vec[1]), read_seg_desc_flags_emit(cpu, vec[1])});
						ST(GEP_EIP(), ADD(cpu->instr_eip, CONST32(bytes)));
						if (((pc + bytes) & ~PAGE_MASK) == (pc & ~PAGE_MASK)) {
							std::vector<BasicBlock *> vec_bb = getBBs(2);
							BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(CONST32(cpu->cpu_ctx.hflags & HFLG_SS32), AND(LD(cpu->ptr_hflags), CONST32(HFLG_SS32))));
							cpu->bb = vec_bb[0];
							link_dst_only_emit(cpu);
							cpu->bb = vec_bb[1];
							cpu->tc->flags |= TC_FLG_DST_ONLY;
						}
						translate_next = 0;
					}
					else {
						std::vector<BasicBlock *> vec_bb = getBBs(3);
						BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(SHR(sel, CONST16(2)), CONST16(0)));
						cpu->bb = vec_bb[0];
						write_seg_reg_emit(cpu, sel_idx, std::vector<Value *> { sel, CONST32(0), CONST32(0), CONST32(0) });
						BR_UNCOND(vec_bb[2]);
						cpu->bb = vec_bb[1];
						vec = check_seg_desc_priv_emit(cpu, sel);
						set_access_flg_seg_desc_emit(cpu, vec[1], vec[0]);
						write_seg_reg_emit(cpu, sel_idx, std::vector<Value *> { sel /* & rpl?? */, read_seg_desc_base_emit(cpu, vec[1]),
							read_seg_desc_limit_emit(cpu, vec[1]), read_seg_desc_flags_emit(cpu, vec[1])});
						BR_UNCOND(vec_bb[2]);
						cpu->bb = vec_bb[2];
					}
				}
				else {
					ST_SEG(sel, GET_REG_idx(instr.operands[OPNUM_DST].reg.value));
					ST_SEG_HIDDEN(SHL(ZEXT32(sel), CONST32(4)), GET_REG_idx(instr.operands[OPNUM_DST].reg.value), SEG_BASE_idx);
				}
			}
			break;

			case 0xA0:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xA1: {
				Value *temp = LD_MEM(fn_idx[size_mode], GET_OP(OPNUM_SRC));
				ST_REG_val(temp, GET_OP(OPNUM_DST));
			}
			break;

			case 0xA2:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xA3:
				ST_MEM(fn_idx[size_mode], GET_OP(OPNUM_DST), LD_REG_val(GET_OP(OPNUM_SRC)));
				break;

			case 0xB0:
			case 0xB1:
			case 0xB2:
			case 0xB3:
			case 0xB4:
			case 0xB5:
			case 0xB6:
			case 0xB7:
				ST_REG_val(GET_IMM8(), GET_OP(OPNUM_DST));
				break;

			case 0xB8:
			case 0xB9:
			case 0xBA:
			case 0xBB:
			case 0xBC:
			case 0xBD:
			case 0xBE:
			case 0xBF:
				ST_REG_val(GET_IMM(), GET_OP(OPNUM_DST));
				break;

			case 0xC6:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xC7: {
				Value *rm;
				GET_RM(OPNUM_DST, ST_REG_val(GET_IMM(), rm);, ST_MEM(fn_idx[size_mode], rm, GET_IMM()););
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
			break;

		case ZYDIS_MNEMONIC_MOVD: {
			if (cpu_ctx->hflags & HFLG_CR0_EM) {
				RAISEin0(EXP_UD);
				translate_next = 0;
			}
			else {
				switch (instr.opcode)
				{
				case 0x6E: {
					Value *src, *rm;
					std::vector<BasicBlock *> vec_bb = getBBs(2);

					BR_COND(vec_bb[0], vec_bb[1], ICMP_NE(AND(LD_R16(ST_idx), CONST16(ST_ES_MASK)), CONST16(0)));
					cpu->bb = vec_bb[0];
					RAISEin0(EXP_MF);
					UNREACH();
					cpu->bb = vec_bb[1];
					GET_RM(OPNUM_SRC, src = LD_R32(GET_REG_idx(instr.operands[OPNUM_SRC].reg.value));, src = LD_MEM(MEM_LD32_idx, rm););
					int mm_idx = GET_REG_idx(instr.operands[OPNUM_DST].reg.value);
					ST_MM64(ZEXT64(src), mm_idx);
					UPDATE_FPU_AFTER_MMX_w(CONST16(0), mm_idx);
				}
				break;

				case 0x7E: {
					Value *rm;
					std::vector<BasicBlock *> vec_bb = getBBs(2);

					BR_COND(vec_bb[0], vec_bb[1], ICMP_NE(AND(LD_R16(ST_idx), CONST16(ST_ES_MASK)), CONST16(0)));
					cpu->bb = vec_bb[0];
					RAISEin0(EXP_MF);
					UNREACH();
					cpu->bb = vec_bb[1];
					int mm_idx = GET_REG_idx(instr.operands[OPNUM_SRC].reg.value);
					GET_RM(OPNUM_DST, ST_R32(LD_MM32(mm_idx), GET_REG_idx(instr.operands[OPNUM_DST].reg.value));, ST_MEM(MEM_LD32_idx, rm, LD_MM32(mm_idx)););
					UPDATE_FPU_AFTER_MMX_r(CONST16(0), mm_idx);
				}
				break;

				default:
					BAD;
				}

			}
		}
		break;

		case ZYDIS_MNEMONIC_MOVSB:
		case ZYDIS_MNEMONIC_MOVSD:
		case ZYDIS_MNEMONIC_MOVSW: {
			switch (instr.opcode)
			{
			case 0xA4:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xA5: {
				Value *val, *df, *addr1, *addr2, *src, *esi, *edi;
				std::vector<BasicBlock *> vec_bb = getBBs(3);

				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP_start();
				}

				switch (addr_mode)
				{
				case ADDR16:
					esi = ZEXT32(LD_R16(ESI_idx));
					addr1 = ADD(LD_SEG_HIDDEN(get_seg_prfx_idx(&instr), SEG_BASE_idx), esi);
					edi = ZEXT32(LD_R16(EDI_idx));
					addr2 = ADD(LD_SEG_HIDDEN(ES_idx, SEG_BASE_idx), edi);
					break;

				case ADDR32:
					esi = LD_R32(ESI_idx);
					addr1 = ADD(LD_SEG_HIDDEN(get_seg_prfx_idx(&instr), SEG_BASE_idx), esi);
					edi = LD_R32(EDI_idx);
					addr2 = ADD(LD_SEG_HIDDEN(ES_idx, SEG_BASE_idx), edi);
					break;

				default:
					LIB86CPU_ABORT();
				}

				switch (size_mode)
				{
				case SIZE8:
					val = CONST32(1);
					src = LD_MEM(fn_idx[size_mode], addr1);
					ST_MEM(fn_idx[size_mode], addr2, src);
					break;

				case SIZE16:
					val = CONST32(2);
					src = LD_MEM(fn_idx[size_mode], addr1);
					ST_MEM(fn_idx[size_mode], addr2, src);
					break;

				case SIZE32:
					val = CONST32(4);
					src = LD_MEM(fn_idx[size_mode], addr1);
					ST_MEM(fn_idx[size_mode], addr2, src);
					break;

				default:
					LIB86CPU_ABORT();
				}

				df = AND(LD_R32(EFLAGS_idx), CONST32(DF_MASK));
				BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(df, CONST32(0)));

				cpu->bb = vec_bb[0];
				Value *esi_sum = ADD(esi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(esi_sum), ESI_idx) : ST_R32(esi_sum, ESI_idx);
				Value *edi_sum = ADD(edi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(edi_sum), EDI_idx) : ST_R32(edi_sum, EDI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[1];
				Value *esi_sub = SUB(esi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(esi_sub), ESI_idx) : ST_R32(esi_sub, ESI_idx);
				Value *edi_sub = SUB(edi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(edi_sub), EDI_idx) : ST_R32(edi_sub, EDI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[2];
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_MOVSX: {
			switch (instr.opcode)
			{
			case 0xBE: {
				Value *rm, *val;
				GET_RM(OPNUM_SRC, val = (GET_REG_idx(instr.operands[OPNUM_SRC].reg.value) < 4) ? LD_R8L(GET_REG_idx(instr.operands[OPNUM_SRC].reg.value)) :
					LD_R8H(GET_REG_idx(instr.operands[OPNUM_SRC].reg.value));, val = LD_MEM(MEM_LD8_idx, rm););
				ST_REG_val(size_mode == SIZE16 ? SEXT16(val) : SEXT32(val), GET_REG(OPNUM_DST));
			}
			break;

			case 0xBF: {
				Value *rm, *val;
				GET_RM(OPNUM_SRC, val = LD_R16(GET_REG_idx(instr.operands[OPNUM_SRC].reg.value));, val = LD_MEM(MEM_LD16_idx, rm););
				ST_REG_val(SEXT32(val), GEP_R32(GET_REG_idx(instr.operands[OPNUM_DST].reg.value)));
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_MOVZX: {
			switch (instr.opcode)
			{
			case 0xB6: {
				Value *rm, *val;
				GET_RM(OPNUM_SRC, val = (GET_REG_idx(instr.operands[OPNUM_SRC].reg.value) < 4) ? LD_R8L(GET_REG_idx(instr.operands[OPNUM_SRC].reg.value)) :
					LD_R8H(GET_REG_idx(instr.operands[OPNUM_SRC].reg.value));, val = LD_MEM(MEM_LD8_idx, rm););
				ST_REG_val(size_mode == SIZE16 ? ZEXT16(val) : ZEXT32(val), GET_REG(OPNUM_DST));
			}
			break;

			case 0xB7: {
				Value *rm, *val;
				GET_RM(OPNUM_SRC, val = LD_R16(GET_REG_idx(instr.operands[OPNUM_SRC].reg.value));, val = LD_MEM(MEM_LD16_idx, rm););
				ST_REG_val(ZEXT32(val), GEP_R32(GET_REG_idx(instr.operands[OPNUM_DST].reg.value)));
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_MUL: {
			switch (instr.opcode)
			{
			case 0xF6:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xF7: {
				assert(instr.raw.modrm.reg == 4);

				Value *val, *reg, *rm, *out;
				switch (size_mode)
				{
				case SIZE8:
					reg = LD_R8L(EAX_idx);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(ZEXT16(reg), ZEXT16(val));
					ST_REG_val(out, GEP_R16(EAX_idx));
					ST_FLG_AUX(SHL(ZEXT32(NOT_ZERO(16, SHR(out, CONST16(8)))), CONST32(31)));
					break;

				case SIZE16:
					reg = LD_R16(EAX_idx);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(ZEXT32(reg), ZEXT32(val));
					ST_REG_val(TRUNC16(SHR(out, CONST32(16))), GEP_R16(EDX_idx));
					ST_REG_val(TRUNC16(out), GEP_R16(EAX_idx));
					ST_FLG_AUX(SHL(NOT_ZERO(32, SHR(out, CONST32(16))), CONST32(31)));
					break;

				case SIZE32:
					reg = LD_R32(EAX_idx);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(ZEXT64(reg), ZEXT64(val));
					ST_REG_val(TRUNC32(SHR(out, CONST64(32))), GEP_R32(EDX_idx));
					ST_REG_val(TRUNC32(out), GEP_R32(EAX_idx));
					ST_FLG_AUX(SHL(TRUNC32(NOT_ZERO(64, SHR(out, CONST64(32)))), CONST32(31)));
					break;

				default:
					LIB86CPU_ABORT();
				}
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_NEG: {
			switch (instr.opcode)
			{
			case 0xF6:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xF7: {
				assert(instr.raw.modrm.reg == 3);

				Value *val, *neg, *rm, *zero = size_mode == SIZE16 ? CONST16(0) : size_mode == SIZE32 ? CONST32(0) : CONST8(0);
				GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm); neg = NEG(val); ST_REG_val(neg, rm);, val = LD_MEM(fn_idx[size_mode], rm);
				neg = NEG(val); ST_MEM(fn_idx[size_mode], rm, neg););
				SET_FLG_SUB(neg, zero, val);
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_NOP:
			// nothing to do
			break;

		case ZYDIS_MNEMONIC_NOT: {
			switch (instr.opcode)
			{
			case 0xF6:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xF7: {
				assert(instr.raw.modrm.reg == 2);

				Value *val, *rm;
				GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm); val = NOT(val); ST_REG_val(val, rm);, val = LD_MEM(fn_idx[size_mode], rm);
				val = NOT(val); ST_MEM(fn_idx[size_mode], rm, val););
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_OR: {
			switch (instr.opcode)
			{
			case 0x08:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x09: {
				Value *val, *rm, *src;
				src = LD_REG_val(GET_REG(OPNUM_SRC));
				GET_RM(OPNUM_DST, val = LD_REG_val(rm); val = OR(val, src); ST_REG_val(val, rm);, val = LD_MEM(fn_idx[size_mode], rm);
				val = OR(val, src); ST_MEM(fn_idx[size_mode], rm, val););
				SET_FLG(val, CONST32(0));
			}
			break;

			case 0x0A:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x0B: {
				Value *val, *rm, *reg = GET_REG(OPNUM_DST);
				GET_RM(OPNUM_SRC, val = LD_REG_val(rm); val = OR(val, LD_REG_val(reg)); ST_REG_val(val, reg);,
				val = LD_MEM(fn_idx[size_mode], rm); val = OR(val, LD_REG_val(reg)); ST_REG_val(val, reg););
				SET_FLG(val, CONST32(0));
			}
			break;

			case 0x0C:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x0D: {
				Value *val, *eax;
				val = GET_IMM();
				eax = GET_REG(OPNUM_DST);
				val = OR(LD_REG_val(eax), val);
				ST_REG_val(val, eax);
				SET_FLG(val, CONST32(0));
			}
			break;

			case 0x80:
			case 0x82:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x81: {
				assert(instr.raw.modrm.reg == 1);

				Value *val, *rm, *src = GET_IMM();
				GET_RM(OPNUM_DST, val = LD_REG_val(rm); val = OR(val, src); ST_REG_val(val, rm);, val = LD_MEM(fn_idx[size_mode], rm);
				val = OR(val, src); ST_MEM(fn_idx[size_mode], rm, val););
				SET_FLG(val, CONST32(0));
			}
			break;

			case 0x83: {
				assert(instr.raw.modrm.reg == 1);

				Value *val, *rm, *src = size_mode == SIZE16 ? SEXT16(GET_IMM8()) : SEXT32(GET_IMM8());
				GET_RM(OPNUM_DST, val = LD_REG_val(rm); val = OR(val, src); ST_REG_val(val, rm);,
				val = LD_MEM(fn_idx[size_mode], rm); val = OR(val, src); ST_MEM(fn_idx[size_mode], rm, val););
				SET_FLG(val, CONST32(0));
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_OUT:
			switch (instr.opcode)
			{
			case 0xE6:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xE7: {
				Value *port = CONST8(instr.operands[OPNUM_DST].imm.value.u);
				check_io_priv_emit(cpu, ZEXT32(port), size_mode);
				ST_IO(fn_io_idx[size_mode], ZEXT16(port), size_mode == SIZE16 ? LD_R16(EAX_idx) : size_mode == SIZE32 ? LD_R32(EAX_idx) : LD_R8L(EAX_idx));
			}
			break;

			case 0xEE:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xEF: {
				Value *port = LD_R16(EDX_idx);
				check_io_priv_emit(cpu, ZEXT32(port), size_mode);
				ST_IO(fn_io_idx[size_mode], port, size_mode == SIZE16 ? LD_R16(EAX_idx) : size_mode == SIZE32 ? LD_R32(EAX_idx) : LD_R8L(EAX_idx));
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
			break;

		case ZYDIS_MNEMONIC_OUTSB:
		case ZYDIS_MNEMONIC_OUTSD:
		case ZYDIS_MNEMONIC_OUTSW:
			switch (instr.opcode)
			{
			case 0x6E:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x6F: {
				Value *val, *df, *addr, *src, *esi, *io_val, *port = LD_R16(EDX_idx);
				check_io_priv_emit(cpu, ZEXT32(port), size_mode);
				std::vector<BasicBlock *> vec_bb = getBBs(3);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP_start();
				}

				switch (addr_mode)
				{
				case ADDR16:
					esi = ZEXT32(LD_R16(ESI_idx));
					addr = ADD(LD_SEG_HIDDEN(GET_REG_idx(instr.operands[OPNUM_SRC].mem.segment), SEG_BASE_idx), esi);
					break;

				case ADDR32:
					esi = LD_R32(ESI_idx);
					addr = ADD(LD_SEG_HIDDEN(GET_REG_idx(instr.operands[OPNUM_SRC].mem.segment), SEG_BASE_idx), esi);
					break;

				default:
					LIB86CPU_ABORT();
				}

				switch (size_mode)
				{
				case SIZE8:
					val = CONST32(1);
					io_val = LD_MEM(MEM_LD8_idx, addr);
					ST_IO(IO_ST8_idx, port, io_val);
					break;

				case SIZE16:
					val = CONST32(2);
					io_val = LD_MEM(MEM_LD16_idx, addr);
					ST_IO(IO_ST16_idx, port, io_val);
					break;

				case SIZE32:
					val = CONST32(4);
					io_val = LD_MEM(MEM_LD32_idx, addr);
					ST_IO(IO_ST32_idx, port, io_val);
					break;

				default:
					LIB86CPU_ABORT();
				}

				df = AND(LD_R32(EFLAGS_idx), CONST32(DF_MASK));
				BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(df, CONST32(0)));

				cpu->bb = vec_bb[0];
				Value *esi_sum = ADD(esi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(esi_sum), ESI_idx) : ST_R32(esi_sum, ESI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[1];
				Value *esi_sub = SUB(esi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(esi_sub), ESI_idx) : ST_R32(esi_sub, ESI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[2];
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
			break;

		case ZYDIS_MNEMONIC_POP: {
			std::vector<Value *> vec;

			switch (instr.opcode)
			{
				case 0x58:
				case 0x59:
				case 0x5A:
				case 0x5B:
				case 0x5C:
				case 0x5D:
				case 0x5E:
				case 0x5F: {
					assert(instr.operands[OPNUM_SINGLE].type == ZYDIS_OPERAND_TYPE_REGISTER);

					vec = MEM_POP(1);
					ST_REG_val(vec[1], vec[2]);
					size_mode == SIZE16 ? ST_R16(vec[0], GET_REG_idx(instr.operands[OPNUM_SINGLE].reg.value)) :
						ST_R32(vec[0], GET_REG_idx(instr.operands[OPNUM_SINGLE].reg.value));
				}
				break;

				case 0x8F: {
					assert(instr.raw.modrm.reg == 0);

					vec = MEM_POP(1);
					if (instr.operands[OPNUM_SINGLE].type == ZYDIS_OPERAND_TYPE_REGISTER) {
						Value *rm = GET_OP(OPNUM_SINGLE);
						ST_REG_val(vec[1], vec[2]);
						ST_REG_val(vec[0], rm);
					}
					else {
						Value *esp = cpu->cpu_ctx.hflags & HFLG_SS32 ? LD_R32(ESP_idx) : LD_R16(ESP_idx);
						ST_REG_val(vec[1], vec[2]);
						Value *rm = GET_OP(OPNUM_SINGLE);
						ST_REG_val(esp, vec[2]);
						ST_MEM(fn_idx[size_mode], rm, vec[0]);
						ST_REG_val(vec[1], vec[2]);
					}
				}
				break;

				case 0x1F:
				case 0x07:
				case 0x17:
				case 0xA1:
				case 0xA9: {
					const unsigned sel_idx = GET_REG_idx(instr.operands[OPNUM_SINGLE].reg.value);
					std::vector<Value *> vec_pop = MEM_POP(1);
					Value *sel = vec_pop[0];
					if (size_mode == SIZE32) {
						sel = TRUNC16(sel);
					}

					if (cpu_ctx->hflags & HFLG_PE_MODE) {
						std::vector<Value *> vec;

						if (sel_idx == SS_idx) {
							vec = check_ss_desc_priv_emit(cpu, sel);
							set_access_flg_seg_desc_emit(cpu, vec[1], vec[0]);
							write_seg_reg_emit(cpu, sel_idx, std::vector<Value *> { sel, read_seg_desc_base_emit(cpu, vec[1]),
								read_seg_desc_limit_emit(cpu, vec[1]), read_seg_desc_flags_emit(cpu, vec[1])});
							ST(GEP_EIP(), ADD(cpu->instr_eip, CONST32(bytes)));
							ST_REG_val(vec_pop[1], vec_pop[2]);
							if (((pc + bytes) & ~PAGE_MASK) == (pc & ~PAGE_MASK)) {
								std::vector<BasicBlock *> vec_bb = getBBs(2);
								BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(CONST32(cpu->cpu_ctx.hflags & HFLG_SS32), AND(LD(cpu->ptr_hflags), CONST32(HFLG_SS32))));
								cpu->bb = vec_bb[0];
								link_dst_only_emit(cpu);
								cpu->bb = vec_bb[1];
								cpu->tc->flags |= TC_FLG_DST_ONLY;
							}
							translate_next = 0;
						}
						else {
							std::vector<BasicBlock *> vec_bb = getBBs(3);
							BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(SHR(sel, CONST16(2)), CONST16(0)));
							cpu->bb = vec_bb[0];
							write_seg_reg_emit(cpu, sel_idx, std::vector<Value *> { sel, CONST32(0), CONST32(0), CONST32(0) });
							BR_UNCOND(vec_bb[2]);
							cpu->bb = vec_bb[1];
							vec = check_seg_desc_priv_emit(cpu, sel);
							set_access_flg_seg_desc_emit(cpu, vec[1], vec[0]);
							write_seg_reg_emit(cpu, sel_idx, std::vector<Value *> { sel, read_seg_desc_base_emit(cpu, vec[1]),
								read_seg_desc_limit_emit(cpu, vec[1]), read_seg_desc_flags_emit(cpu, vec[1])});
							BR_UNCOND(vec_bb[2]);
							cpu->bb = vec_bb[2];
							ST_REG_val(vec_pop[1], vec_pop[2]);
						}
					}
					else {
						ST_SEG(sel, sel_idx);
						ST_SEG_HIDDEN(SHL(ZEXT32(sel), CONST32(4)), sel_idx, SEG_BASE_idx);
						ST_REG_val(vec_pop[1], vec_pop[2]);
					}
				}
				break;

				default:
					LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_POPA:
		case ZYDIS_MNEMONIC_POPAD: {
			switch ((size_mode << 1) | ((cpu->cpu_ctx.hflags & HFLG_SS32) >> SS32_SHIFT))
			{
			case 0: {
				Value *sp = LD_R16(ESP_idx);
				for (int8_t reg_idx = EDI_idx; reg_idx >= EAX_idx; reg_idx--) {
					if (reg_idx != ESP_idx) {
						Value *reg = LD_MEM(MEM_LD32_idx, ADD(ZEXT32(sp), LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)));
						ST_R32(reg, reg_idx);
					}
					sp = ADD(sp, CONST16(4));
				}
				ST_R16(sp, ESP_idx);
			}
			break;

			case 1: {
				Value *esp = LD_R32(ESP_idx);
				for (int8_t reg_idx = EDI_idx; reg_idx >= EAX_idx; reg_idx--) {
					if (reg_idx != ESP_idx) {
						Value *reg = LD_MEM(MEM_LD32_idx, ADD(esp, LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)));
						ST_R32(reg, reg_idx);
					}
					esp = ADD(esp, CONST32(4));
				}
				ST_R32(esp, ESP_idx);
			}
			break;

			case 2: {
				Value *sp = LD_R16(ESP_idx);
				for (int8_t reg_idx = EDI_idx; reg_idx >= EAX_idx; reg_idx--) {
					if (reg_idx != ESP_idx) {
						Value *reg = LD_MEM(MEM_LD16_idx, ADD(ZEXT32(sp), LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)));
						ST_R16(reg, reg_idx);
					}
					sp = ADD(sp, CONST16(2));
				}
				ST_R16(sp, ESP_idx);
			}
			break;

			case 3: {
				Value *esp = LD_R32(ESP_idx);
				for (int8_t reg_idx = EDI_idx; reg_idx >= EAX_idx; reg_idx--) {
					if (reg_idx != ESP_idx) {
						Value *reg = LD_MEM(MEM_LD16_idx, ADD(esp, LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)));
						ST_R16(reg, reg_idx);
					}
					esp = ADD(esp, CONST32(2));
				}
				ST_R32(esp, ESP_idx);
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_POPF:
		case ZYDIS_MNEMONIC_POPFD: {
			std::vector<Value *> vec = MEM_POP(1);
			Value *eflags = vec[0];
			Value *mask = CONST32(TF_MASK | DF_MASK | NT_MASK);
			uint32_t mask2 = TF_MASK;
			uint32_t cpl = cpu->cpu_ctx.hflags & HFLG_CPL;
			uint32_t iopl = (cpu->cpu_ctx.regs.eflags & IOPL_MASK) >> 12;
			if (cpl == 0) {
				mask = OR(mask, CONST32(IOPL_MASK | IF_MASK));
				mask2 |= IOPL_MASK;
			}
			else if (iopl >= cpl) {
				mask = OR(mask, CONST32(IF_MASK));
			}

			if (size_mode == SIZE32) {
				mask = OR(mask, CONST32(ID_MASK | AC_MASK));
				mask2 |= AC_MASK;
			}
			else {
				eflags = ZEXT32(eflags);
			}

			write_eflags(cpu, eflags, mask);
			ST_REG_val(vec[1], vec[2]);
			ST(GEP_EIP(), ADD(cpu->instr_eip, CONST32(bytes)));
			if (((pc + bytes) & ~PAGE_MASK) == (pc & ~PAGE_MASK)) {
				std::vector<BasicBlock *> vec_bb = getBBs(2);
				BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(CONST32(cpu->cpu_ctx.regs.eflags & mask2), AND(LD_R32(EFLAGS_idx), CONST32(mask2))));
				cpu->bb = vec_bb[0];
				link_dst_only_emit(cpu);
				cpu->bb = vec_bb[1];
				cpu->tc->flags |= TC_FLG_DST_ONLY;
			}
			translate_next = 0;
		}
		break;

		case ZYDIS_MNEMONIC_PUSH: {
			std::vector<Value *> vec;

			switch (instr.opcode)
			{
			case 0x50:
			case 0x51:
			case 0x52:
			case 0x53:
			case 0x54:
			case 0x55:
			case 0x56:
			case 0x57: {
				assert(instr.operands[OPNUM_SINGLE].type == ZYDIS_OPERAND_TYPE_REGISTER);

				vec.push_back(size_mode == SIZE16 ? LD_R16(GET_REG_idx(instr.operands[OPNUM_SINGLE].reg.value)) :
					LD_R32(GET_REG_idx(instr.operands[OPNUM_SINGLE].reg.value)));
				MEM_PUSH(vec);
			}
			break;

			case 0x68: {
				vec.push_back(size_mode == SIZE16 ? CONST16(instr.operands[OPNUM_SINGLE].imm.value.u) : CONST32(instr.operands[OPNUM_SINGLE].imm.value.u));
				MEM_PUSH(vec);
			}
			break;

			case 0x6A: {
				vec.push_back(size_mode == SIZE16 ? SEXT16(CONST8(instr.operands[OPNUM_SINGLE].imm.value.u)) : SEXT32(CONST8(instr.operands[OPNUM_SINGLE].imm.value.u)));
				MEM_PUSH(vec);
			}
			break;

			case 0xFF: {
				assert(instr.raw.modrm.reg == 6);

				Value *rm, *val;
				GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				vec.push_back(val);
				MEM_PUSH(vec);
			}
			break;

			case 0x06:
			case 0x0E:
			case 0x16:
			case 0x1E:
			case 0xA0:
			case 0xA8: {
				assert(instr.operands[OPNUM_SINGLE].type == ZYDIS_OPERAND_TYPE_REGISTER);

				Value *reg = LD_R16(GET_REG_idx(instr.operands[OPNUM_SINGLE].reg.value));
				if (size_mode == SIZE32) {
					reg = ZEXT32(reg);
				}
				vec.push_back(reg);
				MEM_PUSH(vec);
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_PUSHA:
		case ZYDIS_MNEMONIC_PUSHAD: {
			std::vector<Value *> vec;

			if (size_mode == SIZE16) {
				vec.push_back(LD_R16(EAX_idx));
				vec.push_back(LD_R16(ECX_idx));
				vec.push_back(LD_R16(EDX_idx));
				vec.push_back(LD_R16(EBX_idx));
				vec.push_back(LD_R16(ESP_idx));
				vec.push_back(LD_R16(EBP_idx));
				vec.push_back(LD_R16(ESI_idx));
				vec.push_back(LD_R16(EDI_idx));
			}
			else {
				vec.push_back(LD_R32(EAX_idx));
				vec.push_back(LD_R32(ECX_idx));
				vec.push_back(LD_R32(EDX_idx));
				vec.push_back(LD_R32(EBX_idx));
				vec.push_back(LD_R32(ESP_idx));
				vec.push_back(LD_R32(EBP_idx));
				vec.push_back(LD_R32(ESI_idx));
				vec.push_back(LD_R32(EDI_idx));
			}

			MEM_PUSH(vec);
		}
		break;

		case ZYDIS_MNEMONIC_PUSHF:
		case ZYDIS_MNEMONIC_PUSHFD: {
			Value *flags = OR(OR(OR(OR(OR(SHR(LD_CF(), CONST32(31)),
				SHR(LD_OF(), CONST32(20))),
				SHL(XOR(NOT_ZERO(32, LD_ZF()), CONST32(1)), CONST32(6))),
				SHL(LD_SF(), CONST32(7))),
				SHL(XOR(ZEXT32(LD_PF()), CONST32(1)), CONST32(2))),
				SHL(LD_AF(), CONST32(1))
				);

			std::vector<Value *> vec;
			if (size_mode == SIZE16) {
				vec.push_back(OR(LD_R16(EFLAGS_idx), TRUNC16(flags)));
			}
			else {
				vec.push_back(AND(OR(LD_R32(EFLAGS_idx), flags), CONST32(0xFCFFFF)));
			}

			MEM_PUSH(vec);
		}
		break;

		case ZYDIS_MNEMONIC_RCL: {
			assert(instr.raw.modrm.reg == 2);

			Value *count;
			switch (instr.opcode)
			{
			case 0xD0:
				count = CONST32(1);
				size_mode = SIZE8;
				break;

			case 0xD2:
				count = ZEXT32(AND(LD_R8L(ECX_idx), CONST8(0x1F)));
				size_mode = SIZE8;
				break;

			case 0xC0:
				count = CONST32(instr.operands[OPNUM_SRC].imm.value.u & 0x1F);
				size_mode = SIZE8;
				break;

			case 0xD1:
				count = CONST32(1);
				break;

			case 0xD3:
				count = ZEXT32(AND(LD_R8L(ECX_idx), CONST8(0x1F)));
				break;

			case 0xC1:
				count = CONST32(instr.operands[OPNUM_SRC].imm.value.u & 0x1F);
				break;

			default:
				LIB86CPU_ABORT();
			}

			std::vector<BasicBlock *>vec_bb = getBBs(2);
			BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(count, CONST32(0)));
			cpu->bb = vec_bb[1];
			Value *val, *rm, *flg, *res;
			switch (size_mode)
			{
			case SIZE8: {
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				Value *i9 = OR(ZEXTs(9, val), TRUNCs(9, SHR(LD_CF(), CONST32(23))));
				Value *rotl = INTRINSIC_ty(fshl, getIntegerType(9), (std::vector<Value *> { i9, i9, TRUNCs(9, count) }));
				Value *cf = ZEXT32(AND(SHR(val, SUB(CONST8(8), TRUNC8(count))), CONST8(1)));
				Value *of = ZEXT32(AND(rotl, CONSTs(9, 1 << 7)));
				flg = OR(SHL(cf, CONST32(31)), SHL(of, CONST32(23)));
				res = TRUNC8(rotl);
			}
			break;

			case SIZE16: {
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				Value *i17 = OR(ZEXTs(17, val), TRUNCs(17, SHR(LD_CF(), CONST32(15))));
				Value *rotl = INTRINSIC_ty(fshl, getIntegerType(17), (std::vector<Value *> { i17, i17, TRUNCs(17, count) }));
				Value *cf = ZEXT32(AND(SHR(val, SUB(CONST16(16), TRUNC16(count))), CONST16(1)));
				Value *of = ZEXT32(AND(rotl, CONSTs(17, 1 << 15)));
				flg = OR(SHL(cf, CONST32(31)), SHL(of, CONST32(15)));
				res = TRUNC16(rotl);
			}
			break;

			case SIZE32: {
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				Value *i33 = OR(ZEXTs(33, val), SHL(ZEXTs(33, LD_CF()), CONSTs(33, 1)));
				Value *rotl = INTRINSIC_ty(fshl, getIntegerType(33), (std::vector<Value *> { i33, i33, ZEXTs(33, count) }));
				Value *cf = AND(SHR(val, SUB(CONST32(32), count)), CONST32(1));
				Value *of = TRUNC32(SHR(AND(rotl, CONSTs(33, 1ULL << 31)), CONSTs(33, 1)));
				flg = OR(SHL(cf, CONST32(31)), of);
				res = TRUNC32(rotl);
			}
			break;

			default:
				LIB86CPU_ABORT();
			}

			(instr.operands[OPNUM_DST].type == ZYDIS_OPERAND_TYPE_REGISTER) ? ST_REG_val(res, rm) : ST_MEM(fn_idx[size_mode], rm, res);
			ST_FLG_AUX(OR(AND(LD_FLG_AUX(), CONST32(0x3FFFFFFF)), flg));
			BR_UNCOND(vec_bb[0]);
			cpu->bb = vec_bb[0];
		}
		break;

		case ZYDIS_MNEMONIC_RCR: {
			assert(instr.raw.modrm.reg == 3);

			Value *count;
			switch (instr.opcode)
			{
			case 0xD0:
				count = CONST32(1);
				size_mode = SIZE8;
				break;

			case 0xD2:
				count = ZEXT32(AND(LD_R8L(ECX_idx), CONST8(0x1F)));
				size_mode = SIZE8;
				break;

			case 0xC0:
				count = CONST32(instr.operands[OPNUM_SRC].imm.value.u & 0x1F);
				size_mode = SIZE8;
				break;

			case 0xD1:
				count = CONST32(1);
				break;

			case 0xD3:
				count = ZEXT32(AND(LD_R8L(ECX_idx), CONST8(0x1F)));
				break;

			case 0xC1:
				count = CONST32(instr.operands[OPNUM_SRC].imm.value.u & 0x1F);
				break;

			default:
				LIB86CPU_ABORT();
			}

			std::vector<BasicBlock *>vec_bb = getBBs(2);
			BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(count, CONST32(0)));
			cpu->bb = vec_bb[1];
			Value *val, *rm, *flg, *res;
			switch (size_mode)
			{
			case SIZE8: {
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				Value *i9 = OR(SHL(ZEXTs(9, val), CONSTs(9, 1)), TRUNCs(9, SHR(LD_CF(), CONST32(31))));
				Value *rotr = INTRINSIC_ty(fshr, getIntegerType(9), (std::vector<Value *> { val, val, TRUNCs(9, count) }));
				Value *cf = ZEXT32(AND(SHR(val, SUB(TRUNC8(count), CONST8(1))), CONST8(1)));
				Value *of = ZEXT32(XOR(AND(rotr, CONSTs(9, 1 << 8)), SHL(AND(rotr, CONSTs(9, 1 << 7)), CONSTs(9, 1))));
				flg = OR(SHL(cf, CONST32(31)), SHL(XOR(of, SHL(cf, CONST32(8))), CONST32(22)));
				res = TRUNC8(SHR(val, CONSTs(9, 1)));
			}
			break;

			case SIZE16: {
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				Value *i17 = OR(SHL(ZEXTs(17, val), CONSTs(17, 1)), TRUNCs(17, SHR(LD_CF(), CONST32(31))));
				Value *rotr = INTRINSIC_ty(fshr, getIntegerType(17), (std::vector<Value *> { val, val, TRUNCs(17, count) }));
				Value *cf = ZEXT32(AND(SHR(val, SUB(TRUNC16(count), CONST16(1))), CONST16(1)));
				Value *of = ZEXT32(XOR(AND(rotr, CONSTs(17, 1 << 16)), SHL(AND(rotr, CONSTs(17, 1 << 15)), CONSTs(17, 1))));
				flg = OR(SHL(cf, CONST32(31)), SHL(XOR(of, SHL(cf, CONST32(16))), CONST32(14)));
				res = TRUNC16(SHR(val, CONSTs(17, 1)));
			}
			break;

			case SIZE32: {
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				Value *i33 = OR(SHL(ZEXTs(33, val), CONSTs(33, 1)), SHL(ZEXTs(33, LD_CF()), CONSTs(33, 31)));
				Value *rotr = INTRINSIC_ty(fshr, getIntegerType(33), (std::vector<Value *> { val, val, ZEXTs(33, count) }));
				Value *cf = AND(SHR(val, SUB(count, CONST32(1))), CONST32(1));
				Value *of = TRUNC32(XOR(SHR(AND(rotr, CONSTs(33, 1ULL << 32)), CONSTs(33, 1)), AND(rotr, CONSTs(33, 1 << 31))));
				flg = OR(SHL(cf, CONST32(31)), SHR(XOR(of, SHL(cf, CONST32(31))), CONST32(1)));
				res = TRUNC32(SHR(val, CONSTs(33, 1)));
			}
			break;

			default:
				LIB86CPU_ABORT();
			}

			(instr.operands[OPNUM_DST].type == ZYDIS_OPERAND_TYPE_REGISTER) ? ST_REG_val(res, rm) : ST_MEM(fn_idx[size_mode], rm, res);
			ST_FLG_AUX(OR(AND(LD_FLG_AUX(), CONST32(0x3FFFFFFF)), flg));
			BR_UNCOND(vec_bb[0]);
			cpu->bb = vec_bb[0];
		}
		break;

		case ZYDIS_MNEMONIC_RDMSR: {
			if (cpu_ctx->hflags & HFLG_CPL) {
				RAISEin0(EXP_GP);
				translate_next = 0;
			}
			else {
				Function *msr_r_fn = cast<Function>(cpu->mod->getOrInsertFunction("cpu_msr_read", getVoidType(), cpu->ptr_cpu_ctx->getType()));
				CallInst::Create(msr_r_fn, cpu->ptr_cpu_ctx, "", cpu->bb);
			}
		}
		break;

		case ZYDIS_MNEMONIC_RDPMC:       BAD;
		case ZYDIS_MNEMONIC_RDTSC: {
			if (cpu_ctx->hflags & HFLG_CPL) {
				std::vector<BasicBlock *>vec_bb = getBBs(2);
				BR_COND(vec_bb[0], vec_bb[1], ICMP_NE(AND(LD_R32(CR4_idx), CONST32(CR4_TSD_MASK)), CONST32(0)));
				cpu->bb = vec_bb[0];
				RAISEin0(EXP_GP);
				UNREACH();
				cpu->bb = vec_bb[1];
			}

			Function *rdtsc_fn = cast<Function>(cpu->mod->getOrInsertFunction("cpu_rdtsc_handler", getVoidType(), cpu->ptr_cpu_ctx->getType()));
			CallInst::Create(rdtsc_fn, cpu->ptr_cpu_ctx, "", cpu->bb);
		}
		break;

		case ZYDIS_MNEMONIC_RET: {
			bool has_imm_op = false;
			switch (instr.opcode)
			{
			case 0xC2: {
				has_imm_op = true;
			}
			[[fallthrough]];

			case 0xC3: {
				std::vector<Value *> vec = MEM_POP(1);
				Value *ret_eip = vec[0];
				if (size_mode == SIZE16) {
					ret_eip = ZEXT32(ret_eip);
				}
				ST_REG_val(vec[1], vec[2]);
				ST_R32(ret_eip, EIP_idx);
				if (has_imm_op) {
					if (cpu->cpu_ctx.hflags & HFLG_SS32) {
						Value *esp_ptr = GEP_R32(ESP_idx);
						ST_REG_val(ADD(LD_REG_val(esp_ptr), CONST32(instr.operands[OPNUM_SINGLE].imm.value.u)), esp_ptr);
					}
					else {
						Value *esp_ptr = GEP_R16(ESP_idx);
						ST_REG_val(ADD(LD_REG_val(esp_ptr), CONST16(instr.operands[OPNUM_SINGLE].imm.value.u)), esp_ptr);
					}
				}
			}
			break;

			case 0xCB: {
				if (cpu_ctx->hflags & HFLG_PE_MODE) {
					ret_pe_emit(cpu, size_mode, false);
				}
				else {
					std::vector<Value *> vec = MEM_POP(2);
					Value *eip = vec[0];
					Value *cs = vec[1];
					if (size_mode == SIZE16) {
						eip = ZEXT32(eip);
					}
					else {
						cs = TRUNC16(cs);
					}
					ST_REG_val(vec[2], vec[3]);
					ST_R32(eip, EIP_idx);
					ST_SEG(cs, CS_idx);
					ST_SEG_HIDDEN(SHL(ZEXT32(cs), CONST32(4)), CS_idx, SEG_BASE_idx);
				}
			}
			break;

			default:
				BAD;
			}

			cpu->tc->flags |= TC_FLG_INDIRECT;
			translate_next = 0;
		}
		break;

		case ZYDIS_MNEMONIC_ROL: {
			assert(instr.raw.modrm.reg == 0);

			Value *count;
			switch (instr.opcode)
			{
			case 0xD0:
				count = CONST32(1);
				size_mode = SIZE8;
				break;

			case 0xD2:
				count = ZEXT32(AND(LD_R8L(ECX_idx), CONST8(0x1F)));
				size_mode = SIZE8;
				break;

			case 0xC0:
				count = CONST32(instr.operands[OPNUM_SRC].imm.value.u & 0x1F);
				size_mode = SIZE8;
				break;

			case 0xD1:
				count = CONST32(1);
				break;

			case 0xD3:
				count = ZEXT32(AND(LD_R8L(ECX_idx), CONST8(0x1F)));
				break;

			case 0xC1:
				count = CONST32(instr.operands[OPNUM_SRC].imm.value.u & 0x1F);
				break;

			default:
				LIB86CPU_ABORT();
			}

			std::vector<BasicBlock *>vec_bb = getBBs(2);
			BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(count, CONST32(0)));
			cpu->bb = vec_bb[1];
			Value *val, *rm, *flg, *res;
			switch (size_mode)
			{
			case SIZE8: {
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				Value *rotl = INTRINSIC_ty(fshl, getIntegerType(8), (std::vector<Value *> { val, val, TRUNC8(count) }));
				Value *cf = ZEXT32(AND(SHR(val, SUB(CONST8(8), TRUNC8(count))), CONST8(1)));
				Value *of = ZEXT32(AND(rotl, CONST8(1 << 7)));
				flg = OR(SHL(cf, CONST32(31)), SHL(of, CONST32(23)));
				res = rotl;
			}
			break;

			case SIZE16: {
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				Value *rotl = INTRINSIC_ty(fshl, getIntegerType(16), (std::vector<Value *> { val, val, TRUNC16(count) }));
				Value *cf = ZEXT32(AND(SHR(val, SUB(CONST16(16), TRUNC16(count))), CONST16(1)));
				Value *of = ZEXT32(AND(rotl, CONST16(1 << 15)));
				flg = OR(SHL(cf, CONST32(31)), SHL(of, CONST32(15)));
				res = rotl;
			}
			break;

			case SIZE32: {
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				Value *rotl = INTRINSIC_ty(fshl, getIntegerType(32), (std::vector<Value *> { val, val, count }));
				Value *cf = AND(SHR(val, SUB(CONST32(32), count)), CONST32(1));
				Value *of = AND(rotl, CONST32(1 << 31));
				flg = OR(SHL(cf, CONST32(31)), SHR(of, CONST32(1)));
				res = rotl;
			}
			break;

			default:
				LIB86CPU_ABORT();
			}

			(instr.operands[OPNUM_DST].type == ZYDIS_OPERAND_TYPE_REGISTER) ? ST_REG_val(res, rm) : ST_MEM(fn_idx[size_mode], rm, res);
			ST_FLG_AUX(OR(AND(LD_FLG_AUX(), CONST32(0x3FFFFFFF)), flg));
			BR_UNCOND(vec_bb[0]);
			cpu->bb = vec_bb[0];
		}
		break;

		case ZYDIS_MNEMONIC_ROR: {
			assert(instr.raw.modrm.reg == 1);

			Value *count;
			switch (instr.opcode)
			{
			case 0xD0:
				count = CONST32(1);
				size_mode = SIZE8;
				break;

			case 0xD2:
				count = ZEXT32(AND(LD_R8L(ECX_idx), CONST8(0x1F)));
				size_mode = SIZE8;
				break;

			case 0xC0:
				count = CONST32(instr.operands[OPNUM_SRC].imm.value.u & 0x1F);
				size_mode = SIZE8;
				break;

			case 0xD1:
				count = CONST32(1);
				break;

			case 0xD3:
				count = ZEXT32(AND(LD_R8L(ECX_idx), CONST8(0x1F)));
				break;

			case 0xC1:
				count = CONST32(instr.operands[OPNUM_SRC].imm.value.u & 0x1F);
				break;

			default:
				LIB86CPU_ABORT();
			}

			std::vector<BasicBlock *>vec_bb = getBBs(2);
			BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(count, CONST32(0)));
			cpu->bb = vec_bb[1];
			Value *val, *rm, *flg, *res;
			switch (size_mode)
			{
			case SIZE8: {
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				Value *rotr = INTRINSIC_ty(fshr, getIntegerType(8), (std::vector<Value *> { val, val, TRUNC8(count) }));
				Value *cf = ZEXT32(AND(SHR(val, SUB(TRUNC8(count), CONST8(1))), CONST8(1)));
				Value *of = ZEXT32(XOR(AND(rotr, CONST8(1 << 7)), SHL(AND(rotr, CONST8(1 << 6)), CONST8(1))));
				flg = OR(SHL(cf, CONST32(31)), SHL(XOR(of, SHL(cf, CONST32(7))), CONST32(23)));
				res = rotr;
			}
			break;

			case SIZE16: {
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				Value *rotr = INTRINSIC_ty(fshr, getIntegerType(16), (std::vector<Value *> { val, val, TRUNC16(count) }));
				Value *cf = ZEXT32(AND(SHR(val, SUB(TRUNC16(count), CONST16(1))), CONST16(1)));
				Value *of = ZEXT32(XOR(AND(rotr, CONST16(1 << 15)), SHL(AND(rotr, CONST16(1 << 14)), CONST16(1))));
				flg = OR(SHL(cf, CONST32(31)), SHL(XOR(of, SHL(cf, CONST32(15))), CONST32(15)));
				res = rotr;
			}
			break;

			case SIZE32: {
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				Value *rotr = INTRINSIC_ty(fshr, getIntegerType(32), (std::vector<Value *> { val, val, count }));
				Value *cf = AND(SHR(val, SUB(count, CONST32(1))), CONST32(1));
				Value *of = XOR(SHR(AND(rotr, CONST32(1 << 31)), CONST32(1)), AND(rotr, CONST32(1 << 30)));
				flg = OR(SHL(cf, CONST32(31)), XOR(of, SHL(cf, CONST32(30))));
				res = rotr;
			}
			break;

			default:
				LIB86CPU_ABORT();
			}

			(instr.operands[OPNUM_DST].type == ZYDIS_OPERAND_TYPE_REGISTER) ? ST_REG_val(res, rm) : ST_MEM(fn_idx[size_mode], rm, res);
			ST_FLG_AUX(OR(AND(LD_FLG_AUX(), CONST32(0x3FFFFFFF)), flg));
			BR_UNCOND(vec_bb[0]);
			cpu->bb = vec_bb[0];
		}
		break;

		case ZYDIS_MNEMONIC_RSM:         BAD;
		case ZYDIS_MNEMONIC_SAHF: {
			assert(instr.opcode == 0x9E);

			Value *ah = ZEXT32(LD_R8H(EAX_idx));
			Value *sfd = SHR(AND(ah, CONST32(128)), CONST32(7));
			Value *pdb = SHL(XOR(CONST32(4), AND(ah, CONST32(4))), CONST32(6));
			Value *of_new = SHR(XOR(SHL(AND(ah, CONST32(1)), CONST32(31)), LD_OF()), CONST32(1));
			ST_FLG_RES(SHL(XOR(AND(ah, CONST32(64)), CONST32(64)), CONST32(2)));
			ST_FLG_AUX(OR(OR(OR(OR(SHL(AND(ah, CONST32(1)), CONST32(31)), SHR(AND(ah, CONST32(16)), CONST32(1))), of_new), sfd), pdb));
		}
		break;

		case ZYDIS_MNEMONIC_SAR: {
			assert(instr.raw.modrm.reg == 7);
			Value *count;
			switch (instr.opcode)
			{
			case 0xD0:
				count = CONST32(1);
				size_mode = SIZE8;
				break;

			case 0xD2:
				count = ZEXT32(AND(LD_R8L(ECX_idx), CONST8(0x1F)));
				size_mode = SIZE8;
				break;

			case 0xC0:
				count = CONST32(instr.operands[OPNUM_SRC].imm.value.u & 0x1F);
				size_mode = SIZE8;
				break;

			case 0xD1:
				count = CONST32(1);
				break;

			case 0xD3:
				count = ZEXT32(AND(LD_R8L(ECX_idx), CONST8(0x1F)));
				break;

			case 0xC1:
				count = CONST32(instr.operands[OPNUM_SRC].imm.value.u & 0x1F);
				break;

			default:
				LIB86CPU_ABORT();
			}

			std::vector<BasicBlock *>vec_bb = getBBs(2);
			BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(count, CONST32(0)));
			cpu->bb = vec_bb[1];
			Value *val, *rm, *temp, *cf, *cf_mask = SHL(CONST32(1), SUB(count, CONST32(1)));
			switch (size_mode)
			{
			case SIZE8:
				GET_RM(OPNUM_DST, val = SEXT32(LD_REG_val(rm)); cf = AND(val, cf_mask); val = TRUNC8(ASHR(val, count)); ST_REG_val(val, rm);,
				temp = LD_MEM(fn_idx[size_mode], rm); val = ZEXT32(temp); cf = AND(val, cf_mask); val = TRUNC8(ASHR(val, count)); ST_MEM(fn_idx[size_mode], rm, val););
				break;

			case SIZE16:
				GET_RM(OPNUM_DST, val = SEXT32(LD_REG_val(rm)); cf = AND(val, cf_mask); val = TRUNC16(ASHR(val, count)); ST_REG_val(val, rm);,
				temp = LD_MEM(fn_idx[size_mode], rm); val = ZEXT32(temp); cf = AND(val, cf_mask); val = TRUNC16(ASHR(val, count)); ST_MEM(fn_idx[size_mode], rm, val););
				break;

			case SIZE32:
				GET_RM(OPNUM_DST, val = LD_REG_val(rm); cf = AND(val, cf_mask); val = ASHR(val, count); ST_REG_val(val, rm);,
				val = LD_MEM(fn_idx[size_mode], rm); cf = AND(val, cf_mask); val = ASHR(val, count); ST_MEM(fn_idx[size_mode], rm, val););
				break;

			default:
				LIB86CPU_ABORT();
			}

			SET_FLG(val, OR(SHL(cf, SUB(CONST32(32), count)), SHL(cf, SUB(CONST32(31), count))));
			BR_UNCOND(vec_bb[0]);
			cpu->bb = vec_bb[0];
		}
		break;

		case ZYDIS_MNEMONIC_SBB: {
			Value *src, *sub, *sum, *dst, *rm, *cf, *sub_cout;
			switch (instr.opcode)
			{
			case 0x1C:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x1D: {
				switch (size_mode)
				{
				case SIZE8:
					src = CONST8(instr.operands[OPNUM_SRC].imm.value.u);
					rm = GEP_R8L(EAX_idx);
					dst = LD(rm);
					break;

				case SIZE16:
					src = CONST16(instr.operands[OPNUM_SRC].imm.value.u);
					rm = GEP_R16(EAX_idx);
					dst = LD(rm);
					break;

				case SIZE32:
					src = CONST32(instr.operands[OPNUM_SRC].imm.value.u);
					rm = GEP_R32(EAX_idx);
					dst = LD(rm);
					break;

				default:
					LIB86CPU_ABORT();
				}
			}
			break;

			case 0x80:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x81:
			case 0x83: {
				assert(instr.raw.modrm.reg == 3);

				if (instr.opcode == 0x83) {
					src = (size_mode == SIZE16) ? SEXT16(CONST8(instr.operands[OPNUM_SRC].imm.value.u)) :
						SEXT32(CONST8(instr.operands[OPNUM_SRC].imm.value.u));
				}
				else {
					src = GET_IMM();
				}

				GET_RM(OPNUM_DST, dst = LD_REG_val(rm);, dst = LD_MEM(fn_idx[size_mode], rm););
			}
			break;

			case 0x18:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x19: {
				src = LD_REG_val(GET_REG(OPNUM_SRC));
				GET_RM(OPNUM_DST, dst = LD_REG_val(rm);, dst = LD_MEM(fn_idx[size_mode], rm););
			}
			break;

			case 0x1A:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x1B: {
				GET_RM(OPNUM_SRC, src = LD_REG_val(rm);, src = LD_MEM(fn_idx[size_mode], rm););
				rm = GET_REG(OPNUM_DST);
				dst = LD_REG_val(rm);
			}
			break;

			default:
				LIB86CPU_ABORT();
			}

			switch (size_mode)
			{
			case SIZE8:
				cf = TRUNC8(SHR(LD_CF(), CONST32(31)));
				sum = ADD(src, cf);
				sub = SUB(dst, sum);
				sub_cout = GEN_SUB_VEC8(dst, src, sub);
				break;

			case SIZE16:
				cf = TRUNC16(SHR(LD_CF(), CONST32(31)));
				sum = ADD(src, cf);
				sub = SUB(dst, sum);
				sub_cout = GEN_SUB_VEC16(dst, src, sub);
				break;

			case SIZE32:
				cf = SHR(LD_CF(), CONST32(31));
				sum = ADD(src, cf);
				sub = SUB(dst, sum);
				sub_cout = GEN_SUB_VEC32(dst, src, sub);
				break;

			default:
				LIB86CPU_ABORT();
			}

			if (instr.operands[OPNUM_DST].type == ZYDIS_OPERAND_TYPE_REGISTER) {
				ST_REG_val(sub, rm);
			}
			else {
				ST_MEM(fn_idx[size_mode], rm, sub);
			}

			SET_FLG(sub, sub_cout);
		}
		break;

		case ZYDIS_MNEMONIC_SCASB:
		case ZYDIS_MNEMONIC_SCASD:
		case ZYDIS_MNEMONIC_SCASW: {
			switch (instr.opcode)
			{
			case 0xAE:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xAF: {
				Value *val, *df, *sub, *addr, *src, *edi, *eax;
				std::vector<BasicBlock *> vec_bb = getBBs(3);

				if ((instr.attributes & ZYDIS_ATTRIB_HAS_REPNZ) || (instr.attributes & ZYDIS_ATTRIB_HAS_REPZ)) {
					REP_start();
				}

				switch (addr_mode)
				{
				case ADDR16:
					edi = ZEXT32(LD_R16(EDI_idx));
					addr = ADD(LD_SEG_HIDDEN(ES_idx, SEG_BASE_idx), edi);
					break;

				case ADDR32:
					edi = LD_R32(EDI_idx);
					addr = ADD(LD_SEG_HIDDEN(ES_idx, SEG_BASE_idx), edi);
					break;

				default:
					LIB86CPU_ABORT();
				}

				switch (size_mode)
				{
				case SIZE8:
					val = CONST32(1);
					src = LD_MEM(fn_idx[size_mode], addr);
					eax = LD_R8L(EAX_idx);
					sub = SUB(eax, src);
					break;

				case SIZE16:
					val = CONST32(2);
					src = LD_MEM(fn_idx[size_mode], addr);
					eax = LD_R16(EAX_idx);
					sub = SUB(eax, src);
					break;

				case SIZE32:
					val = CONST32(4);
					src = LD_MEM(fn_idx[size_mode], addr);
					eax = LD_R32(EAX_idx);
					sub = SUB(eax, src);
					break;

				default:
					LIB86CPU_ABORT();
				}

				SET_FLG_SUB(sub, eax, src);

				df = AND(LD_R32(EFLAGS_idx), CONST32(DF_MASK));
				BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(df, CONST32(0)));

				cpu->bb = vec_bb[0];
				Value *edi_sum = ADD(edi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(edi_sum), EDI_idx) : ST_R32(edi_sum, EDI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REPNZ) {
					REPNZ();
				}
				else if (instr.attributes & ZYDIS_ATTRIB_HAS_REPZ) {
					REPZ();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[1];
				Value *edi_sub = SUB(edi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(edi_sub), EDI_idx) : ST_R32(edi_sub, EDI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REPNZ) {
					REPNZ();
				}
				else if (instr.attributes & ZYDIS_ATTRIB_HAS_REPZ) {
					REPZ();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[2];
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_SETB:
		case ZYDIS_MNEMONIC_SETBE:
		case ZYDIS_MNEMONIC_SETL:
		case ZYDIS_MNEMONIC_SETLE:
		case ZYDIS_MNEMONIC_SETNB:
		case ZYDIS_MNEMONIC_SETNBE:
		case ZYDIS_MNEMONIC_SETNL:
		case ZYDIS_MNEMONIC_SETNLE:
		case ZYDIS_MNEMONIC_SETNO:
		case ZYDIS_MNEMONIC_SETNP:
		case ZYDIS_MNEMONIC_SETNS:
		case ZYDIS_MNEMONIC_SETNZ:
		case ZYDIS_MNEMONIC_SETO:
		case ZYDIS_MNEMONIC_SETP:
		case ZYDIS_MNEMONIC_SETS:
		case ZYDIS_MNEMONIC_SETZ: {
			Value *val;
			switch (instr.opcode)
			{
			case 0x90:
				val = ICMP_NE(LD_OF(), CONST32(0)); // OF != 0
				break;

			case 0x91:
				val = ICMP_EQ(LD_OF(), CONST32(0)); // OF == 0
				break;

			case 0x92:
				val = ICMP_NE(LD_CF(), CONST32(0)); // CF != 0
				break;

			case 0x93:
				val = ICMP_EQ(LD_CF(), CONST32(0)); // CF == 0
				break;

			case 0x94:
				val = ICMP_EQ(LD_ZF(), CONST32(0)); // ZF != 0
				break;

			case 0x95:
				val = ICMP_NE(LD_ZF(), CONST32(0)); // ZF == 0
				break;

			case 0x96:
				val = OR(ICMP_NE(LD_CF(), CONST32(0)), ICMP_EQ(LD_ZF(), CONST32(0))); // CF != 0 OR ZF != 0
				break;

			case 0x97:
				val = AND(ICMP_EQ(LD_CF(), CONST32(0)), ICMP_NE(LD_ZF(), CONST32(0))); // CF == 0 AND ZF == 0
				break;

			case 0x98:
				val = ICMP_NE(LD_SF(), CONST32(0)); // SF != 0
				break;

			case 0x99:
				val = ICMP_EQ(LD_SF(), CONST32(0)); // SF == 0
				break;

			case 0x9A:
				val = ICMP_EQ(LD_PF(), CONST8(0)); // PF != 0
				break;

			case 0x9B:
				val = ICMP_NE(LD_PF(), CONST8(0)); // PF == 0
				break;

			case 0x9C:
				val = ICMP_NE(LD_SF(), SHR(LD_OF(), CONST32(31))); // SF != OF
				break;

			case 0x9D:
				val = ICMP_EQ(LD_SF(), SHR(LD_OF(), CONST32(31))); // SF == OF
				break;

			case 0x9E:
				val = OR(ICMP_EQ(LD_ZF(), CONST32(0)), ICMP_NE(LD_SF(), SHR(LD_OF(), CONST32(31)))); // ZF != 0 OR SF != OF
				break;

			case 0x9F:
				val = AND(ICMP_NE(LD_ZF(), CONST32(0)), ICMP_EQ(LD_SF(), SHR(LD_OF(), CONST32(31)))); // ZF == 0 AND SF == OF
				break;

			default:
				LIB86CPU_ABORT();
			}

			std::vector<BasicBlock *>vec_bb = getBBs(3);
			Value *rm, *byte = ALLOC8();
			BR_COND(vec_bb[0], vec_bb[1], val);
			cpu->bb = vec_bb[0];
			ST(byte, CONST8(1));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[1];
			ST(byte, CONST8(0));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[2];
			GET_RM(OPNUM_SINGLE, ST_REG_val(LD(byte), rm);, ST_MEM(MEM_LD8_idx, rm, LD(byte)););
		}
		break;

		case ZYDIS_MNEMONIC_SGDT:        BAD;
		case ZYDIS_MNEMONIC_SHL: {
			assert(instr.raw.modrm.reg == 4);

			Value *count;
			switch (instr.opcode)
			{
			case 0xD0:
				count = CONST32(1);
				size_mode = SIZE8;
				break;

			case 0xD2:
				count = ZEXT32(AND(LD_R8L(ECX_idx), CONST8(0x1F)));
				size_mode = SIZE8;
				break;

			case 0xC0:
				count = CONST32(instr.operands[OPNUM_SRC].imm.value.u & 0x1F);
				size_mode = SIZE8;
				break;

			case 0xD1:
				count = CONST32(1);
				break;

			case 0xD3:
				count = ZEXT32(AND(LD_R8L(ECX_idx), CONST8(0x1F)));
				break;

			case 0xC1:
				count = CONST32(instr.operands[OPNUM_SRC].imm.value.u & 0x1F);
				break;

			default:
				LIB86CPU_ABORT();
			}

			std::vector<BasicBlock *> vec_bb = getBBs(2);
			BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(count, CONST32(0)));
			cpu->bb = vec_bb[1];
			Value *val, *rm, *temp, *cf, *of, *of_mask, *cf_mask;
			switch (size_mode)
			{
			case SIZE8: {
				std::vector<BasicBlock *> vec_bb2 = getBBs(2);
				BR_COND(vec_bb2[0], vec_bb2[1], ICMP_ULE(count, CONST32(8)));
				cpu->bb = vec_bb2[0];
				cf_mask = SHL(CONST32(1), SUB(CONST32(8), count));
				of_mask = CONST32(1 << 7);
				GET_RM(OPNUM_DST, val = ZEXT32(LD_REG_val(rm)); cf = SHL(AND(val, cf_mask), ADD(count, CONST32(23))); val = SHL(val, count);
				of = SHL(AND(val, of_mask), CONST32(23)); val = TRUNC8(val); ST_REG_val(val, rm); SET_FLG(val, OR(cf, of)); BR_UNCOND(vec_bb[0]);
				cpu->bb = vec_bb2[1]; ST_REG_val(CONST8(0), rm); SET_FLG(CONST8(0), CONST32(0)); BR_UNCOND(vec_bb[0]);,
				temp = LD_MEM(fn_idx[size_mode], rm); val = ZEXT32(temp); cf = SHL(AND(val, cf_mask), ADD(count, CONST32(23)));
				val = SHL(val, count); of = SHL(AND(val, of_mask), CONST32(23)); val = TRUNC8(val); ST_MEM(fn_idx[size_mode], rm, val); SET_FLG(val, OR(cf, of));
				BR_UNCOND(vec_bb[0]); cpu->bb = vec_bb2[1]; ST_MEM(fn_idx[size_mode], rm, CONST8(0)); SET_FLG(CONST8(0), CONST32(0)); BR_UNCOND(vec_bb[0]););
			}
			break;

			case SIZE16: {
				std::vector<BasicBlock *> vec_bb2 = getBBs(2);
				BR_COND(vec_bb2[0], vec_bb2[1], ICMP_ULE(count, CONST32(16)));
				cpu->bb = vec_bb2[0];
				cf_mask = SHL(CONST32(1), SUB(CONST32(16), count));
				of_mask = CONST32(1 << 15);
				GET_RM(OPNUM_DST, val = ZEXT32(LD_REG_val(rm)); cf = SHL(AND(val, cf_mask), ADD(count, CONST32(15))); val = SHL(val, count);
				of = SHL(AND(val, of_mask), CONST32(15)); val = TRUNC16(val); ST_REG_val(val, rm); SET_FLG(val, OR(cf, of)); BR_UNCOND(vec_bb[0]);
				cpu->bb = vec_bb2[1]; ST_REG_val(CONST16(0), rm); SET_FLG(CONST16(0), CONST32(0)); BR_UNCOND(vec_bb[0]);,
				temp = LD_MEM(fn_idx[size_mode], rm); val = ZEXT32(temp); cf = SHL(AND(val, cf_mask), ADD(count, CONST32(15)));
				val = SHL(val, count); of = SHL(AND(val, of_mask), CONST32(15)); val = TRUNC16(val); ST_MEM(fn_idx[size_mode], rm, val); SET_FLG(val, OR(cf, of));
				BR_UNCOND(vec_bb[0]); cpu->bb = vec_bb2[1]; ST_MEM(fn_idx[size_mode], rm, CONST16(0)); SET_FLG(CONST16(0), CONST32(0)); BR_UNCOND(vec_bb[0]););
			}
			break;

			case SIZE32:
				cf_mask = SHL(CONST32(1), SUB(CONST32(32), count));
				of_mask = CONST32(1 << 31);
				GET_RM(OPNUM_DST, val = LD_REG_val(rm); cf = SHL(AND(val, cf_mask), SUB(count, CONST32(1))); val = SHL(val, count); of = SHR(AND(val, of_mask), CONST32(1));
				ST_REG_val(val, rm);, val = LD_MEM(fn_idx[size_mode], rm); cf = SHL(AND(val, cf_mask), SUB(count, CONST32(1))); val = SHL(val, count);
				of = SHR(AND(val, of_mask), CONST32(1)); ST_MEM(fn_idx[size_mode], rm, val););
				SET_FLG(val, OR(cf, of));
				BR_UNCOND(vec_bb[0]);
				break;

			default:
				LIB86CPU_ABORT();
			}

			cpu->bb = vec_bb[0];
		}
		break;

		case ZYDIS_MNEMONIC_SHLD: {
			Value *count;
			switch (instr.opcode)
			{
			case 0xA5:
				count = ZEXT32(AND(LD_R8L(ECX_idx), CONST8(0x1F)));
				break;

			case 0xA4:
				count = CONST32(instr.operands[OPNUM_THIRD].imm.value.u & 0x1F);
				break;

			default:
				LIB86CPU_ABORT();
			}

			std::vector<BasicBlock *>vec_bb = getBBs(2);
			Value *dst, *src, *rm, *flg, *val;
			BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(count, CONST32(0)));
			cpu->bb = vec_bb[1];

			switch (size_mode)
			{
			case SIZE16: {
				BasicBlock *bb = BasicBlock::Create(CTX(), "", cpu->bb->getParent(), 0);
				BR_COND(vec_bb[0], bb, ICMP_UGT(count, CONST32(16)));
				cpu->bb = bb;
				GET_RM(OPNUM_DST, dst = LD_REG_val(rm);, dst = LD_MEM(fn_idx[size_mode], rm););
				src = LD_REG_val(GET_REG(OPNUM_SRC));
				val = TRUNC16(SHR(SHL(OR(SHL(ZEXT32(dst), CONST32(16)), ZEXT32(src)), count), CONST32(16)));
				Value *cf = SHL(AND(ZEXT32(dst), SHL(CONST32(1), SUB(CONST32(16), count))), ADD(CONST32(15), count));
				Value *of = SHL(ZEXT32(XOR(AND(dst, CONST16(1 << 15)), AND(val, CONST16(1 << 15)))), CONST32(15));
				flg = OR(cf, XOR(SHR(cf, CONST32(1)), of));
			}
			break;

			case SIZE32: {
				GET_RM(OPNUM_DST, dst = LD_REG_val(rm);, dst = LD_MEM(fn_idx[size_mode], rm););
				src = LD_REG_val(GET_REG(OPNUM_SRC));
				val = TRUNC32(SHR(SHL(OR(SHL(ZEXT64(dst), CONST64(32)), ZEXT64(src)), ZEXT64(count)), CONST64(32)));
				Value *cf = SHL(AND(dst, SHL(CONST32(1), SUB(CONST32(32), count))), SUB(count, CONST32(1)));
				Value *of = SHR(XOR(AND(dst, CONST32(1 << 31)), AND(val, CONST32(1 << 31))), CONST32(1));
				flg = OR(cf, XOR(SHR(cf, CONST32(1)), of));
			}
			break;

			default:
				LIB86CPU_ABORT();
			}

			(instr.operands[OPNUM_DST].type == ZYDIS_OPERAND_TYPE_REGISTER) ? ST_REG_val(val, rm) : ST_MEM(fn_idx[size_mode], rm, val);
			SET_FLG(val, flg);
			BR_UNCOND(vec_bb[0]);
			cpu->bb = vec_bb[0];
		}
		break;

		case ZYDIS_MNEMONIC_SHR: {
			assert(instr.raw.modrm.reg == 5);

			Value *count;
			switch (instr.opcode)
			{
			case 0xD0:
				count = CONST32(1);
				size_mode = SIZE8;
				break;

			case 0xD2:
				count = ZEXT32(AND(LD_R8L(ECX_idx), CONST8(0x1F)));
				size_mode = SIZE8;
				break;

			case 0xC0:
				count = CONST32(instr.operands[OPNUM_SRC].imm.value.u & 0x1F);
				size_mode = SIZE8;
				break;

			case 0xD1:
				count = CONST32(1);
				break;

			case 0xD3:
				count = ZEXT32(AND(LD_R8L(ECX_idx), CONST8(0x1F)));
				break;

			case 0xC1:
				count = CONST32(instr.operands[OPNUM_SRC].imm.value.u & 0x1F);
				break;

			default:
				LIB86CPU_ABORT();
			}

			std::vector<BasicBlock *>vec_bb = getBBs(2);
			BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(count, CONST32(0)));
			cpu->bb = vec_bb[1];
			Value *val, *rm, *temp, *cf, *of, *of_mask, *cf_mask = SHL(CONST32(1), SUB(count, CONST32(1)));
			switch (size_mode)
			{
			case SIZE8:
				of_mask = CONST32(1 << 7);
				GET_RM(OPNUM_DST, val = ZEXT32(LD_REG_val(rm)); cf = AND(val, cf_mask); of = SHR(AND(val, of_mask), CONST32(7)); val = TRUNC8(SHR(val, count)); ST_REG_val(val, rm);,
				temp = LD_MEM(fn_idx[size_mode], rm); val = ZEXT32(temp); cf = AND(val, cf_mask); of = SHR(AND(val, of_mask), CONST32(7));
				val = TRUNC8(SHR(val, count)); ST_MEM(fn_idx[size_mode], rm, val););
				break;

			case SIZE16:
				of_mask = CONST32(1 << 15);
				GET_RM(OPNUM_DST, val = ZEXT32(LD_REG_val(rm)); cf = AND(val, cf_mask); of = SHR(AND(val, of_mask), CONST32(15)); val = TRUNC16(SHR(val, count)); ST_REG_val(val, rm);,
				temp = LD_MEM(fn_idx[size_mode], rm); val = ZEXT32(temp); cf = AND(val, cf_mask); of = SHR(AND(val, of_mask), CONST32(15));
				val = TRUNC16(SHR(val, count)); ST_MEM(fn_idx[size_mode], rm, val););
				break;

			case SIZE32:
				of_mask = CONST32(1 << 31);
				GET_RM(OPNUM_DST, val = LD_REG_val(rm); cf = AND(val, cf_mask); of = SHR(AND(val, of_mask), CONST32(31)); val = SHR(val, count);
				ST_REG_val(val, rm);, val = LD_MEM(fn_idx[size_mode], rm); cf = AND(val, cf_mask); of = SHR(AND(val, of_mask), CONST32(31));
				val = SHR(val, count); ST_MEM(fn_idx[size_mode], rm, val););
				break;

			default:
				LIB86CPU_ABORT();
			}

			SET_FLG(val, OR(SHL(cf, SUB(CONST32(32), count)), SHL(XOR(SHR(cf, SUB(count, CONST32(1))), of), CONST32(30))));
			BR_UNCOND(vec_bb[0]);
			cpu->bb = vec_bb[0];
		}
		break;

		case ZYDIS_MNEMONIC_SHRD: {
			Value *count;
			switch (instr.opcode)
			{
			case 0xAD:
				count = ZEXT32(AND(LD_R8L(ECX_idx), CONST8(0x1F)));
				break;

			case 0xAC:
				count = CONST32(instr.operands[OPNUM_THIRD].imm.value.u & 0x1F);
				break;

			default:
				LIB86CPU_ABORT();
			}

			std::vector<BasicBlock *>vec_bb = getBBs(2);
			Value *dst, *src, *rm, *flg, *val;
			BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(count, CONST32(0)));
			cpu->bb = vec_bb[1];

			switch (size_mode)
			{
			case SIZE16: {
				BasicBlock *bb = BasicBlock::Create(CTX(), "", cpu->bb->getParent(), 0);
				BR_COND(vec_bb[0], bb, ICMP_UGT(count, CONST32(16)));
				cpu->bb = bb;
				GET_RM(OPNUM_DST, dst = LD_REG_val(rm);, dst = LD_MEM(fn_idx[size_mode], rm););
				src = LD_REG_val(GET_REG(OPNUM_SRC));
				val = TRUNC16(SHR(OR(SHL(ZEXT32(src), CONST32(16)), ZEXT32(dst)), count));
				Value *cf = SHL(AND(ZEXT32(dst), SHL(CONST32(1), SUB(count, CONST32(1)))), SUB(CONST32(32), count));
				Value *of = SHL(ZEXT32(XOR(AND(dst, CONST16(1 << 15)), AND(val, CONST16(1 << 15)))), CONST32(15));
				flg = OR(cf, XOR(SHR(cf, CONST32(1)), of));
			}
			break;

			case SIZE32: {
				GET_RM(OPNUM_DST, dst = LD_REG_val(rm);, dst = LD_MEM(fn_idx[size_mode], rm););
				src = LD_REG_val(GET_REG(OPNUM_SRC));
				val = TRUNC32(SHR(OR(SHL(ZEXT64(src), CONST64(32)), ZEXT64(dst)), ZEXT64(count)));
				Value *cf = SHL(AND(dst, SHL(CONST32(1), SUB(count, CONST32(1)))), SUB(CONST32(32), count));
				Value *of = SHR(XOR(AND(dst, CONST32(1 << 31)), AND(val, CONST32(1 << 31))), CONST32(1));
				flg = OR(cf, XOR(SHR(cf, CONST32(1)), of));
			}
			break;

			default:
				LIB86CPU_ABORT();
			}

			(instr.operands[OPNUM_DST].type == ZYDIS_OPERAND_TYPE_REGISTER) ? ST_REG_val(val, rm) : ST_MEM(fn_idx[size_mode], rm, val);
			SET_FLG(val, flg);
			BR_UNCOND(vec_bb[0]);
			cpu->bb = vec_bb[0];
		}
		break;

		case ZYDIS_MNEMONIC_SIDT:        BAD;
		case ZYDIS_MNEMONIC_SLDT:        BAD;
		case ZYDIS_MNEMONIC_SMSW:        BAD;
		case ZYDIS_MNEMONIC_STC: {
			assert(instr.opcode == 0xF9);

			Value *of_new = SHR(XOR(CONST32(0x80000000), LD_OF()), CONST32(1));
			ST_FLG_AUX(OR(AND(LD_FLG_AUX(), CONST32(0x3FFFFFFF)), OR(of_new, CONST32(0x80000000))));
		}
		break;

		case ZYDIS_MNEMONIC_STD: {
			assert(instr.opcode == 0xFD);

			Value *eflags = LD_R32(EFLAGS_idx);
			eflags = OR(eflags, CONST32(DF_MASK));
			ST_R32(eflags, EFLAGS_idx);
		}
		break;

		case ZYDIS_MNEMONIC_STI: {
			assert(instr.opcode == 0xFB);

			Value *eflags = LD_R32(EFLAGS_idx);
			if (cpu->cpu_ctx.hflags & HFLG_PE_MODE) {

				// we don't support virtual 8086 mode, so we don't need to check for it
				if (((cpu->cpu_ctx.regs.eflags & IOPL_MASK) >> 12) >= (cpu->cpu_ctx.hflags & HFLG_CPL)) {
					eflags = OR(eflags, CONST32(IF_MASK));
					ST_R32(eflags, EFLAGS_idx);
				}
				else {
					RAISEin0(EXP_GP);
					translate_next = 0;
				}
			}
			else {
				eflags = OR(eflags, CONST32(IF_MASK));
				ST_R32(eflags, EFLAGS_idx);
			}
		}
		break;

		case ZYDIS_MNEMONIC_STOSB:
		case ZYDIS_MNEMONIC_STOSD:
		case ZYDIS_MNEMONIC_STOSW: {
			switch (instr.opcode)
			{
			case 0xAA:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xAB: {
				Value *val, *df, *addr, *edi;
				std::vector<BasicBlock *> vec_bb = getBBs(3);

				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP_start();
				}

				switch (addr_mode)
				{
				case ADDR16:
					edi = ZEXT32(LD_R16(EDI_idx));
					addr = ADD(LD_SEG_HIDDEN(ES_idx, SEG_BASE_idx), edi);
					break;

				case ADDR32:
					edi = LD_R32(EDI_idx);
					addr = ADD(LD_SEG_HIDDEN(ES_idx, SEG_BASE_idx), edi);
					break;

				default:
					LIB86CPU_ABORT();
				}

				switch (size_mode)
				{
				case SIZE8:
					val = CONST32(1);
					ST_MEM(fn_idx[size_mode], addr, LD_R8L(EAX_idx));
					break;

				case SIZE16:
					val = CONST32(2);
					ST_MEM(fn_idx[size_mode], addr, LD_R16(EAX_idx));
					break;

				case SIZE32:
					val = CONST32(4);
					ST_MEM(fn_idx[size_mode], addr, LD_R32(EAX_idx));
					break;

				default:
					LIB86CPU_ABORT();
				}

				df = AND(LD_R32(EFLAGS_idx), CONST32(DF_MASK));
				BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(df, CONST32(0)));

				cpu->bb = vec_bb[0];
				Value *edi_sum = ADD(edi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(edi_sum), EDI_idx) : ST_R32(edi_sum, EDI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[1];
				Value *edi_sub = SUB(edi, val);
				addr_mode == ADDR16 ? ST_R16(TRUNC16(edi_sub), EDI_idx) : ST_R32(edi_sub, EDI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[2];
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_STR:         BAD;
		case ZYDIS_MNEMONIC_SUB: {
			switch (instr.opcode)
			{
			case 0x2C:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x2D: {
				Value *dst, *eax, *sub, *src = GET_IMM();
				eax = GET_REG(OPNUM_DST);
				dst = LD_REG_val(eax);
				sub = SUB(dst, src);
				ST_REG_val(sub, eax);
				SET_FLG_SUB(sub, dst, src);
			}
			break;

			case 0x80:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x81:
			case 0x83: {
				assert(instr.raw.modrm.reg == 5);

				Value *rm, *dst, *sub, *val;
				if (instr.opcode == 0x83) {
					val = size_mode == SIZE16 ? SEXT16(GET_IMM8()) : SEXT32(GET_IMM8());
				}
				else {
					val = GET_IMM();
				}

				GET_RM(OPNUM_DST, dst = LD_REG_val(rm); sub = SUB(dst, val); ST_REG_val(sub, rm);,
				dst = LD_MEM(fn_idx[size_mode], rm); sub = SUB(dst, val); ST_MEM(fn_idx[size_mode], rm, sub););
				SET_FLG_SUB(sub, dst, val);
			}
			break;

			case 0x28:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x29: {
				Value *rm, *dst, *sub, *src = LD_REG_val(GET_REG(OPNUM_SRC));
				GET_RM(OPNUM_DST, dst = LD_REG_val(rm); sub = SUB(dst, src); ST_REG_val(sub, rm);,
					dst = LD_MEM(fn_idx[size_mode], rm); sub = SUB(dst, src); ST_MEM(fn_idx[size_mode], rm, sub););
				SET_FLG_SUB(sub, dst, src);
			}
			break;

			case 0x2A:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x2B: {
				Value *rm, *src, *sub, *dst, *reg = GET_REG(OPNUM_DST);
				dst = LD_REG_val(reg);
				GET_RM(OPNUM_SRC, src = LD_REG_val(rm);, src = LD_MEM(fn_idx[size_mode], rm););
				sub = SUB(dst, src);
				ST_REG_val(sub, reg);
				SET_FLG_SUB(sub, dst, src);
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_SYSENTER:    BAD;
		case ZYDIS_MNEMONIC_SYSEXIT:     BAD;
		case ZYDIS_MNEMONIC_TEST: {
			switch (instr.opcode)
			{
			case 0xA8:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xA9: {
				Value *val = AND(LD_REG_val(GET_REG(OPNUM_DST)), GET_IMM());
				SET_FLG(val, CONST32(0));
			}
			break;

			case 0xF6:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xF7: {
				Value *val, *rm;
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				val = AND(val, GET_IMM());
				SET_FLG(val, CONST32(0));
			}
			break;

			case 0x84:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x85: {
				Value *val, *rm;
				GET_RM(OPNUM_DST, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
				val = AND(val, LD_REG_val(GET_REG(OPNUM_SRC)));
				SET_FLG(val, CONST32(0));
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_UD1:         BAD;
		case ZYDIS_MNEMONIC_UD2:         BAD;
		case ZYDIS_MNEMONIC_VERR:
		case ZYDIS_MNEMONIC_VERW: {
			assert(instr.operands[OPNUM_SINGLE].size == 16);

			Value *rm, *sel;
			GET_RM(OPNUM_SINGLE, sel = LD_REG_val(rm);, sel = LD_MEM(MEM_LD16_idx, rm););
			std::vector<BasicBlock *> vec_bb = getBBs(5);
			BasicBlock *bb_fail = vec_bb[0];
			BR_COND(bb_fail, vec_bb[1], ICMP_EQ(SHR(sel, CONST16(2)), CONST16(0))); // sel == NULL
			cpu->bb = vec_bb[1];
			Value *desc = read_seg_desc_emit(cpu, sel, bb_fail)[1];
			Value *dpl = TRUNC16(SHR(AND(desc, CONST64(SEG_DESC_DPL)), CONST64(45)));
			BR_COND(bb_fail, vec_bb[2], OR(ICMP_EQ(AND(desc, CONST64(SEG_DESC_S)), CONST64(0)), // system desc
				AND(ICMP_NE(AND(desc, CONST64(SEG_DESC_TYC)), CONST64(0xC0000000000)), // code, conf desc
					OR(ICMP_UGT(CONST16(cpu->cpu_ctx.hflags & HFLG_CPL), dpl), ICMP_UGT(AND(sel, CONST16(3)), dpl))))); // cpl > dpl || rpl > dpl
			cpu->bb = vec_bb[2];
			if (instr.mnemonic == ZYDIS_MNEMONIC_VERR) {
				BR_COND(bb_fail, vec_bb[3], ICMP_EQ(AND(desc, CONST64(SEG_DESC_DCRW)), CONST64(0x80000000000))); // code, exec only
			}
			else {
				BR_COND(bb_fail, vec_bb[3], ICMP_NE(AND(desc, CONST64(SEG_DESC_DCRW)), CONST64(0x20000000000))); // data, r/w
			}
			cpu->bb = vec_bb[3];
			Value *new_sfd = XOR(LD_SF(), CONST32(0));
			Value *new_pdb = SHL(XOR(AND(XOR(LD_FLG_RES(), SHR(LD_FLG_AUX(), CONST32(8))), CONST32(0xFF)), CONST32(0)), CONST32(8));
			ST_FLG_AUX(OR(AND(LD_FLG_AUX(), CONST32(0xFFFF00FE)), OR(new_sfd, new_pdb)));
			ST_FLG_RES(CONST32(0));
			BR_UNCOND(vec_bb[4]);
			cpu->bb = bb_fail;
			ST_FLG_RES(OR(LD_FLG_RES(), CONST32(0x100)));
			BR_UNCOND(vec_bb[4]);
			cpu->bb = vec_bb[4];
		}
		break;

		case ZYDIS_MNEMONIC_WBINVD:      BAD;
		case ZYDIS_MNEMONIC_WRMSR:       BAD;
		case ZYDIS_MNEMONIC_XADD:        BAD;
		case ZYDIS_MNEMONIC_XCHG: {
			switch (instr.opcode)
			{
			case 0x86:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x87: {
				Value *reg, *val, *rm, *rm_src;
				rm_src = rm = GET_REG(OPNUM_SRC);
				reg = LD_REG_val(rm);
				GET_RM(OPNUM_DST, val = LD_REG_val(rm); ST_REG_val(reg, rm); ST_REG_val(val, rm_src);,
				val = LD_MEM(fn_idx[size_mode], rm); ST_MEM(fn_idx[size_mode], rm, reg); ST_REG_val(val, rm_src););
			}
			break;

			case 0x90:
			case 0x91:
			case 0x92:
			case 0x93:
			case 0x94:
			case 0x95:
			case 0x96:
			case 0x97: {
				Value *reg, *val, *reg_dst;
				reg = (size_mode == SIZE32) ? GEP_R32(EAX_idx) : GEP_R16(EAX_idx);
				reg_dst = GET_REG(OPNUM_DST);
				val = LD_REG_val(reg_dst);
				ST_REG_val(LD_REG_val(reg), reg_dst);
				ST_REG_val(val, reg);
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_XLAT:        BAD;
		case ZYDIS_MNEMONIC_XOR:
			switch (instr.opcode)
			{
			case 0x30:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x31: {
				Value *reg = GET_OP(OPNUM_SRC);
				Value *val, *rm;
				GET_RM(OPNUM_DST, val = LD_REG_val(rm); val = XOR(val, LD_REG_val(reg)); ST_REG_val(val, rm);,
				val = LD_MEM(fn_idx[size_mode], rm); val = XOR(val, LD_REG_val(reg)); ST_MEM(fn_idx[size_mode], rm, val););
				SET_FLG(val, CONST32(0));
			}
			break;

			case 0x32:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x33: {
				Value *reg = GET_REG(OPNUM_DST);
				Value *val, *rm;
				GET_RM(OPNUM_SRC, val = LD_REG_val(rm); val = XOR(val, LD_REG_val(reg)); ST_REG_val(val, reg);,
					val = LD_MEM(fn_idx[size_mode], rm); val = XOR(val, LD_REG_val(reg)); ST_REG_val(val, reg););
				SET_FLG(val, CONST32(0));
			}
			break;

			case 0x34:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x35: {
				Value *val = GET_IMM();
				Value *reg = GET_REG(OPNUM_DST);
				val = XOR(val, LD_REG_val(reg));
				ST_REG_val(val, reg);
				SET_FLG(val, CONST32(0));
			}
			break;

			case 0x80:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0x81: {
				Value *rm, *val, *imm = GET_IMM();
				GET_RM(OPNUM_DST, val = LD_REG_val(rm); val = XOR(val, imm); ST_REG_val(val, rm);,
					val = LD_MEM(fn_idx[size_mode], rm); val = XOR(val, imm); ST_MEM(fn_idx[size_mode], rm, val););
				SET_FLG(val, CONST32(0));
			}
			break;

			case 0x83: {
				Value *rm, *val, *imm = GET_IMM8();
				imm = size_mode == SIZE16 ? SEXT16(imm) : SEXT32(imm);
				GET_RM(OPNUM_DST, val = LD_REG_val(rm); val = XOR(val, imm); ST_REG_val(val, rm);,
					val = LD_MEM(fn_idx[size_mode], rm); val = XOR(val, imm); ST_MEM(fn_idx[size_mode], rm, val););
				SET_FLG(val, CONST32(0));
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
			break;

		default:
			LIB86CPU_ABORT();
		}

		pc += bytes;
		cpu->tc->size += bytes;

	} while ((translate_next | (disas_ctx->flags & (DISAS_FLG_PAGE_CROSS | DISAS_FLG_ONE_INSTR))) == 1);

	// update the eip if we stopped decoding without a terminating instr
	if ((translate_next == 1) && (DISAS_FLG_PAGE_CROSS | DISAS_FLG_ONE_INSTR) != 0) {
		ST_R32(CONST32(pc - cpu_ctx->regs.cs_hidden.base), EIP_idx);
	}

	// unconditionally jump to the exp handler if we need to service a debug trap
	if (cpu->cpu_flags & CPU_DBG_TRAP) {
		Value *tlb_idx = GEP(cpu->ptr_tlb, CONST32(cpu->cpu_ctx.exp_info.exp_data.fault_addr >> PAGE_SHIFT));
		ST(tlb_idx, OR(LD(tlb_idx), CONST32(TLB_WATCH)));
		raise_exp_inline_emit(cpu, std::vector<Value *> { CONST32(0), CONST16(0), CONST16(EXP_DB), LD_R32(EIP_idx) });
		cpu->bb = getBB();
	}
}

template<typename T>
void cpu_main_loop(cpu_t *cpu, T &&lambda)
{
	translated_code_t *prev_tc = nullptr, *ptr_tc = nullptr;
	addr_t virt_pc, pc;

	// main cpu loop
	while (lambda()) {

		retry:
		try {
			virt_pc = get_pc(&cpu->cpu_ctx);
			cpu_check_data_watchpoints(cpu, virt_pc, 1, DR7_TYPE_INSTR, cpu->cpu_ctx.regs.eip);
			pc = get_code_addr(cpu, virt_pc, cpu->cpu_ctx.regs.eip);
		}
		catch (host_exp_t type) {
			assert((type == host_exp_t::pf_exp) || (type == host_exp_t::de_exp));

			// this is either a page fault or a debug exception. In both cases, we have to call the exception handler
			try {
				// the exception handler always returns nullptr
				prev_tc = cpu->cpu_ctx.exp_fn(&cpu->cpu_ctx);
			}
			catch (host_exp_t type) {
				assert(type == host_exp_t::pf_exp);

				// page fault while delivering another exception
				// NOTE: we abort because we don't support double/triple faults yet
				LIB86CPU_ABORT();
			}

			goto retry;
		}

		ptr_tc = tc_cache_search(cpu, pc);

		if (ptr_tc == nullptr) {

			// code block for this pc not present, we need to translate new code
			std::shared_ptr<translated_code_t> tc(new translated_code_t(cpu));
			cpu->ctx = new LLVMContext();
			if (cpu->ctx == nullptr) {
				LIB86CPU_ABORT();
			}
			cpu->mod = new Module(cpu->cpu_name, *cpu->ctx);
			cpu->mod->setDataLayout(*cpu->dl);
			if (cpu->mod == nullptr) {
				LIB86CPU_ABORT();
			}

			cpu->tc = tc.get();
			create_tc_prologue(cpu);

			// add to the module the external host functions that will be called by the translated guest code
			get_ext_fn(cpu);

			// prepare the disas ctx
			disas_ctx_t disas_ctx{};
			disas_ctx.flags = ((cpu->cpu_ctx.hflags & HFLG_CS32) >> CS32_SHIFT) |
				((cpu->cpu_ctx.hflags & HFLG_PE_MODE) >> (PE_MODE_SHIFT - 1)) |
				(cpu->cpu_flags & CPU_DISAS_ONE) |
				((cpu->cpu_ctx.regs.eflags & RF_MASK) >> 9); // if rf is set, we need to clear it after the first instr executed
			disas_ctx.virt_pc = virt_pc;
			disas_ctx.pc = pc;

			auto it = cpu->hook_map.find(disas_ctx.virt_pc);
			if (it != cpu->hook_map.end()) {
				// XXX: putting a hook on the addr of an instr that causes a debug exception will cause the watchpoint not to be
				// reinstalled. That's because we will skip the call to cpu_translate below, which reinstalls it later
				cpu->instr_eip = CONST32(disas_ctx.virt_pc - cpu->cpu_ctx.regs.cs_hidden.base);
				hook_emit(cpu, it->second.get());
				cpu->tc->flags |= TC_FLG_HOOK;
				it->second->hook_tc_flags = tc;
			}
			else {
				// start guest code translation
				cpu_translate(cpu, &disas_ctx);
			}

			create_tc_epilogue(cpu);

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

			tc->pc = pc;
			tc->cs_base = cpu->cpu_ctx.regs.cs_hidden.base;
			tc->cpu_flags = cpu->cpu_ctx.hflags | (cpu->cpu_ctx.regs.eflags & (TF_MASK | IOPL_MASK | RF_MASK | AC_MASK));
			tc->ptr_code = reinterpret_cast<entry_t>(cpu->jit->lookup("main")->getAddress());
			assert(tc->ptr_code);
			tc->jmp_offset[0] = reinterpret_cast<entry_t>(cpu->jit->lookup("exit")->getAddress());
			tc->jmp_offset[1] = tc->jmp_offset[2] = tc->jmp_offset[0];
			assert(tc->jmp_offset[0]);

			// now remove the function symbol names so that we can reuse them for other modules
			cpu->jit->remove_symbols(std::vector<std::string> { "main", "exit" });

			// llvm will delete the context and the module by itself, so we just null both the pointers now to prevent accidental usage
			cpu->ctx = nullptr;
			cpu->mod = nullptr;

			// we are done with code generation for this block, so we null the tc and bb pointers to prevent accidental usage
			ptr_tc = cpu->tc;
			cpu->tc = nullptr;
			cpu->bb = nullptr;

			if (disas_ctx.flags & (DISAS_FLG_PAGE_CROSS | DISAS_FLG_ONE_INSTR)) {
				if (cpu->cpu_flags & CPU_FORCE_INSERT) {
					if ((cpu->num_tc) == CODE_CACHE_MAX_SIZE) {
						tc_cache_clear(cpu);
						prev_tc = nullptr;
					}
					tc_cache_insert(cpu, pc, std::move(tc));
				}

				cpu->cpu_flags &= ~(CPU_DISAS_ONE | CPU_ALLOW_CODE_WRITE | CPU_FORCE_INSERT | CPU_DBG_TRAP);
				tc_run_code(&cpu->cpu_ctx, ptr_tc);
				prev_tc = nullptr;
				continue;
			}
			else {
				if ((cpu->num_tc) == CODE_CACHE_MAX_SIZE) {
					tc_cache_clear(cpu);
					prev_tc = nullptr;
				}
				tc_cache_insert(cpu, pc, std::move(tc));
			}
		}

		// see if we can link the previous tc with the current one
		if (prev_tc != nullptr) {
			switch (prev_tc->flags & TC_FLG_LINK_MASK)
			{
			case 0:
			case TC_FLG_INDIRECT:
				break;

			case TC_FLG_DST_ONLY:
				tc_link_dst_only(prev_tc, ptr_tc);
				break;

			case TC_FLG_DIRECT:
				tc_link_direct(prev_tc, ptr_tc);
				break;

			default:
				LIB86CPU_ABORT();
			}
		}

		prev_tc = tc_run_code(&cpu->cpu_ctx, ptr_tc);
	}
}

lc86_status
cpu_start(cpu_t *cpu)
{
	gen_exp_fn(cpu);

	try {
		cpu_main_loop(cpu, []() { return true; });
	}
	catch (lc86_exp_abort &exp) {
		last_error = exp.what();
		return exp.get_code();
	}

	return set_last_error(lc86_status::internal_error);
}

void
trmp_stack_i32(cpu_t *cpu, std::any &value, std::vector<uint32_t *> &vec)
{
	*(vec[0]) -= 4;
	mem_write<uint32_t>(cpu, *vec[0], std::any_cast<uint32_t>(value), *vec[1], 0, nullptr);
	*(vec[1]) += 1; // simulates a push imm32 instruction
}

void
trmp_stack_i64(cpu_t *cpu, std::any &value, std::vector<uint32_t *> &vec)
{
	*(vec[0]) -= 8;
	mem_write<uint64_t>(cpu, *vec[0], std::any_cast<uint64_t>(value), *vec[1], 0, nullptr);
	*(vec[1]) += 2; // simulates two push imm32 instructions
}

void
trmp_ecx_i32(cpu_t *cpu, std::any &value, std::vector<uint32_t *> &vec)
{
	cpu->cpu_ctx.regs.ecx = std::any_cast<uint32_t>(value);
	*(vec[1]) += 5; // simulates a mov ecx,imm32 instruction
}

void
trmp_ecx_i8(cpu_t *cpu, std::any &value, std::vector<uint32_t *> &vec)
{
	cpu->cpu_ctx.regs.ecx |= std::any_cast<uint8_t>(value);
	*(vec[1]) += 2; // simulates a mov cl,imm8 instruction
}

void
trmp_edx_i32(cpu_t *cpu, std::any &value, std::vector<uint32_t *> &vec)
{
	cpu->cpu_ctx.regs.edx = std::any_cast<uint32_t>(value);
	*(vec[1]) += 5; // simulates a mov edx,imm32 instruction
}

void
trmp_edx_i8(cpu_t *cpu, std::any &value, std::vector<uint32_t *> &vec)
{
	cpu->cpu_ctx.regs.edx |= std::any_cast<uint8_t>(value);
	*(vec[1]) += 2; // simulates a mov dl,imm8 instruction
}

lc86_status
cpu_exec_trampoline(cpu_t *cpu, addr_t addr, hook *hook_ptr, std::any &ret, std::vector<std::any> &args)
{
	if (hook_ptr->trmp_vec.empty()) {
		// code for calling the trampoline is not present, we need to generate it first. This will happen when the trampoline
		// for this hook is called for the first time

		hook_ptr->trmp_vec.resize(hook_ptr->info.args.size(), nullptr);
		switch (hook_ptr->o_conv)
		{
		case call_conv::x86_cdecl: {
			uint32_t arg_size = 0;
			for (unsigned i = hook_ptr->info.args.size() - 1; i > 0; i--) {
				if (hook_ptr->info.args[i] == arg_types::i64) {
					hook_ptr->trmp_vec[i] = trmp_stack_i64;
					arg_size += 8;
				}
				else {
					hook_ptr->trmp_vec[i] = trmp_stack_i32;
					arg_size += 4;
				}
			}
			hook_ptr->cdecl_arg_size = arg_size;
		}
		break;

		case call_conv::x86_stdcall: {
			for (unsigned i = hook_ptr->info.args.size() - 1; i > 0; i--) {
				if (hook_ptr->info.args[i] == arg_types::i64) {
					hook_ptr->trmp_vec[i] = trmp_stack_i64;
				}
				else {
					hook_ptr->trmp_vec[i] = trmp_stack_i32;
				}
			}
		}
		break;

		case call_conv::x86_fastcall: {
			int num_reg_args = 0;
			bool use_stack = false;
			for (unsigned i = 1; i < hook_ptr->info.args.size(); i++) {
				if (use_stack || (hook_ptr->info.args[i] == arg_types::i64)) {
					continue;
				}
				else {
					switch (hook_ptr->info.args[i])
					{
					case arg_types::i8:
						hook_ptr->trmp_vec[i] = num_reg_args ? trmp_edx_i8 : trmp_ecx_i8;
						break;

					case arg_types::i16:
					case arg_types::i32:
					case arg_types::ptr:
					case arg_types::ptr2:
						hook_ptr->trmp_vec[i] = num_reg_args ? trmp_edx_i32 : trmp_ecx_i32;
						break;

					default:
						LIB86CPU_ABORT_msg("Unknown or invalid hook argument type specified");
					}

					num_reg_args++;
					if (num_reg_args == 2) {
						use_stack = true;
					}
				}
			}

			for (unsigned i = hook_ptr->info.args.size() - 1; i > 0; i--) {
				if (hook_ptr->trmp_vec[i] == nullptr) {
					if (hook_ptr->info.args[i] == arg_types::i64) {
						hook_ptr->trmp_vec[i] = trmp_stack_i64;
					}
					else {
						hook_ptr->trmp_vec[i] = trmp_stack_i32;
					}
				}
			}
		}
		break;

		default:
			LIB86CPU_ABORT_msg("Unknown or invalid hook calling convention specified");
		}

		hook_ptr->trmp_vec.erase(hook_ptr->trmp_vec.begin());
		hook_ptr->trmp_fn = [hook_ptr, addr](cpu_t *cpu, std::vector<std::any> &args, uint32_t *ret_eip) {
			uint32_t eip = cpu->cpu_ctx.regs.eip;
			uint32_t stack = cpu->cpu_ctx.regs.esp + cpu->cpu_ctx.regs.ss_hidden.base;
			std::vector<uint32_t *> vec { &stack, &eip };
			for (unsigned i = args.size(); i > 0 ; i--) {
				hook_ptr->trmp_vec[i - 1](cpu, args[i - 1], vec);
			}

			stack -= 4;
			mem_write<uint32_t>(cpu, stack, eip + 5, eip, 0, nullptr); // simulates a near, relative call instruction
			*ret_eip = (eip + 5);
			cpu->cpu_ctx.regs.eip = addr;
			cpu->cpu_ctx.regs.esp = stack - cpu->cpu_ctx.regs.ss_hidden.base;
		};
	}

	uint32_t ret_eip;
	uint32_t ecx = cpu->cpu_ctx.regs.ecx;
	uint32_t edx = cpu->cpu_ctx.regs.edx;
	try {
		// setup the stack to call the trampoline
		hook_ptr->trmp_fn(cpu, args, &ret_eip);
	}
	catch (host_exp_t type) {
		assert((type == host_exp_t::pf_exp) || (type == host_exp_t::de_exp));

		// page fault while calling the trampoline. We return because we can't handle an exception here. If this happens,
		// it probably means there is a stack overflow condition in the guest stack. Alternatively, this can also be a debug excepion
		cpu->cpu_ctx.regs.ecx = ecx;
		cpu->cpu_ctx.regs.edx = edx;
		return set_last_error(lc86_status::guest_exp);
	}
	catch (std::bad_any_cast e) {
		// this will happen if the client passes an argument type not supported by arg_types

		cpu->cpu_ctx.regs.ecx = ecx;
		cpu->cpu_ctx.regs.edx = edx;
		LOG(log_level::warn, "Exception thrown while calling a trampoline with error string: %s", e.what());
		return set_last_error(lc86_status::invalid_parameter);
	}

	int i = 0;
	auto &hook_node = cpu->hook_map.extract(addr);
	cpu->cpu_flags |= (CPU_DISAS_ONE | CPU_FORCE_INSERT);
	if (!(hook_ptr->hook_tc_flags.expired())) {
		hook_ptr->hook_tc_flags.lock()->cpu_flags |= CPU_IGNORE_TC;
	}
	if (!(hook_ptr->trmp_tc_flags.expired())) {
		hook_ptr->trmp_tc_flags.lock()->cpu_flags &= ~CPU_IGNORE_TC;
	}

	cpu_main_loop(cpu, [&i]() { return i++ == 0; });

	if (hook_ptr->trmp_tc_flags.expired()) {
		auto &tc_ptr = [](cpu_t *cpu, uint32_t pc) {
			uint32_t flags = cpu->cpu_ctx.hflags | (cpu->cpu_ctx.regs.eflags & (TF_MASK | IOPL_MASK | RF_MASK | AC_MASK));
			uint32_t idx = tc_hash(pc);
			auto it = cpu->code_cache[idx].begin();
			while (it != cpu->code_cache[idx].end()) {
				translated_code_t *tc = it->get();
				if (tc->cs_base == cpu->cpu_ctx.regs.cs_hidden.base &&
					tc->pc == pc &&
					tc->cpu_flags == flags) {
					return *it;
				}
				it++;
			}

			return std::shared_ptr<translated_code_t>();
			}(cpu, addr);

		if (tc_ptr) {
			assert(tc_ptr->size != 0);
			tc_ptr->cpu_flags |= CPU_IGNORE_TC;
			hook_ptr->trmp_tc_flags = tc_ptr;
		}
	}
	else {
		hook_ptr->trmp_tc_flags.lock()->cpu_flags |= CPU_IGNORE_TC;
	}
	if (!(hook_ptr->hook_tc_flags.expired())) {
		hook_ptr->hook_tc_flags.lock()->cpu_flags &= ~CPU_IGNORE_TC;
	}
	cpu->hook_map.insert(std::move(hook_node));

	cpu_main_loop(cpu, [cpu, ret_eip]() { return cpu->cpu_ctx.regs.eip != ret_eip; });

	if (hook_ptr->o_conv == call_conv::x86_cdecl) {
		// with cdecl, we also have to clean the stack ourselves

		cpu->cpu_ctx.regs.esp += hook_ptr->cdecl_arg_size;
	}

	switch (hook_ptr->info.args[0])
	{
	case arg_types::void_:
		ret.reset();
		break;

	case arg_types::i8:
		ret = static_cast<uint8_t>(cpu->cpu_ctx.regs.eax & 0xFF);
		break;

	case arg_types::i16:
	case arg_types::i32:
	case arg_types::ptr:
	case arg_types::ptr2:
		ret = cpu->cpu_ctx.regs.eax;
		break;

	case arg_types::i64:
		ret = (cpu->cpu_ctx.regs.eax | (static_cast<uint64_t>(cpu->cpu_ctx.regs.edx) << 32));
		break;

	default:
		LIB86CPU_ABORT_msg("Unknown hook return type specified");
	}

	return lc86_status::success;
}
