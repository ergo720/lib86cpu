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
#include "main_wnd.h"
#include "debugger.h"
#include "helpers.h"

#define BAD LIB86CPU_ABORT_msg("Encountered unimplemented instruction %s", log_instr(disas_ctx->virt_pc - bytes, &instr).c_str())


static void
check_dbl_exp(cpu_ctx_t *cpu_ctx)
{
	uint16_t idx = cpu_ctx->exp_info.exp_data.idx;
	bool old_contributory = cpu_ctx->exp_info.old_exp == 0 || (cpu_ctx->exp_info.old_exp >= 10 && cpu_ctx->exp_info.old_exp <= 13);
	bool curr_contributory = idx == 0 || (idx >= 10 && idx <= 13);

	LOG(log_level::info, "%s old: %u new %u", __func__, cpu_ctx->exp_info.old_exp, idx);

	if (cpu_ctx->exp_info.old_exp == EXP_DF) {
		throw lc86_exp_abort("The guest has triple faulted, cannot continue", lc86_status::success);
	}

	if ((old_contributory && curr_contributory) || (cpu_ctx->exp_info.old_exp == EXP_PF && (curr_contributory || (idx == EXP_PF)))) {
		cpu_ctx->exp_info.exp_data.code = 0;
		cpu_ctx->exp_info.exp_data.eip = 0;
		idx = EXP_DF;
	}

	if (curr_contributory || (idx == EXP_PF) || (idx == EXP_DF)) {
		cpu_ctx->exp_info.old_exp = idx;
	}

	cpu_ctx->exp_info.exp_data.idx = idx;
}

template<bool is_int>
translated_code_t *cpu_raise_exception(cpu_ctx_t *cpu_ctx)
{
	check_dbl_exp(cpu_ctx);

	cpu_t *cpu = cpu_ctx->cpu;
	uint32_t fault_addr = cpu_ctx->exp_info.exp_data.fault_addr;
	uint16_t code = cpu_ctx->exp_info.exp_data.code;
	uint16_t idx = cpu_ctx->exp_info.exp_data.idx;
	uint32_t eip = cpu_ctx->exp_info.exp_data.eip;
	uint32_t old_eflags = read_eflags(cpu);

	if (cpu_ctx->hflags & HFLG_PE_MODE) {
		// protected mode

		if (idx * 8 + 7 > cpu_ctx->regs.idtr_hidden.limit) {
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		uint64_t desc = mem_read<uint64_t>(cpu, cpu_ctx->regs.idtr_hidden.base + idx * 8, eip, 2);
		uint16_t type = (desc >> 40) & 0x1F;
		uint32_t new_eip, eflags;
		switch (type)
		{
		case 5:  // task gate
			// we don't support task gates yet, so just abort
			LIB86CPU_ABORT_msg("Task gates are not supported yet while delivering an exception");

		case 6:  // interrupt gate, 16 bit
		case 14: // interrupt gate, 32 bit
			eflags = cpu_ctx->regs.eflags & ~IF_MASK;
			new_eip = ((desc & 0xFFFF000000000000) >> 32) | (desc & 0xFFFF);
			break;

		case 7:  // trap gate, 16 bit
		case 15: // trap gate, 32 bit
			eflags = cpu_ctx->regs.eflags;
			new_eip = ((desc & 0xFFFF000000000000) >> 32) | (desc & 0xFFFF);
			break;

		default:
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		uint32_t dpl = (desc & SEG_DESC_DPL) >> 45;
		uint32_t cpl = cpu_ctx->hflags & HFLG_CPL;
		if (is_int && (dpl < cpl)) {
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		if ((desc & SEG_DESC_P) == 0) {
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2;
			cpu_ctx->exp_info.exp_data.idx = EXP_NP;
			return cpu_raise_exception(cpu_ctx);
		}

		uint16_t sel = (desc & 0xFFFF0000) >> 16;
		if ((sel >> 2) == 0) {
			cpu_ctx->exp_info.exp_data.code = 0;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		addr_t code_desc_addr;
		uint64_t code_desc;
		if (read_seg_desc_helper(cpu, sel, code_desc_addr, code_desc, eip)) {
			return cpu_raise_exception(cpu_ctx);
		}

		dpl = (code_desc & SEG_DESC_DPL) >> 45;
		if (dpl > cpl) {
			cpu_ctx->exp_info.exp_data.code = sel & 0xFFFC;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		if ((code_desc & SEG_DESC_P) == 0) {
			cpu_ctx->exp_info.exp_data.code = sel & 0xFFFC;
			cpu_ctx->exp_info.exp_data.idx = EXP_NP;
			return cpu_raise_exception(cpu_ctx);
		}

		if (code_desc & SEG_DESC_C) {
			dpl = cpl;
		}

		set_access_flg_seg_desc_helper(cpu, code_desc, code_desc_addr, eip);

		uint32_t seg_base = read_seg_desc_base_helper(cpu, code_desc);
		uint32_t seg_limit = read_seg_desc_limit_helper(cpu, code_desc);
		uint32_t seg_flags = read_seg_desc_flags_helper(cpu, code_desc);
		uint32_t stack_switch, stack_mask, stack_base, esp;
		uint32_t new_esp;
		uint16_t new_ss;
		addr_t ss_desc_addr;
		uint64_t ss_desc;

		if (dpl < cpl) {
			// more privileged

			if (read_stack_ptr_from_tss_helper(cpu, dpl, new_esp, new_ss, eip)) {
				return cpu_raise_exception(cpu_ctx);
			}

			if ((new_ss >> 2) == 0) {
				cpu_ctx->exp_info.exp_data.code = new_ss & 0xFFFC;
				cpu_ctx->exp_info.exp_data.idx = EXP_TS;
				return cpu_raise_exception(cpu_ctx);
			}

			if (read_seg_desc_helper(cpu, new_ss, ss_desc_addr, ss_desc, eip)) {
				// code already written by read_seg_desc_helper
				cpu_ctx->exp_info.exp_data.idx = EXP_TS;
				return cpu_raise_exception(cpu_ctx);
			}

			uint32_t p = (ss_desc & SEG_DESC_P) >> 40;
			uint32_t s = (ss_desc & SEG_DESC_S) >> 44;
			uint32_t d = (ss_desc & SEG_DESC_DC) >> 42;
			uint32_t w = (ss_desc & SEG_DESC_W) >> 39;
			uint32_t ss_dpl = (ss_desc & SEG_DESC_DPL) >> 42;
			uint32_t ss_rpl = (new_ss & 3) << 5;
			if ((s | d | w | ss_dpl | ss_rpl | p) ^ ((0x85 | (dpl << 3)) | (dpl << 5))) {
				cpu_ctx->exp_info.exp_data.code = new_ss & 0xFFFC;
				cpu_ctx->exp_info.exp_data.idx = EXP_TS;
				return cpu_raise_exception(cpu_ctx);
			}

			set_access_flg_seg_desc_helper(cpu, ss_desc, ss_desc_addr, eip);

			stack_switch = 1;
			stack_mask = ss_desc & SEG_DESC_DB ? 0xFFFFFFFF : 0xFFFF;
			stack_base = read_seg_desc_base_helper(cpu, ss_desc);
			esp = new_esp;
		}
		else { // same privilege
			stack_switch = 0;
			stack_mask = cpu_ctx->hflags & HFLG_SS32 ? 0xFFFFFFFF : 0xFFFF;
			stack_base = cpu_ctx->regs.ss_hidden.base;
			esp = cpu_ctx->regs.esp;
		}

		uint8_t has_code;
		switch (idx)
		{
		case EXP_DF:
		case EXP_TS:
		case EXP_NP:
		case EXP_SS:
		case EXP_GP:
		case EXP_PF:
		case EXP_AC:
			has_code = 1;
			break;

		default:
			has_code = 0;
		}

		type >>= 3;
		if (stack_switch) {
			if (type) { // push 32, priv
				esp -= 4;
				mem_write<uint32_t>(cpu, stack_base + (esp & stack_mask), cpu_ctx->regs.ss, eip, 2);
				esp -= 4;
				mem_write<uint32_t>(cpu, stack_base + (esp & stack_mask), cpu_ctx->regs.esp, eip, 2);
				esp -= 4;
				mem_write<uint32_t>(cpu, stack_base + (esp & stack_mask), old_eflags, eip, 2);
				esp -= 4;
				mem_write<uint32_t>(cpu, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, eip, 2);
				esp -= 4;
				mem_write<uint32_t>(cpu, stack_base + (esp & stack_mask), eip, eip, 2);
				if (has_code) {
					esp -= 4;
					mem_write<uint32_t>(cpu, stack_base + (esp & stack_mask), code, eip, 2);
				}
			}
			else { // push 16, priv
				esp -= 2;
				mem_write<uint16_t>(cpu, stack_base + (esp & stack_mask), cpu_ctx->regs.ss, eip, 2);
				esp -= 2;
				mem_write<uint16_t>(cpu, stack_base + (esp & stack_mask), cpu_ctx->regs.esp, eip, 2);
				esp -= 2;
				mem_write<uint16_t>(cpu, stack_base + (esp & stack_mask), old_eflags, eip, 2);
				esp -= 2;
				mem_write<uint16_t>(cpu, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, eip, 2);
				esp -= 2;
				mem_write<uint16_t>(cpu, stack_base + (esp & stack_mask), eip, eip, 2);
				if (has_code) {
					esp -= 2;
					mem_write<uint16_t>(cpu, stack_base + (esp & stack_mask), code, eip, 2);
				}
			}

			uint32_t ss_flags = read_seg_desc_flags_helper(cpu, ss_desc);
			cpu_ctx->regs.ss = (new_ss & ~3) | dpl;
			cpu_ctx->regs.ss_hidden.base = stack_base;
			cpu_ctx->regs.ss_hidden.limit = read_seg_desc_limit_helper(cpu, ss_desc);
			cpu_ctx->regs.ss_hidden.flags = ss_flags;
			cpu_ctx->hflags = ((ss_flags & SEG_HIDDEN_DB) >> 19) | (cpu_ctx->hflags & ~HFLG_SS32);
		}
		else {
			if (type) { // push 32, not priv
				esp -= 4;
				mem_write<uint32_t>(cpu, stack_base + (esp & stack_mask), old_eflags, eip, 0);
				esp -= 4;
				mem_write<uint32_t>(cpu, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, eip, 0);
				esp -= 4;
				mem_write<uint32_t>(cpu, stack_base + (esp & stack_mask), eip, eip, 0);
				if (has_code) {
					esp -= 4;
					mem_write<uint32_t>(cpu, stack_base + (esp & stack_mask), code, eip, 0);
				}
			}
			else { // push 16, not priv
				esp -= 2;
				mem_write<uint16_t>(cpu, stack_base + (esp & stack_mask), old_eflags, eip, 0);
				esp -= 2;
				mem_write<uint16_t>(cpu, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, eip, 0);
				esp -= 2;
				mem_write<uint16_t>(cpu, stack_base + (esp & stack_mask), eip, eip, 0);
				if (has_code) {
					esp -= 2;
					mem_write<uint16_t>(cpu, stack_base + (esp & stack_mask), code, eip, 0);
				}
			}
		}

		cpu_ctx->regs.eflags = (eflags & ~(VM_MASK | RF_MASK | NT_MASK | TF_MASK));
		cpu_ctx->regs.esp = (cpu_ctx->regs.esp & ~stack_mask) | (esp & stack_mask);
		cpu_ctx->regs.cs = (sel & ~3) | dpl;
		cpu_ctx->regs.cs_hidden.base = seg_base;
		cpu_ctx->regs.cs_hidden.limit = seg_limit;
		cpu_ctx->regs.cs_hidden.flags = seg_flags;
		cpu_ctx->hflags = (((seg_flags & SEG_HIDDEN_DB) >> 20) | dpl) | (cpu_ctx->hflags & ~(HFLG_CS32 | HFLG_CPL));
		cpu_ctx->regs.eip = new_eip;
		// always clear HFLG_DBG_TRAP
		cpu_ctx->hflags &= ~HFLG_DBG_TRAP;
		if (idx == EXP_PF) {
			cpu_ctx->regs.cr2 = fault_addr;
		}
		if (idx == EXP_DB) {
			cpu_ctx->regs.dr7 &= ~DR7_GD_MASK;
		}
		cpu_ctx->exp_info.old_exp = EXP_INVALID;
	}
	else {
		// real mode

		if (idx * 4 + 3 > cpu_ctx->regs.idtr_hidden.limit) {
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		uint32_t vec_entry = mem_read<uint32_t>(cpu, cpu_ctx->regs.idtr_hidden.base + idx * 4, eip, 0);
		uint32_t stack_mask = 0xFFFF;
		uint32_t stack_base = cpu_ctx->regs.ss_hidden.base;
		uint32_t esp = cpu_ctx->regs.esp;
		esp -= 2;
		mem_write<uint16_t>(cpu, stack_base + (esp & stack_mask), old_eflags, eip, 0);
		esp -= 2;
		mem_write<uint16_t>(cpu, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, eip, 0);
		esp -= 2;
		mem_write<uint16_t>(cpu, stack_base + (esp & stack_mask), eip, eip, 0);

		cpu_ctx->regs.eflags &= ~(AC_MASK | RF_MASK | IF_MASK | TF_MASK);
		cpu_ctx->regs.esp = (cpu_ctx->regs.esp & ~stack_mask) | (esp & stack_mask);
		cpu_ctx->regs.cs = vec_entry >> 16;
		cpu_ctx->regs.cs_hidden.base = cpu_ctx->regs.cs << 4;
		cpu_ctx->regs.eip = vec_entry & 0xFFFF;
		// always clear HFLG_DBG_TRAP
		cpu_ctx->hflags &= ~HFLG_DBG_TRAP;
		if (idx == EXP_DB) {
			cpu_ctx->regs.dr7 &= ~DR7_GD_MASK;
		}
		cpu_ctx->exp_info.old_exp = EXP_INVALID;
	}

	return nullptr;
}

addr_t
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

static inline uint32_t
tc_hash(addr_t pc)
{
	return pc & (CODE_CACHE_MAX_SIZE - 1);
}

template<bool remove_hook>
void tc_invalidate(cpu_ctx_t *cpu_ctx, addr_t addr, [[maybe_unused]] uint8_t size, [[maybe_unused]] uint32_t eip)
{
	bool halt_tc = false;
	addr_t phys_addr;
	uint8_t is_code;

	if constexpr (remove_hook) {
		phys_addr = get_write_addr(cpu_ctx->cpu, addr, 2, cpu_ctx->regs.eip, &is_code);
	}
	else {
		if (cpu_ctx->cpu->cpu_flags & CPU_ALLOW_CODE_WRITE) {
			return;
		}

		try {
			phys_addr = get_write_addr(cpu_ctx->cpu, addr, 2, eip, &is_code);
		}
		catch (host_exp_t type) {
			// because all callers of this function translate the address already, this should never happen
			LIB86CPU_ABORT_msg("Unexpected page fault in %s", __func__);
		}
	}

	// find all tc's in the page addr belongs to
	auto it_map = cpu_ctx->cpu->tc_page_map.find(phys_addr >> PAGE_SHIFT);
	if (it_map != cpu_ctx->cpu->tc_page_map.end()) {
		auto it_set = it_map->second.begin();
		uint32_t flags = (cpu_ctx->hflags & HFLG_CONST) | (cpu_ctx->regs.eflags & EFLAGS_CONST);
		std::vector<std::unordered_set<translated_code_t *>::iterator> tc_to_delete;
		// iterate over all tc's found in the page
		while (it_set != it_map->second.end()) {
			translated_code_t *tc_in_page = *it_set;
			// only invalidate the tc if phys_addr is included in the translated address range of the tc
			// hook tc's have a zero guest code size, so they are unaffected by guest writes and do not need to be considered by tc_invalidate
			bool remove_tc;
			if constexpr (remove_hook) {
				remove_tc = !tc_in_page->size && (tc_in_page->pc == phys_addr);
			}
			else {
				remove_tc = tc_in_page->size && !(std::min(phys_addr + size - 1, tc_in_page->pc + tc_in_page->size - 1) < std::max(phys_addr, tc_in_page->pc));
			}

			if (remove_tc) {
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
				while (it != cpu_ctx->cpu->code_cache[idx].end()) {
					if (it->get() == tc_in_page) {
						try {
							if (it->get()->cs_base == cpu_ctx->regs.cs_hidden.base &&
								it->get()->pc == get_code_addr(cpu_ctx->cpu, get_pc(cpu_ctx), cpu_ctx->regs.eip) &&
								it->get()->cpu_flags == flags) {
								// worst case: the write overlaps with the tc we are currently executing
								halt_tc = true;
								if constexpr (!remove_hook) {
									cpu_ctx->cpu->cpu_flags |= (CPU_DISAS_ONE | CPU_ALLOW_CODE_WRITE);
								}
							}
						}
						catch (host_exp_t type) {
							// the current tc cannot fault
						}
						cpu_ctx->cpu->code_cache[idx].erase(it);
						cpu_ctx->cpu->num_tc--;
						break;
					}
					it++;
				}

				// we can't delete the tc in tc_page_map right now because it would invalidate its iterator, which is still needed below
				tc_to_delete.push_back(it_set);

				if constexpr (remove_hook) {
					break;
				}
			}
			it_set++;
		}

		// delete the found tc's from tc_page_map and ibtc
		for (auto &it : tc_to_delete) {
			auto it_ibtc = cpu_ctx->cpu->ibtc.find((*it)->virt_pc);
			if (it_ibtc != cpu_ctx->cpu->ibtc.end()) {
				cpu_ctx->cpu->ibtc.erase(it_ibtc);
			}
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
		if constexpr (!remove_hook) {
			cpu_ctx->regs.eip = eip;
		}
		throw host_exp_t::halt_tc;
	}
}

template void tc_invalidate<true>(cpu_ctx_t *cpu_ctx, addr_t addr, [[maybe_unused]] uint8_t size, [[maybe_unused]] uint32_t eip);
template void tc_invalidate<false>(cpu_ctx_t *cpu_ctx, addr_t addr, [[maybe_unused]] uint8_t size, [[maybe_unused]] uint32_t eip);

static translated_code_t *
tc_cache_search(cpu_t *cpu, addr_t pc)
{
	uint32_t flags = (cpu->cpu_ctx.hflags & HFLG_CONST) | (cpu->cpu_ctx.regs.eflags & EFLAGS_CONST);
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
tc_cache_insert(cpu_t *cpu, addr_t pc, std::unique_ptr<translated_code_t> &&tc)
{
	cpu->num_tc++;
	cpu->tc_page_map[pc >> PAGE_SHIFT].insert(tc.get());
	cpu->code_cache[tc_hash(pc)].push_front(std::move(tc));
}

void
tc_cache_clear(cpu_t *cpu)
{
	// Use this when you want to destroy all code sections but leave intact the data sections instead. E.g: on x86-64, you'll want to keep the .pdata sections
	// when this is called from a function called from the JITed code, and the current function can potentially throw an exception
	cpu->num_tc = 0;
	cpu->tc_page_map.clear();
	cpu->ibtc.clear();
	for (auto &bucket : cpu->code_cache) {
		bucket.clear();
	}
}

void
tc_cache_purge(cpu_t *cpu)
{
	// This is like tc_cache_clear, but it also frees all the non-code sections. E.g: on x86-64, llvm also emits .pdata sections that hold the exception tables
	// necessary to unwind the stack of the JITed functions
	tc_cache_clear(cpu);
	g_mapper.destroy_all_blocks();
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
		case TC_JMP_DST_PC:
			prev_tc->jmp_offset[0] = ptr_tc->ptr_code;
			ptr_tc->linked_tc.push_front(prev_tc);
			break;

		case TC_JMP_NEXT_PC:
			prev_tc->jmp_offset[1] = ptr_tc->ptr_code;
			ptr_tc->linked_tc.push_front(prev_tc);
			break;

		case TC_JMP_RET:
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

	ZydisDecodedInstruction instr;
	ZydisDecoder decoder;
	ZyanStatus status;

	init_instr_decoder(disas_ctx, &decoder);

	do {
		cpu->instr_eip = CONST32(pc - cpu_ctx->regs.cs_hidden.base);

		try {
			status = decode_instr(cpu, disas_ctx, &decoder, &instr);
		}
		catch (host_exp_t type) {
			// this happens on instr breakpoints (not int3)
			assert(type == host_exp_t::de_exp);
			RAISEin0(EXP_DB);
			disas_ctx->flags |= DISAS_FLG_DBG_FAULT;
			return;
		}

		if (ZYAN_SUCCESS(status)) {
			// successfully decoded

			bytes = instr.length;
			disas_ctx->flags |= ((disas_ctx->virt_pc & ~PAGE_MASK) != ((disas_ctx->virt_pc + bytes - 1) & ~PAGE_MASK)) << 2;
			disas_ctx->pc += bytes;
			disas_ctx->virt_pc += bytes;

			// att syntax uses percentage symbols to designate the operands, which will cause an error/crash if we (or the client)
			// attempts to interpret them as conversion specifiers, so we pass the formatted instruction as an argument
			LOG(log_level::debug, "0x%08X  %s", disas_ctx->virt_pc - bytes, instr_logfn(disas_ctx->virt_pc - bytes, &instr).c_str());
		}
		else {
			// NOTE: if rf is set, then it means we are translating the instr that caused a breakpoint. However, the exp handler always clears rf on itw own,
			// which means we do not need to do it again here in the case the original instr raises another kind of exp
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
				volatile addr_t addr = get_code_addr(cpu, disas_ctx->virt_pc + X86_MAX_INSTR_LENGTH, disas_ctx->virt_pc - cpu->cpu_ctx.regs.cs_hidden.base, TLB_CODE, disas_ctx);
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
			ST_REG_idx(ADD(LD_R16(EAX_idx), CONST16(0x106)), EAX_idx);
			ST_FLG_AUX(CONST32(0x80000008));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[1];
			ST_FLG_AUX(CONST32(0));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[2];
			ST_REG_idx(AND(LD_R8L(EAX_idx), CONST8(0xF)), EAX_idx);
		}
		break;

		case ZYDIS_MNEMONIC_AAD: {
			Value *al = LD_R8L(EAX_idx);
			Value *ah = LD_R8H(EAX_idx);
			ST_REG_idx(ADD(al, MUL(ah, CONST8(instr.operands[OPNUM_SINGLE].imm.value.u))), EAX_idx);
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
				ST_REG_idx(UREM(al, CONST8(instr.operands[OPNUM_SINGLE].imm.value.u)), EAX_idx);
				ST_FLG_RES_ext(LD_R8L(EAX_idx));
				ST_FLG_AUX(CONST32(0));
			}
		}
		break;

		case ZYDIS_MNEMONIC_AAS: {
			std::vector<BasicBlock *> vec_bb = getBBs(3);
			BR_COND(vec_bb[0], vec_bb[1], OR(ICMP_UGT(AND(LD_R8L(EAX_idx), CONST8(0xF)), CONST8(9)), ICMP_NE(LD_AF(), CONST32(0))));
			cpu->bb = vec_bb[0];
			ST_REG_idx(SUB(LD_R16(EAX_idx), CONST16(6)), EAX_idx);
			ST_R8H(SUB(LD_R8H(EAX_idx), CONST8(1)), EAX_idx);
			ST_FLG_AUX(CONST32(0x80000008));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[1];
			ST_FLG_AUX(CONST32(0));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[2];
			ST_REG_idx(AND(LD_R8L(EAX_idx), CONST8(0xF)), EAX_idx);
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
					rm = GEP_REG_idx(EAX_idx);
					dst = LD(rm, getIntegerType(8));
					break;

				case SIZE16:
					src = CONST16(instr.operands[OPNUM_SRC].imm.value.u);
					rm = GEP_REG_idx(EAX_idx);
					dst = LD(rm, getIntegerType(16));
					break;

				case SIZE32:
					src = CONST32(instr.operands[OPNUM_SRC].imm.value.u);
					rm = GEP_REG_idx(EAX_idx);
					dst = LD(rm, getIntegerType(32));
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
				GET_RM(OPNUM_SRC, val = LD_REG_val(rm); val = AND(LD_REG_val(reg), val);, val = LD_MEM(fn_idx[size_mode], rm); val = AND(LD_REG_val(reg), val););
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
			if (instr.operands[OPNUM_DST].type == ZYDIS_OPERAND_TYPE_REGISTER) {
				ST_REG_val(new_rpl, rm);
			}
			else {
				ST_MEM(MEM_LD16_idx, rm, new_rpl);
			}
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
			ST_REG_idx(temp, reg_idx);
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
				// cs holds the cpl, so it can be assumed a constant
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
					Function *lcall_helper = cast<Function>(cpu->mod->getOrInsertFunction("lcall_pe_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
						getIntegerType(16), getIntegerType(32), getIntegerType(8), getIntegerType(32), getIntegerType(32)).getCallee());
					CallInst *ci = CallInst::Create(lcall_helper, { cpu->ptr_cpu_ctx, CONST16(new_sel), CONST32(call_eip), CONST8(size_mode), CONST32(ret_eip), cpu->instr_eip }, "", cpu->bb);
					BasicBlock *bb0 = getBB();
					BasicBlock *bb1 = getBB();
					BR_COND(bb0, bb1, ICMP_NE(ci, CONST8(0)));
					cpu->bb = bb0;
					CallInst *ci2 = CallInst::Create(cpu->ptr_exp_fn, cpu->ptr_cpu_ctx, "", cpu->bb);
					ReturnInst::Create(CTX(), ci2, cpu->bb);
					cpu->bb = bb1;
					link_indirect_emit(cpu);
					cpu->tc->flags |= TC_FLG_INDIRECT;
				}
				else {
					MEM_PUSH((std::vector<Value *> { cs, eip }));
					ST_SEG(CONST16(new_sel), CS_idx);
					ST_REG_idx(CONST32(call_eip), EIP_idx);
					ST_SEG_HIDDEN(CONST32(static_cast<uint32_t>(new_sel) << 4), CS_idx, SEG_BASE_idx);
					link_direct_emit(cpu, pc, (static_cast<uint32_t>(new_sel) << 4) + call_eip, nullptr,
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
				ST_REG_idx(CONST32(call_eip), EIP_idx);
				addr_t next_pc = pc + bytes;
				link_direct_emit(cpu, pc, cpu_ctx->regs.cs_hidden.base + call_eip, &next_pc,
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
					ST_REG_idx(call_eip, EIP_idx);
					link_indirect_emit(cpu);
					cpu->tc->flags |= TC_FLG_INDIRECT;
				}
				else if (instr.raw.modrm.reg == 3) {
					assert(instr.operands[OPNUM_SINGLE].type == ZYDIS_OPERAND_TYPE_MEMORY);

					Value *cs, *eip, *call_eip, *call_cs, *cs_addr, *offset_addr = GET_OP(OPNUM_SINGLE);
					addr_t ret_eip = (pc - cpu_ctx->regs.cs_hidden.base) + bytes;
					// cs holds the cpl, so it can be assumed a constant
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
						Function *lcall_helper = cast<Function>(cpu->mod->getOrInsertFunction("lcall_pe_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
							getIntegerType(16), getIntegerType(32), getIntegerType(8), getIntegerType(32), getIntegerType(32)).getCallee());
						CallInst *ci = CallInst::Create(lcall_helper, { cpu->ptr_cpu_ctx, call_cs, call_eip, CONST8(size_mode), CONST32(ret_eip), cpu->instr_eip }, "", cpu->bb);
						BasicBlock *bb0 = getBB();
						BasicBlock *bb1 = getBB();
						BR_COND(bb0, bb1, ICMP_NE(ci, CONST8(0)));
						cpu->bb = bb0;
						CallInst *ci2 = CallInst::Create(cpu->ptr_exp_fn, cpu->ptr_cpu_ctx, "", cpu->bb);
						ReturnInst::Create(CTX(), ci2, cpu->bb);
						cpu->bb = bb1;
					}
					else {
						std::vector<Value *> vec;
						vec.push_back(cs);
						vec.push_back(eip);
						MEM_PUSH(vec);
						ST_SEG(call_cs, CS_idx);
						ST_REG_idx(call_eip, EIP_idx);
						ST_SEG_HIDDEN(SHL(ZEXT32(call_cs), CONST32(4)), CS_idx, SEG_BASE_idx);
					}
					link_indirect_emit(cpu);
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
			ST_REG_idx(SEXT16(LD_R8L(EAX_idx)), EAX_idx);
		}
		break;

		case ZYDIS_MNEMONIC_CDQ: {
			ST_REG_idx(TRUNC32(SHR(SEXT64(LD_R32(EAX_idx)), CONST64(32))), EDX_idx);
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
			ST_REG_idx(eflags, EFLAGS_idx);
		}
		break;

		case ZYDIS_MNEMONIC_CLI: {
			assert(instr.opcode == 0xFA);

			Value *eflags = LD_R32(EFLAGS_idx);
			if (cpu_ctx->hflags & HFLG_PE_MODE) {

				// we don't support virtual 8086 mode, so we don't need to check for it
				if (((cpu->cpu_ctx.regs.eflags & IOPL_MASK) >> 12) >= (cpu->cpu_ctx.hflags & HFLG_CPL)) {
					eflags = AND(eflags, CONST32(~IF_MASK));
					ST_REG_idx(eflags, EFLAGS_idx);
				}
				else {
					RAISEin0(EXP_GP);
					translate_next = 0;
				}
			}
			else {
				eflags = AND(eflags, CONST32(~IF_MASK));
				ST_REG_idx(eflags, EFLAGS_idx);
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
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(esi_sum), ESI_idx) : ST_REG_idx(esi_sum, ESI_idx);
				Value *edi_sum = ADD(edi, val);
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(edi_sum), EDI_idx) : ST_REG_idx(edi_sum, EDI_idx);
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
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(esi_sub), ESI_idx) : ST_REG_idx(esi_sub, ESI_idx);
				Value *edi_sub = SUB(edi, val);
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(edi_sub), EDI_idx) : ST_REG_idx(edi_sub, EDI_idx);
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
			ST_REG_idx(TRUNC16(SHR(SEXT32(LD_R16(EAX_idx)), CONST32(16))), EDX_idx);
		}
		break;

		case ZYDIS_MNEMONIC_CWDE: {
			ST_REG_idx(SEXT32(LD_R16(EAX_idx)), EAX_idx);
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
			ST_REG_idx(sum, EAX_idx);
			ST_FLG_AUX(OR(OR(AND(GEN_SUM_VEC8(old_al, CONST8(6), sum), CONST32(0x80000000)), old_cf), CONST32(8)));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[1];
			ST_FLG_AUX(CONST32(0));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[2];
			BR_COND(vec_bb[3], vec_bb[4], OR(ICMP_UGT(old_al, CONST8(0x99)), ICMP_NE(old_cf, CONST32(0))));
			cpu->bb = vec_bb[3];
			ST_REG_idx(ADD(LD_R8L(EAX_idx), CONST8(0x60)), EAX_idx);
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
			ST_REG_idx(sub, EAX_idx);
			ST_FLG_AUX(OR(OR(AND(GEN_SUB_VEC8(old_al, CONST8(6), sub), CONST32(0x80000000)), old_cf), CONST32(8)));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[1];
			ST_FLG_AUX(CONST32(0));
			BR_UNCOND(vec_bb[2]);
			cpu->bb = vec_bb[2];
			BR_COND(vec_bb[3], vec_bb[4], OR(ICMP_UGT(old_al, CONST8(0x99)), ICMP_NE(old_cf, CONST32(0))));
			cpu->bb = vec_bb[3];
			ST_REG_idx(SUB(LD_R8L(EAX_idx), CONST8(0x60)), EAX_idx);
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
					ST_REG_val(TRUNC8(div), GEP_REG_idx(EAX_idx));
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
					ST_REG_val(TRUNC16(div), GEP_REG_idx(EAX_idx));
					ST_REG_val(TRUNC16(UREM(reg, ZEXT32(val))), GEP_REG_idx(EDX_idx));
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
					ST_REG_val(TRUNC32(div), GEP_REG_idx(EAX_idx));
					ST_REG_val(TRUNC32(UREM(reg, ZEXT64(val))), GEP_REG_idx(EDX_idx));
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
				esp_ptr = GEP_REG_idx(ESP_idx);
				ebp_ptr = GEP_REG_idx(EBP_idx);
				ebp_addr = ALLOC32();
				ST(ebp_addr, ZEXT32(LD_R16(EBP_idx)));
				frame_esp = OR(ZEXT32(SUB(LD_R16(ESP_idx), CONST16(4))), AND(LD_R32(ESP_idx), CONST32(0xFFFF0000)));
				args.push_back(LD_R32(EBP_idx));
			}
			break;

			case 1: { // esp, push 32
				stack_sub = 4;
				esp_ptr = GEP_REG_idx(ESP_idx);
				ebp_ptr = GEP_REG_idx(EBP_idx);
				ebp_addr = ALLOC32();
				ST(ebp_addr, LD_R32(EBP_idx));
				frame_esp = SUB(LD_R32(ESP_idx), CONST32(4));
				args.push_back(LD_R32(EBP_idx));
			}
			break;

			case 2: { // sp, push 16
				stack_sub = 2;
				esp_ptr = GEP_REG_idx(ESP_idx);
				ebp_ptr = GEP_REG_idx(EBP_idx);
				ebp_addr = ALLOC32();
				ST(ebp_addr, ZEXT32(LD_R16(EBP_idx)));
				frame_esp = SUB(LD_R16(ESP_idx), CONST16(2));
				args.push_back(LD_R16(EBP_idx));
			}
			break;

			case 3: { // esp, push 16
				stack_sub = 2;
				esp_ptr = GEP_REG_idx(ESP_idx);
				ebp_ptr = GEP_REG_idx(EBP_idx);
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
					ST(ebp_addr, SUB(LD(ebp_addr, getIntegerType(32)), CONST32(stack_sub)));
					Value *new_ebp = LD_MEM(fn_idx[size_mode], ADD(LD(ebp_addr, getIntegerType(32)), LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)));
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
					ST_REG_val(TRUNC8(div), GEP_REG_idx(EAX_idx));
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
					ST_REG_val(TRUNC16(div), GEP_REG_idx(EAX_idx));
					ST_REG_val(TRUNC16(SREM(reg, SEXT32(val))), GEP_REG_idx(EDX_idx));
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
					ST_REG_val(TRUNC32(div), GEP_REG_idx(EAX_idx));
					ST_REG_val(TRUNC32(SREM(reg, SEXT64(val))), GEP_REG_idx(EDX_idx));
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
					ST_REG_val(out, GEP_REG_idx(EAX_idx));
					ST_FLG_AUX(SHL(ZEXT32(NOT_ZERO(16, XOR(SEXT16(LD_R8L(EAX_idx)), out))), CONST32(31)));
					break;

				case SIZE16:
					reg = LD_R16(EAX_idx);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(SEXT32(reg), SEXT32(val));
					ST_REG_val(TRUNC16(SHR(out, CONST32(16))), GEP_REG_idx(EDX_idx));
					ST_REG_val(TRUNC16(out), GEP_REG_idx(EAX_idx));
					ST_FLG_AUX(SHL(NOT_ZERO(32, XOR(SEXT32(LD_R16(EAX_idx)), out)), CONST32(31)));
					break;

				case SIZE32:
					reg = LD_R32(EAX_idx);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(SEXT64(reg), SEXT64(val));
					ST_REG_val(TRUNC32(SHR(out, CONST64(32))), GEP_REG_idx(EDX_idx));
					ST_REG_val(TRUNC32(out), GEP_REG_idx(EAX_idx));
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
				Value *val = LD_IO(ZEXT16(port));
				size_mode == SIZE16 ? ST_REG_idx(val, EAX_idx) : size_mode == SIZE32 ? ST_REG_idx(val, EAX_idx) : ST_REG_idx(val, EAX_idx);
			}
			break;

			case 0xEC:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xED: {
				Value *port = LD_R16(EDX_idx);
				check_io_priv_emit(cpu, ZEXT32(port), size_mode);
				Value *val = LD_IO(port);
				size_mode == SIZE16 ? ST_REG_idx(val, EAX_idx) : size_mode == SIZE32 ? ST_REG_idx(val, EAX_idx) : ST_REG_idx(val, EAX_idx);
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
					io_val = LD_IO(port);
					ST_MEM(MEM_LD8_idx, addr, io_val);
					break;

				case SIZE16:
					val = CONST32(2);
					io_val = LD_IO(port);
					ST_MEM(MEM_LD16_idx, addr, io_val);
					break;

				case SIZE32:
					val = CONST32(4);
					io_val = LD_IO(port);
					ST_MEM(MEM_LD32_idx, addr, io_val);
					break;

				default:
					LIB86CPU_ABORT();
				}

				df = AND(LD_R32(EFLAGS_idx), CONST32(DF_MASK));
				BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(df, CONST32(0)));

				cpu->bb = vec_bb[0];
				Value *edi_sum = ADD(edi, val);
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(edi_sum), EDI_idx) : ST_REG_idx(edi_sum, EDI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[1];
				Value *edi_sub = SUB(edi, val);
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(edi_sub), EDI_idx) : ST_REG_idx(edi_sub, EDI_idx);
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

		case ZYDIS_MNEMONIC_INT3: {
			// NOTE1: we don't support virtual 8086 mode, so we don't need to check for it
			// NOTE2: we can't just use RAISEin0 because the eip should point to the instr following int3
			RAISEisInt(0, 0, EXP_BP, (pc + bytes) - cpu_ctx->regs.cs_hidden.base);
			translate_next = 0;
		}
		break;

		case ZYDIS_MNEMONIC_INT:         BAD;
		case ZYDIS_MNEMONIC_INTO:        BAD;
		case ZYDIS_MNEMONIC_INVD:        BAD;
		case ZYDIS_MNEMONIC_INVLPG:      BAD;
		case ZYDIS_MNEMONIC_IRET:
		case ZYDIS_MNEMONIC_IRETD: {
			assert(instr.opcode == 0xCF);

			if (cpu->cpu_ctx.hflags & HFLG_PE_MODE) {
				Function *iret_helper = cast<Function>(cpu->mod->getOrInsertFunction("iret_pe_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
					getIntegerType(8), getIntegerType(32)).getCallee());
				CallInst *ci = CallInst::Create(iret_helper, { cpu->ptr_cpu_ctx, CONST8(size_mode), cpu->instr_eip }, "", cpu->bb);
				BasicBlock *bb0 = getBB();
				BasicBlock *bb1 = getBB();
				BR_COND(bb0, bb1, ICMP_NE(ci, CONST8(0)));
				cpu->bb = bb0;
				CallInst *ci2 = CallInst::Create(cpu->ptr_exp_fn, cpu->ptr_cpu_ctx, "", cpu->bb);
				ReturnInst::Create(CTX(), ci2, cpu->bb);
				cpu->bb = bb1;
			}
			else {
				Function *iret_helper = cast<Function>(cpu->mod->getOrInsertFunction("iret_real_helper", getVoidType(), cpu->ptr_cpu_ctx->getType(),
					getIntegerType(8), getIntegerType(32)).getCallee());
				CallInst::Create(iret_helper, { cpu->ptr_cpu_ctx, CONST8(size_mode), cpu->instr_eip }, "", cpu->bb);
			}

			link_ret_emit(cpu);
			cpu->tc->flags |= TC_FLG_RET;
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
			addr_t next_pc2 = pc + bytes;
			link_direct_emit(cpu, pc, cpu_ctx->regs.cs_hidden.base + jump_eip, &next_pc2, LD(dst_pc, getIntegerType(32)));
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
				ST_REG_idx(CONST32(new_eip), EIP_idx);
				link_direct_emit(cpu, pc, cpu_ctx->regs.cs_hidden.base + new_eip, nullptr, CONST32(cpu_ctx->regs.cs_hidden.base + new_eip));
				cpu->tc->flags |= TC_FLG_DIRECT;
			}
			break;

			case 0xEA: {
				addr_t new_eip = instr.operands[OPNUM_SINGLE].ptr.offset;
				uint16_t new_sel = instr.operands[OPNUM_SINGLE].ptr.segment;
				if (cpu_ctx->hflags & HFLG_PE_MODE) {
					Function *ljmp_helper = cast<Function>(cpu->mod->getOrInsertFunction("ljmp_pe_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
						getIntegerType(16), getIntegerType(8), getIntegerType(32), getIntegerType(32)).getCallee());
					CallInst *ci = CallInst::Create(ljmp_helper, { cpu->ptr_cpu_ctx, CONST16(new_sel), CONST8(size_mode), CONST32(new_eip), cpu->instr_eip }, "", cpu->bb);
					BasicBlock *bb0 = getBB();
					BasicBlock *bb1 = getBB();
					BR_COND(bb0, bb1, ICMP_NE(ci, CONST8(0)));
					cpu->bb = bb0;
					CallInst *ci2 = CallInst::Create(cpu->ptr_exp_fn, cpu->ptr_cpu_ctx, "", cpu->bb);
					ReturnInst::Create(CTX(), ci2, cpu->bb);
					cpu->bb = bb1;
					link_indirect_emit(cpu);
					cpu->tc->flags |= TC_FLG_INDIRECT;
				}
				else {
					new_eip = size_mode == SIZE16 ? new_eip & 0xFFFF : new_eip;
					ST_SEG(CONST16(new_sel), CS_idx);
					ST_REG_idx(CONST32(new_eip), EIP_idx);
					ST_SEG_HIDDEN(CONST32(static_cast<uint32_t>(new_sel) << 4), CS_idx, SEG_BASE_idx);
					link_direct_emit(cpu, pc, (static_cast<uint32_t>(new_sel) << 4) + new_eip, nullptr, CONST32((static_cast<uint32_t>(new_sel) << 4) + new_eip));
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
						ST_REG_idx(new_eip, EIP_idx);
					}
					else {
						new_eip = offset;
						ST_REG_idx(new_eip, EIP_idx);
					}
					link_indirect_emit(cpu);
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
				ST_REG_idx(LD_R16(EBP_idx), ESP_idx);
				std::vector<Value *> vec_pop = MEM_POP(1);
				ST_REG_idx(vec_pop[0], EBP_idx);
				ST_REG_idx(vec_pop[1], ESP_idx);
			}
			break;

			case 1: { // esp, pop 32
				ST_REG_idx(LD_R32(EBP_idx), ESP_idx);
				std::vector<Value *> vec_pop = MEM_POP(1);
				ST_REG_idx(vec_pop[0], EBP_idx);
				ST_REG_idx(vec_pop[1], ESP_idx);
			}
			break;

			case 2: { // sp, pop 16
				ST_REG_idx(LD_R16(EBP_idx), ESP_idx);
				std::vector<Value *> vec_pop = MEM_POP(1);
				ST_REG_idx(vec_pop[0], EBP_idx);
				ST_REG_idx(vec_pop[1], ESP_idx);
			}
			break;

			case 3: { // esp, pop 16
				ST_REG_idx(LD_R32(EBP_idx), ESP_idx);
				std::vector<Value *> vec_pop = MEM_POP(1);
				ST_REG_idx(vec_pop[0], EBP_idx);
				ST_REG_idx(vec_pop[1], ESP_idx);
			}
			break;

			default:
				LIB86CPU_ABORT();
			}
		}
		break;

		case ZYDIS_MNEMONIC_LGDT: {
			assert(instr.raw.modrm.reg == 2);

			Value *rm, *limit, *base;
			GET_RM(OPNUM_SINGLE, assert(0);, limit = LD_MEM(MEM_LD16_idx, rm); rm = ADD(rm, CONST32(2)); base = LD_MEM(MEM_LD32_idx, rm););
			if (size_mode == SIZE16) {
				base = AND(base, CONST32(0x00FFFFFF));
			}
			ST_SEG_HIDDEN(base, GDTR_idx, SEG_BASE_idx);
			ST_SEG_HIDDEN(ZEXT32(limit), GDTR_idx, SEG_LIMIT_idx);
		}
		break;

		case ZYDIS_MNEMONIC_LIDT: {
			assert(instr.raw.modrm.reg == 3);

			Value *rm, *limit, *base;
			GET_RM(OPNUM_SINGLE, assert(0);, limit = LD_MEM(MEM_LD16_idx, rm); rm = ADD(rm, CONST32(2)); base = LD_MEM(MEM_LD32_idx, rm););
			if (size_mode == SIZE16) {
				base = AND(base, CONST32(0x00FFFFFF));
			}
			ST_SEG_HIDDEN(base, IDTR_idx, SEG_BASE_idx);
			ST_SEG_HIDDEN(ZEXT32(limit), IDTR_idx, SEG_LIMIT_idx);

			if (cpu->cpu_flags & CPU_DBG_PRESENT) {
				// hook the breakpoint exception handler so that the debugger can catch it
				Function *fn = cast<Function>(cpu->mod->getOrInsertFunction("dbg_update_bp_hook", getVoidType(), cpu->ptr_cpu_ctx->getType()).getCallee());
				CallInst::Create(fn, cpu->ptr_cpu_ctx, "", cpu->bb);
			}
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
				GET_RM(OPNUM_SINGLE, sel = LD_REG_val(rm);, sel = LD_MEM(MEM_LD16_idx, rm););
				Function *ltr_helper = cast<Function>(cpu->mod->getOrInsertFunction("lldt_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
					getIntegerType(16), getIntegerType(32)).getCallee());
				CallInst *ci = CallInst::Create(ltr_helper, { cpu->ptr_cpu_ctx, sel, cpu->instr_eip }, "", cpu->bb);
				BasicBlock *bb0 = getBB();
				BasicBlock *bb1 = getBB();
				BR_COND(bb0, bb1, ICMP_NE(ci, CONST8(0)));
				cpu->bb = bb0;
				CallInst *ci2 = CallInst::Create(cpu->ptr_exp_fn, cpu->ptr_cpu_ctx, "", cpu->bb);
				ReturnInst::Create(CTX(), ci2, cpu->bb);
				cpu->bb = bb1;
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
					ST_REG_idx(src, EAX_idx);
					break;

				case SIZE16:
					val = CONST32(2);
					src = LD_MEM(fn_idx[size_mode], addr);
					ST_REG_idx(src, EAX_idx);
					break;

				case SIZE32:
					val = CONST32(4);
					src = LD_MEM(fn_idx[size_mode], addr);
					ST_REG_idx(src, EAX_idx);
					break;

				default:
					LIB86CPU_ABORT();
				}

				df = AND(LD_R32(EFLAGS_idx), CONST32(DF_MASK));
				BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(df, CONST32(0)));

				cpu->bb = vec_bb[0];
				Value *esi_sum = ADD(esi, val);
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(esi_sum), ESI_idx) : ST_REG_idx(esi_sum, ESI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[1];
				Value *esi_sub = SUB(esi, val);
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(esi_sub), ESI_idx) : ST_REG_idx(esi_sub, ESI_idx);
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
				ST_REG_idx(val, ECX_idx);
				zero = CONST16(0);
				break;

			case ADDR32:
				val = SUB(LD_R32(ECX_idx), CONST32(1));
				ST_REG_idx(val, ECX_idx);
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
			addr_t next_pc = pc + bytes;
			link_direct_emit(cpu, pc, cpu_ctx->regs.cs_hidden.base + loop_eip, &next_pc, LD(dst_pc, getIntegerType(32)));
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

			const char *mov_sel_pe_fn;
			switch (instr.opcode)
			{
			case 0xB2:
				sel_idx = SS_idx;
				mov_sel_pe_fn = "mov_ss_pe_helper";
				break;

			case 0xB4:
				sel_idx = FS_idx;
				mov_sel_pe_fn = "mov_fs_pe_helper";
				break;

			case 0xB5:
				sel_idx = GS_idx;
				mov_sel_pe_fn = "mov_gs_pe_helper";
				break;

			case 0xC4:
				sel_idx = ES_idx;
				mov_sel_pe_fn = "mov_es_pe_helper";
				break;

			case 0xC5:
				sel_idx = DS_idx;
				mov_sel_pe_fn = "mov_ds_pe_helper";
				break;

			default:
				LIB86CPU_ABORT();
			}

			if (cpu_ctx->hflags & HFLG_PE_MODE) {
				if (sel_idx == SS_idx) {
					Function *mov_ss_helper = cast<Function>(cpu->mod->getOrInsertFunction(mov_sel_pe_fn, getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
						getIntegerType(16), getIntegerType(32)).getCallee());
					CallInst *ci = CallInst::Create(mov_ss_helper, { cpu->ptr_cpu_ctx, sel, cpu->instr_eip }, "", cpu->bb);
					BasicBlock *bb0 = getBB();
					BasicBlock *bb1 = getBB();
					BR_COND(bb0, bb1, ICMP_NE(ci, CONST8(0)));
					cpu->bb = bb0;
					CallInst *ci2 = CallInst::Create(cpu->ptr_exp_fn, cpu->ptr_cpu_ctx, "", cpu->bb);
					ReturnInst::Create(CTX(), ci2, cpu->bb);
					cpu->bb = bb1;
					ST(GEP_EIP(), ADD(cpu->instr_eip, CONST32(bytes)));
					ST_REG_val(offset, GET_REG(OPNUM_DST));
					if (((pc + bytes) & ~PAGE_MASK) == (pc & ~PAGE_MASK)) {
						BasicBlock *bb2 = getBB();
						BasicBlock *bb3 = getBB();
						BR_COND(bb2, bb3, ICMP_EQ(CONST32(cpu->cpu_ctx.hflags & HFLG_SS32), AND(LD(cpu->ptr_hflags, getIntegerType(32)), CONST32(HFLG_SS32))));
						cpu->bb = bb2;
						link_dst_only_emit(cpu);
						cpu->bb = bb3;
						cpu->tc->flags |= TC_FLG_COND_DST_ONLY;
					}
					translate_next = 0;
				}
				else {
					Function *mov_sel_helper = cast<Function>(cpu->mod->getOrInsertFunction(mov_sel_pe_fn, getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
						getIntegerType(16), getIntegerType(32)).getCallee());
					CallInst *ci = CallInst::Create(mov_sel_helper, { cpu->ptr_cpu_ctx, sel, cpu->instr_eip }, "", cpu->bb);
					BasicBlock *bb0 = getBB();
					BasicBlock *bb1 = getBB();
					BR_COND(bb0, bb1, ICMP_NE(ci, CONST8(0)));
					cpu->bb = bb0;
					CallInst *ci2 = CallInst::Create(cpu->ptr_exp_fn, cpu->ptr_cpu_ctx, "", cpu->bb);
					ReturnInst::Create(CTX(), ci2, cpu->bb);
					cpu->bb = bb1;
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
				GET_RM(OPNUM_SINGLE, sel = LD_REG_val(rm);, sel = LD_MEM(MEM_LD16_idx, rm););
				Function *ltr_helper = cast<Function>(cpu->mod->getOrInsertFunction("ltr_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
					getIntegerType(16), getIntegerType(32)).getCallee());
				CallInst *ci = CallInst::Create(ltr_helper, { cpu->ptr_cpu_ctx, sel, cpu->instr_eip }, "", cpu->bb);
				BasicBlock *bb0 = getBB();
				BasicBlock *bb1 = getBB();
				BR_COND(bb0, bb1, ICMP_NE(ci, CONST8(0)));
				cpu->bb = bb0;
				CallInst *ci2 = CallInst::Create(cpu->ptr_exp_fn, cpu->ptr_cpu_ctx, "", cpu->bb);
				ReturnInst::Create(CTX(), ci2, cpu->bb);
				cpu->bb = bb1;
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
					ST_REG_idx(LD_REG_val(GET_REG(OPNUM_SRC)), GET_REG_idx(instr.operands[OPNUM_DST].reg.value));
				}
			}
			break;

			case 0x21: {
				std::vector<BasicBlock *> vec_bb = getBBs(2);
				BR_COND(vec_bb[0], vec_bb[1], ICMP_NE(AND(LD_R32(DR7_idx), CONST32(DR7_GD_MASK)), CONST32(0)));
				cpu->bb = vec_bb[0];
				ST_REG_idx(OR(LD_R32(DR6_idx), CONST32(DR6_BD_MASK)), DR6_idx); // can't just use RAISE0 because we need to set bd in dr6
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
					ST_REG_idx(LD_R32(GET_REG_idx(instr.operands[OPNUM_SRC].reg.value) + dr_offset),
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
						Function *crN_fn = cast<Function>(cpu->mod->getOrInsertFunction("update_crN_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
							getIntegerType(32), getIntegerType(8), getIntegerType(32), getIntegerType(32)).getCallee());
						CallInst *ci = CallInst::Create(crN_fn, std::vector<Value *>{ cpu->ptr_cpu_ctx, val, CONST8(GET_REG_idx(instr.operands[OPNUM_DST].reg.value) - CR_offset),
							cpu->instr_eip, CONST32(bytes) }, "", cpu->bb);
						std::vector<BasicBlock *> vec_bb = getBBs(1);
						BR_COND(RAISE(CONST16(0), EXP_GP), vec_bb[0], ICMP_NE(ci, CONST8(0)));
						cpu->bb = vec_bb[0];
					}
					break;

					case ZYDIS_REGISTER_CR2:
						ST_REG_idx(val, CR2_idx);
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
				ST_REG_idx(OR(LD_R32(DR6_idx), CONST32(DR6_BD_MASK)), DR6_idx); // can't just use RAISE0 because we need to set bd in dr6
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
							Value *tlb_old_idx = GEP(cpu->ptr_tlb, getArrayType(getIntegerType(32), TLB_MAX_SIZE), SHR(LD_R32(idx), CONST32(PAGE_SHIFT)));
							Value *tlb_new_idx = GEP(cpu->ptr_tlb, getArrayType(getIntegerType(32), TLB_MAX_SIZE), SHR(LD(reg, getIntegerType(32)), CONST32(PAGE_SHIFT)));
							ST(tlb_old_idx, AND(LD(tlb_old_idx, getIntegerType(32)), CONST32(~TLB_WATCH))); // remove existing watchpoint
							BR_COND(vec_bb[0], vec_bb[1], ICMP_NE(AND(SHR(LD_R32(DR7_idx), CONST32(idx * 2)), CONST32(3)), CONST32(0)));
							cpu->bb = vec_bb[0];
							ST(tlb_new_idx, OR(LD(tlb_new_idx, getIntegerType(32)), CONST32(TLB_WATCH))); // install new watchpoint if enabled
							BR_UNCOND(vec_bb[1]);
							cpu->bb = vec_bb[1];
						}
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
						ST(reg, OR(LD(reg, getIntegerType(32)), CONST32(DR6_RES_MASK)));
						break;

					case DR5_idx: {
						BasicBlock *bb = getBB();
						BR_COND(RAISE0(EXP_UD), bb, ICMP_NE(AND(LD_R32(CR4_idx), CONST32(CR4_DE_MASK)), CONST32(0)));
						cpu->bb = bb;
						dr_offset = 2; // turns dr5 to dr7
					}
					[[fallthrough]];

					case DR7_idx: {
						ST(reg, OR(LD(reg, getIntegerType(32)), CONST32(DR7_RES_MASK)));
						for (int idx = 0; idx < 4; ++idx) {
							std::vector<BasicBlock *> vec_bb = getBBs(5);
							Value *curr_watch_addr = LD_R32(DR_offset + idx);
							Value *tlb_idx = GEP(cpu->ptr_tlb, getArrayType(getIntegerType(32), TLB_MAX_SIZE), SHR(curr_watch_addr, CONST32(PAGE_SHIFT)));
							// we don't support task switches, so local and global enable flags are the same for now
							BR_COND(vec_bb[0], vec_bb[1], ICMP_NE(AND(SHR(LD(reg, getIntegerType(32)), CONST32(idx * 2)), CONST32(3)), CONST32(0)));
							cpu->bb = vec_bb[0];
							BR_COND(vec_bb[2], vec_bb[3], ICMP_EQ(OR(AND(SHR(LD(reg, getIntegerType(32)), CONST32(DR7_TYPE_SHIFT + idx * 4)), CONST32(3)),
								AND(LD_R32(CR4_idx), CONST32(CR4_DE_MASK))), CONST32(DR7_TYPE_IO_RW | CR4_DE_MASK)));
							cpu->bb = vec_bb[2];
							// we don't support io watchpoints yet so for now we just abort
							ABORT("Io watchpoints are not supported");
							UNREACH();
							cpu->bb = vec_bb[3];
							ST(tlb_idx, OR(LD(tlb_idx, getIntegerType(32)), CONST32(TLB_WATCH))); // install watchpoint
							BR_UNCOND(vec_bb[4]);
							cpu->bb = vec_bb[1];
							ST(tlb_idx, AND(LD(tlb_idx, getIntegerType(32)), CONST32(~TLB_WATCH))); // remove watchpoint
							BR_UNCOND(vec_bb[4]);
							cpu->bb = vec_bb[4];
						}
					}
					break;

					default:
						LIB86CPU_ABORT();
					}

					ST_REG_idx(LD(reg, getIntegerType(32)), dr_idx + dr_offset);
					ST(GEP_EIP(), ADD(cpu->instr_eip, CONST32(bytes)));
					// instr breakpoint are checked at compile time, so we cannot jump to the next tc if we are writing to anything but dr6
					if ((((pc + bytes) & ~PAGE_MASK) == (pc & ~PAGE_MASK)) && ((dr_idx + dr_offset) == DR6_idx)) {
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
				GET_RM(OPNUM_DST, ST_REG_val(ZEXT32(val), rm);, ST_MEM(MEM_LD16_idx, rm, val););
			}
			break;

			case 0x8E: {
				Value *sel, *rm;
				const unsigned sel_idx = GET_REG_idx(instr.operands[OPNUM_DST].reg.value);
				GET_RM(OPNUM_SRC, sel = LD_REG_val(rm);, sel = LD_MEM(MEM_LD16_idx, rm););

				if (cpu_ctx->hflags & HFLG_PE_MODE) {
					if (sel_idx == SS_idx) {
						Function *mov_ss_helper = cast<Function>(cpu->mod->getOrInsertFunction("mov_ss_pe_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
							getIntegerType(16), getIntegerType(32)).getCallee());
						CallInst *ci = CallInst::Create(mov_ss_helper, { cpu->ptr_cpu_ctx, sel, cpu->instr_eip }, "", cpu->bb);
						BasicBlock *bb0 = getBB();
						BasicBlock *bb1 = getBB();
						BR_COND(bb0, bb1, ICMP_NE(ci, CONST8(0)));
						cpu->bb = bb0;
						CallInst *ci2 = CallInst::Create(cpu->ptr_exp_fn, cpu->ptr_cpu_ctx, "", cpu->bb);
						ReturnInst::Create(CTX(), ci2, cpu->bb);
						cpu->bb = bb1;
						ST(GEP_EIP(), ADD(cpu->instr_eip, CONST32(bytes)));
						if (((pc + bytes) & ~PAGE_MASK) == (pc & ~PAGE_MASK)) {
							BasicBlock *bb2 = getBB();
							BasicBlock *bb3 = getBB();
							BR_COND(bb2, bb3, ICMP_EQ(CONST32(cpu->cpu_ctx.hflags & HFLG_SS32), AND(LD(cpu->ptr_hflags, getIntegerType(32)), CONST32(HFLG_SS32))));
							cpu->bb = bb2;
							link_dst_only_emit(cpu);
							cpu->bb = bb3;
							cpu->tc->flags |= TC_FLG_COND_DST_ONLY;
						}
						translate_next = 0;
					}
					else {
						CallInst *ci;
						switch (sel_idx)
						{
						case DS_idx: {
							Function *mov_ds_helper = cast<Function>(cpu->mod->getOrInsertFunction("mov_ds_pe_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
								getIntegerType(16), getIntegerType(32)).getCallee());
							ci = CallInst::Create(mov_ds_helper, { cpu->ptr_cpu_ctx, sel, cpu->instr_eip }, "", cpu->bb);
						}
						break;

						case ES_idx: {
							Function *mov_es_helper = cast<Function>(cpu->mod->getOrInsertFunction("mov_es_pe_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
								getIntegerType(16), getIntegerType(32)).getCallee());
							ci = CallInst::Create(mov_es_helper, { cpu->ptr_cpu_ctx, sel, cpu->instr_eip }, "", cpu->bb);
						}
						break;

						case FS_idx: {
							Function *mov_fs_helper = cast<Function>(cpu->mod->getOrInsertFunction("mov_fs_pe_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
								getIntegerType(16), getIntegerType(32)).getCallee());
							ci = CallInst::Create(mov_fs_helper, { cpu->ptr_cpu_ctx, sel, cpu->instr_eip }, "", cpu->bb);
						}
						break;

						case GS_idx: {
							Function *mov_gs_helper = cast<Function>(cpu->mod->getOrInsertFunction("mov_gs_pe_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
								getIntegerType(16), getIntegerType(32)).getCallee());
							ci = CallInst::Create(mov_gs_helper, { cpu->ptr_cpu_ctx, sel, cpu->instr_eip }, "", cpu->bb);
						}
						break;

						default:
							LIB86CPU_ABORT();
						}

						BasicBlock *bb0 = getBB();
						BasicBlock *bb1 = getBB();
						BR_COND(bb0, bb1, ICMP_NE(ci, CONST8(0)));
						cpu->bb = bb0;
						CallInst *ci2 = CallInst::Create(cpu->ptr_exp_fn, cpu->ptr_cpu_ctx, "", cpu->bb);
						ReturnInst::Create(CTX(), ci2, cpu->bb);
						cpu->bb = bb1;
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

			case 0xA3: {
				ST_MEM(fn_idx[size_mode], GET_OP(OPNUM_DST), LD_REG_val(GET_OP(OPNUM_SRC)));
			}
			break;

			case 0xB0:
			case 0xB1:
			case 0xB2:
			case 0xB3:
			case 0xB4:
			case 0xB5:
			case 0xB6:
			case 0xB7: {
				ST_REG_val(GET_IMM8(), GET_OP(OPNUM_DST));
			}
			break;

			case 0xB8:
			case 0xB9:
			case 0xBA:
			case 0xBB:
			case 0xBC:
			case 0xBD:
			case 0xBE:
			case 0xBF: {
				ST_REG_val(GET_IMM(), GET_OP(OPNUM_DST));
			}
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
					GET_RM(OPNUM_DST, ST_REG_idx(LD_MM32(mm_idx), GET_REG_idx(instr.operands[OPNUM_DST].reg.value));, ST_MEM(MEM_LD32_idx, rm, LD_MM32(mm_idx)););
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
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(esi_sum), ESI_idx) : ST_REG_idx(esi_sum, ESI_idx);
				Value *edi_sum = ADD(edi, val);
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(edi_sum), EDI_idx) : ST_REG_idx(edi_sum, EDI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[1];
				Value *esi_sub = SUB(esi, val);
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(esi_sub), ESI_idx) : ST_REG_idx(esi_sub, ESI_idx);
				Value *edi_sub = SUB(edi, val);
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(edi_sub), EDI_idx) : ST_REG_idx(edi_sub, EDI_idx);
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
				ST_REG_val(SEXT32(val), GEP_REG_idx(GET_REG_idx(instr.operands[OPNUM_DST].reg.value)));
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
				ST_REG_val(ZEXT32(val), GEP_REG_idx(GET_REG_idx(instr.operands[OPNUM_DST].reg.value)));
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
					ST_REG_val(out, GEP_REG_idx(EAX_idx));
					ST_FLG_AUX(SHL(ZEXT32(NOT_ZERO(16, SHR(out, CONST16(8)))), CONST32(31)));
					break;

				case SIZE16:
					reg = LD_R16(EAX_idx);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(ZEXT32(reg), ZEXT32(val));
					ST_REG_val(TRUNC16(SHR(out, CONST32(16))), GEP_REG_idx(EDX_idx));
					ST_REG_val(TRUNC16(out), GEP_REG_idx(EAX_idx));
					ST_FLG_AUX(SHL(NOT_ZERO(32, SHR(out, CONST32(16))), CONST32(31)));
					break;

				case SIZE32:
					reg = LD_R32(EAX_idx);
					GET_RM(OPNUM_SINGLE, val = LD_REG_val(rm);, val = LD_MEM(fn_idx[size_mode], rm););
					out = MUL(ZEXT64(reg), ZEXT64(val));
					ST_REG_val(TRUNC32(SHR(out, CONST64(32))), GEP_REG_idx(EDX_idx));
					ST_REG_val(TRUNC32(out), GEP_REG_idx(EAX_idx));
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
				ST_IO(ZEXT16(port), size_mode == SIZE16 ? LD_R16(EAX_idx) : size_mode == SIZE32 ? LD_R32(EAX_idx) : LD_R8L(EAX_idx));
			}
			break;

			case 0xEE:
				size_mode = SIZE8;
				[[fallthrough]];

			case 0xEF: {
				Value *port = LD_R16(EDX_idx);
				check_io_priv_emit(cpu, ZEXT32(port), size_mode);
				ST_IO(port, size_mode == SIZE16 ? LD_R16(EAX_idx) : size_mode == SIZE32 ? LD_R32(EAX_idx) : LD_R8L(EAX_idx));
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
					ST_IO(port, io_val);
					break;

				case SIZE16:
					val = CONST32(2);
					io_val = LD_MEM(MEM_LD16_idx, addr);
					ST_IO(port, io_val);
					break;

				case SIZE32:
					val = CONST32(4);
					io_val = LD_MEM(MEM_LD32_idx, addr);
					ST_IO(port, io_val);
					break;

				default:
					LIB86CPU_ABORT();
				}

				df = AND(LD_R32(EFLAGS_idx), CONST32(DF_MASK));
				BR_COND(vec_bb[0], vec_bb[1], ICMP_EQ(df, CONST32(0)));

				cpu->bb = vec_bb[0];
				Value *esi_sum = ADD(esi, val);
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(esi_sum), ESI_idx) : ST_REG_idx(esi_sum, ESI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[1];
				Value *esi_sub = SUB(esi, val);
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(esi_sub), ESI_idx) : ST_REG_idx(esi_sub, ESI_idx);
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
					size_mode == SIZE16 ? ST_REG_idx(vec[0], GET_REG_idx(instr.operands[OPNUM_SINGLE].reg.value)) :
						ST_REG_idx(vec[0], GET_REG_idx(instr.operands[OPNUM_SINGLE].reg.value));
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
						if (sel_idx == SS_idx) {
							Function *mov_ss_helper = cast<Function>(cpu->mod->getOrInsertFunction("mov_ss_pe_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
								getIntegerType(16), getIntegerType(32)).getCallee());
							CallInst *ci = CallInst::Create(mov_ss_helper, { cpu->ptr_cpu_ctx, sel, cpu->instr_eip }, "", cpu->bb);
							BasicBlock *bb0 = getBB();
							BasicBlock *bb1 = getBB();
							BR_COND(bb0, bb1, ICMP_NE(ci, CONST8(0)));
							cpu->bb = bb0;
							CallInst *ci2 = CallInst::Create(cpu->ptr_exp_fn, cpu->ptr_cpu_ctx, "", cpu->bb);
							ReturnInst::Create(CTX(), ci2, cpu->bb);
							cpu->bb = bb1;
							ST(GEP_EIP(), ADD(cpu->instr_eip, CONST32(bytes)));
							ST_REG_val(vec_pop[1], vec_pop[2]);
							if (((pc + bytes) & ~PAGE_MASK) == (pc & ~PAGE_MASK)) {
								BasicBlock *bb2 = getBB();
								BasicBlock *bb3 = getBB();
								BR_COND(bb2, bb3, ICMP_EQ(CONST32(cpu->cpu_ctx.hflags & HFLG_SS32), AND(LD(cpu->ptr_hflags, getIntegerType(32)), CONST32(HFLG_SS32))));
								cpu->bb = bb2;
								link_dst_only_emit(cpu);
								cpu->bb = bb3;
								cpu->tc->flags |= TC_FLG_COND_DST_ONLY;
							}
							translate_next = 0;
						}
						else {
							CallInst *ci;
							switch (sel_idx)
							{
							case DS_idx: {
								Function *mov_ds_helper = cast<Function>(cpu->mod->getOrInsertFunction("mov_ds_pe_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
									getIntegerType(16), getIntegerType(32)).getCallee());
								ci = CallInst::Create(mov_ds_helper, { cpu->ptr_cpu_ctx, sel, cpu->instr_eip }, "", cpu->bb);
							}
							break;

							case ES_idx: {
								Function *mov_es_helper = cast<Function>(cpu->mod->getOrInsertFunction("mov_es_pe_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
									getIntegerType(16), getIntegerType(32)).getCallee());
								ci = CallInst::Create(mov_es_helper, { cpu->ptr_cpu_ctx, sel, cpu->instr_eip }, "", cpu->bb);
							}
							break;

							case FS_idx: {
								Function *mov_fs_helper = cast<Function>(cpu->mod->getOrInsertFunction("mov_fs_pe_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
									getIntegerType(16), getIntegerType(32)).getCallee());
								ci = CallInst::Create(mov_fs_helper, { cpu->ptr_cpu_ctx, sel, cpu->instr_eip }, "", cpu->bb);
							}
							break;

							case GS_idx: {
								Function *mov_gs_helper = cast<Function>(cpu->mod->getOrInsertFunction("mov_gs_pe_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
									getIntegerType(16), getIntegerType(32)).getCallee());
								ci = CallInst::Create(mov_gs_helper, { cpu->ptr_cpu_ctx, sel, cpu->instr_eip }, "", cpu->bb);
							}
							break;

							default:
								LIB86CPU_ABORT();
							}

							BasicBlock *bb0 = getBB();
							BasicBlock *bb1 = getBB();
							BR_COND(bb0, bb1, ICMP_NE(ci, CONST8(0)));
							cpu->bb = bb0;
							CallInst *ci2 = CallInst::Create(cpu->ptr_exp_fn, cpu->ptr_cpu_ctx, "", cpu->bb);
							ReturnInst::Create(CTX(), ci2, cpu->bb);
							cpu->bb = bb1;
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
						ST_REG_idx(reg, reg_idx);
					}
					sp = ADD(sp, CONST16(4));
				}
				ST_REG_idx(sp, ESP_idx);
			}
			break;

			case 1: {
				Value *esp = LD_R32(ESP_idx);
				for (int8_t reg_idx = EDI_idx; reg_idx >= EAX_idx; reg_idx--) {
					if (reg_idx != ESP_idx) {
						Value *reg = LD_MEM(MEM_LD32_idx, ADD(esp, LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)));
						ST_REG_idx(reg, reg_idx);
					}
					esp = ADD(esp, CONST32(4));
				}
				ST_REG_idx(esp, ESP_idx);
			}
			break;

			case 2: {
				Value *sp = LD_R16(ESP_idx);
				for (int8_t reg_idx = EDI_idx; reg_idx >= EAX_idx; reg_idx--) {
					if (reg_idx != ESP_idx) {
						Value *reg = LD_MEM(MEM_LD16_idx, ADD(ZEXT32(sp), LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)));
						ST_REG_idx(reg, reg_idx);
					}
					sp = ADD(sp, CONST16(2));
				}
				ST_REG_idx(sp, ESP_idx);
			}
			break;

			case 3: {
				Value *esp = LD_R32(ESP_idx);
				for (int8_t reg_idx = EDI_idx; reg_idx >= EAX_idx; reg_idx--) {
					if (reg_idx != ESP_idx) {
						Value *reg = LD_MEM(MEM_LD16_idx, ADD(esp, LD_SEG_HIDDEN(SS_idx, SEG_BASE_idx)));
						ST_REG_idx(reg, reg_idx);
					}
					esp = ADD(esp, CONST32(2));
				}
				ST_REG_idx(esp, ESP_idx);
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
				cpu->tc->flags |= TC_FLG_COND_DST_ONLY;
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

			if (instr.operands[OPNUM_DST].type == ZYDIS_OPERAND_TYPE_REGISTER) {
				ST_REG_val(res, rm);
			}
			else {
				ST_MEM(fn_idx[size_mode], rm, res);
			}
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

			if (instr.operands[OPNUM_DST].type == ZYDIS_OPERAND_TYPE_REGISTER) {
				ST_REG_val(res, rm);
			}
			else {
				ST_MEM(fn_idx[size_mode], rm, res);
			}
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
				Function *msr_r_fn = cast<Function>(cpu->mod->getOrInsertFunction("msr_read_helper", getVoidType(), cpu->ptr_cpu_ctx->getType()).getCallee());
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

			Function *rdtsc_fn = cast<Function>(cpu->mod->getOrInsertFunction("cpu_rdtsc_handler", getVoidType(), cpu->ptr_cpu_ctx->getType()).getCallee());
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
				ST_REG_idx(ret_eip, EIP_idx);
				if (has_imm_op) {
					if (cpu->cpu_ctx.hflags & HFLG_SS32) {
						Value *esp_ptr = GEP_REG_idx(ESP_idx);
						ST_REG_val(ADD(LD(esp_ptr, getIntegerType(32)), CONST32(instr.operands[OPNUM_SINGLE].imm.value.u)), esp_ptr);
					}
					else {
						Value *esp_ptr = GEP_REG_idx(ESP_idx);
						ST_REG_val(ADD(LD(esp_ptr, getIntegerType(16)), CONST16(instr.operands[OPNUM_SINGLE].imm.value.u)), esp_ptr);
					}
				}
			}
			break;

			case 0xCB: {
				if (cpu_ctx->hflags & HFLG_PE_MODE) {
					Function *lret_helper = cast<Function>(cpu->mod->getOrInsertFunction("lret_pe_helper", getIntegerType(8), cpu->ptr_cpu_ctx->getType(),
						getIntegerType(8), getIntegerType(32)).getCallee());
					CallInst *ci = CallInst::Create(lret_helper, { cpu->ptr_cpu_ctx, CONST8(size_mode), cpu->instr_eip }, "", cpu->bb);
					BasicBlock *bb0 = getBB();
					BasicBlock *bb1 = getBB();
					BR_COND(bb0, bb1, ICMP_NE(ci, CONST8(0)));
					cpu->bb = bb0;
					CallInst *ci2 = CallInst::Create(cpu->ptr_exp_fn, cpu->ptr_cpu_ctx, "", cpu->bb);
					ReturnInst::Create(CTX(), ci2, cpu->bb);
					cpu->bb = bb1;
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
					ST_REG_idx(eip, EIP_idx);
					ST_SEG(cs, CS_idx);
					ST_SEG_HIDDEN(SHL(ZEXT32(cs), CONST32(4)), CS_idx, SEG_BASE_idx);
				}
			}
			break;

			default:
				BAD;
			}

			link_ret_emit(cpu);
			cpu->tc->flags |= TC_FLG_RET;
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

			if (instr.operands[OPNUM_DST].type == ZYDIS_OPERAND_TYPE_REGISTER) {
				ST_REG_val(res, rm);
			}
			else {
				ST_MEM(fn_idx[size_mode], rm, res);
			}
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

			if (instr.operands[OPNUM_DST].type == ZYDIS_OPERAND_TYPE_REGISTER) {
				ST_REG_val(res, rm);
			}
			else {
				ST_MEM(fn_idx[size_mode], rm, res);
			}
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
					rm = GEP_REG_idx(EAX_idx);
					dst = LD(rm, getIntegerType(8));
					break;

				case SIZE16:
					src = CONST16(instr.operands[OPNUM_SRC].imm.value.u);
					rm = GEP_REG_idx(EAX_idx);
					dst = LD(rm, getIntegerType(16));
					break;

				case SIZE32:
					src = CONST32(instr.operands[OPNUM_SRC].imm.value.u);
					rm = GEP_REG_idx(EAX_idx);
					dst = LD(rm, getIntegerType(32));
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
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(edi_sum), EDI_idx) : ST_REG_idx(edi_sum, EDI_idx);
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
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(edi_sub), EDI_idx) : ST_REG_idx(edi_sub, EDI_idx);
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
			GET_RM(OPNUM_SINGLE, ST_REG_val(LD(byte, getIntegerType(8)), rm);, ST_MEM(MEM_LD8_idx, rm, LD(byte, getIntegerType(8))););
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
			Value *val, *rm, *cf, *of, *of_mask, *cf_mask;
			switch (size_mode)
			{
			case SIZE8: {
				std::vector<BasicBlock *> vec_bb2 = getBBs(2);
				rm = GET_OP(OPNUM_DST);
				BR_COND(vec_bb2[0], vec_bb2[1], ICMP_ULE(count, CONST32(8)));
				cpu->bb = vec_bb2[0];
				cf_mask = SHL(CONST32(1), SUB(CONST32(8), count));
				of_mask = CONST32(1 << 7);
				switch (instr.operands[OPNUM_DST].type)
				{
				case ZYDIS_OPERAND_TYPE_REGISTER:
					val = ZEXT32(LD_REG_val(rm));
					cf = SHL(AND(val, cf_mask), ADD(count, CONST32(23)));
					val = SHL(val, count);
					of = SHL(AND(val, of_mask), CONST32(23));
					val = TRUNC8(val);
					ST_REG_val(val, rm);
					SET_FLG(val, OR(cf, of));
					BR_UNCOND(vec_bb[0]);
					cpu->bb = vec_bb2[1];
					ST_REG_val(CONST8(0), rm);
					SET_FLG(CONST8(0), CONST32(0));
					BR_UNCOND(vec_bb[0]);
					break;

				case ZYDIS_OPERAND_TYPE_MEMORY: {
					Value *temp = LD_MEM(fn_idx[size_mode], rm);
					val = ZEXT32(temp);
					cf = SHL(AND(val, cf_mask), ADD(count, CONST32(23)));
					val = SHL(val, count);
					of = SHL(AND(val, of_mask), CONST32(23));
					val = TRUNC8(val);
					ST_MEM(fn_idx[size_mode], rm, val);
					SET_FLG(val, OR(cf, of));
					BR_UNCOND(vec_bb[0]);
					cpu->bb = vec_bb2[1];
					ST_MEM(fn_idx[size_mode], rm, CONST8(0));
					SET_FLG(CONST8(0), CONST32(0));
					BR_UNCOND(vec_bb[0]);
				}
				break;

				default:
					LIB86CPU_ABORT_msg("Invalid operand type used in GET_RM macro!");
				}
			}
			break;

			case SIZE16: {
				std::vector<BasicBlock *> vec_bb2 = getBBs(2);
				rm = GET_OP(OPNUM_DST);
				BR_COND(vec_bb2[0], vec_bb2[1], ICMP_ULE(count, CONST32(16)));
				cpu->bb = vec_bb2[0];
				cf_mask = SHL(CONST32(1), SUB(CONST32(16), count));
				of_mask = CONST32(1 << 15);
				switch (instr.operands[OPNUM_DST].type)
				{
				case ZYDIS_OPERAND_TYPE_REGISTER:
					val = ZEXT32(LD_REG_val(rm));
					cf = SHL(AND(val, cf_mask), ADD(count, CONST32(15)));
					val = SHL(val, count);
					of = SHL(AND(val, of_mask), CONST32(15));
					val = TRUNC16(val);
					ST_REG_val(val, rm);
					SET_FLG(val, OR(cf, of));
					BR_UNCOND(vec_bb[0]);
					cpu->bb = vec_bb2[1];
					ST_REG_val(CONST16(0), rm);
					SET_FLG(CONST16(0), CONST32(0));
					BR_UNCOND(vec_bb[0]);
					break;

				case ZYDIS_OPERAND_TYPE_MEMORY: {
					Value *temp = LD_MEM(fn_idx[size_mode], rm);
					val = ZEXT32(temp);
					cf = SHL(AND(val, cf_mask), ADD(count, CONST32(15)));
					val = SHL(val, count);
					of = SHL(AND(val, of_mask), CONST32(15));
					val = TRUNC16(val); ST_MEM(fn_idx[size_mode], rm, val);
					SET_FLG(val, OR(cf, of));
					BR_UNCOND(vec_bb[0]);
					cpu->bb = vec_bb2[1];
					ST_MEM(fn_idx[size_mode], rm, CONST16(0));
					SET_FLG(CONST16(0), CONST32(0));
					BR_UNCOND(vec_bb[0]);
				}
				break;

				default:
					LIB86CPU_ABORT_msg("Invalid operand type used in GET_RM macro!");
				}
			}
			break;

			case SIZE32: {
				cf_mask = SHL(CONST32(1), SUB(CONST32(32), count));
				of_mask = CONST32(1 << 31);
				rm = GET_OP(OPNUM_DST);
				switch (instr.operands[OPNUM_DST].type)
				{
				case ZYDIS_OPERAND_TYPE_REGISTER:
					val = LD_REG_val(rm);
					cf = SHL(AND(val, cf_mask), SUB(count, CONST32(1)));
					val = SHL(val, count);
					of = SHR(AND(val, of_mask), CONST32(1));
					ST_REG_val(val, rm);
					break;

				case ZYDIS_OPERAND_TYPE_MEMORY: {
					val = LD_MEM(fn_idx[size_mode], rm);
					cf = SHL(AND(val, cf_mask), SUB(count, CONST32(1)));
					val = SHL(val, count);
					of = SHR(AND(val, of_mask), CONST32(1));
					ST_MEM(fn_idx[size_mode], rm, val);
				}
				break;

				default:
					LIB86CPU_ABORT_msg("Invalid operand type used in GET_RM macro!");
				}
				SET_FLG(val, OR(cf, of));
				BR_UNCOND(vec_bb[0]);
			}
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

			if (instr.operands[OPNUM_DST].type == ZYDIS_OPERAND_TYPE_REGISTER) {
				ST_REG_val(val, rm);
			}
			else {
				ST_MEM(fn_idx[size_mode], rm, val);
			}
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

			if (instr.operands[OPNUM_DST].type == ZYDIS_OPERAND_TYPE_REGISTER) {
				ST_REG_val(val, rm);
			}
			else {
				ST_MEM(fn_idx[size_mode], rm, val);
			}
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
			ST_REG_idx(eflags, EFLAGS_idx);
		}
		break;

		case ZYDIS_MNEMONIC_STI: {
			assert(instr.opcode == 0xFB);

			Value *eflags = LD_R32(EFLAGS_idx);
			if (cpu->cpu_ctx.hflags & HFLG_PE_MODE) {

				// we don't support virtual 8086 mode, so we don't need to check for it
				if (((cpu->cpu_ctx.regs.eflags & IOPL_MASK) >> 12) >= (cpu->cpu_ctx.hflags & HFLG_CPL)) {
					eflags = OR(eflags, CONST32(IF_MASK));
					ST_REG_idx(eflags, EFLAGS_idx);
				}
				else {
					RAISEin0(EXP_GP);
					translate_next = 0;
				}
			}
			else {
				eflags = OR(eflags, CONST32(IF_MASK));
				ST_REG_idx(eflags, EFLAGS_idx);
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
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(edi_sum), EDI_idx) : ST_REG_idx(edi_sum, EDI_idx);
				if (instr.attributes & ZYDIS_ATTRIB_HAS_REP) {
					REP();
				}
				else {
					BR_UNCOND(vec_bb[2]);
				}

				cpu->bb = vec_bb[1];
				Value *edi_sub = SUB(edi, val);
				addr_mode == ADDR16 ? ST_REG_idx(TRUNC16(edi_sub), EDI_idx) : ST_REG_idx(edi_sub, EDI_idx);
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
			if (instr.mnemonic == ZYDIS_MNEMONIC_VERR) {
				Function *verr_helper = cast<Function>(cpu->mod->getOrInsertFunction("verr_helper", getVoidType(), cpu->ptr_cpu_ctx->getType(),
					getIntegerType(16), getIntegerType(32)).getCallee());
				CallInst::Create(verr_helper, { cpu->ptr_cpu_ctx, sel, cpu->instr_eip }, "", cpu->bb);
			}
			else {
				Function *verw_helper = cast<Function>(cpu->mod->getOrInsertFunction("verw_helper", getVoidType(), cpu->ptr_cpu_ctx->getType(),
					getIntegerType(16), getIntegerType(32)).getCallee());
				CallInst::Create(verw_helper, { cpu->ptr_cpu_ctx, sel, cpu->instr_eip }, "", cpu->bb);
			}
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
				switch (size_mode)
				{
				case SIZE32:
					reg = GEP_REG_idx(EAX_idx);
					break;

				case SIZE16:
					reg = GEP_REG_idx(EAX_idx);
					break;
				}
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
		ST_REG_idx(CONST32(pc - cpu_ctx->regs.cs_hidden.base), EIP_idx);
	}

	// TC_FLG_INDIRECT, TC_FLG_DIRECT and TC_FLG_DST_ONLY already check for rf/single step, so we only need to check them here with
	// TC_FLG_COND_DST_ONLY and if no linking code was emitted
	if ((cpu->tc->flags & TC_FLG_COND_DST_ONLY) || ((cpu->tc->flags & TC_FLG_LINK_MASK) == 0)) {
		check_rf_single_step_emit(cpu);
	}
}

static translated_code_t *
cpu_dbg_int(cpu_ctx_t *cpu_ctx)
{
	// this is called when the user closes the debugger window
	throw lc86_exp_abort("The debugger was closed", lc86_status::success);
}

static translated_code_t *
cpu_do_int(cpu_ctx_t *cpu_ctx)
{
	// hw interrupts not implemented yet
	throw lc86_exp_abort("Hardware interrupts are not implemented yet", lc86_status::internal_error);
}

// forward declare for cpu_main_loop
translated_code_t *tc_run_code(cpu_ctx_t *cpu_ctx, translated_code_t *tc);

template<bool is_tramp>
void cpu_suppress_trampolines(cpu_t *cpu)
{
	if constexpr (is_tramp) {
		// we need to remove the HFLG_TRAMP after we have searched the tc cache, but before executing the guest code, so that successive tc's
		// can still call hooks, if the trampolined function happens to make calls to other hooked functions internally
		cpu->cpu_ctx.hflags &= ~HFLG_TRAMP;
	}
}

template<bool is_tramp, bool is_trap, typename T>
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
			cpu_suppress_trampolines<is_tramp>(cpu);

			// this is either a page fault or a debug exception. In both cases, we have to call the exception handler
			retry_exp:
			try {
				// the exception handler always returns nullptr
				prev_tc = cpu_raise_exception(&cpu->cpu_ctx);
			}
			catch (host_exp_t type) {
				assert((type == host_exp_t::pf_exp) || (type == host_exp_t::de_exp));

				// page fault or debug exception while delivering another exception
				goto retry_exp;
			}

			goto retry;
		}

		if constexpr (!is_trap) {
			// if we are executing a trapped instr, we must always emit a new tc to run it and not consider other tc's in the cache. Doing so avoids having to invalidate
			// the tc in the cache that contains the trapped instr
			ptr_tc = tc_cache_search(cpu, pc);
		}

		if (ptr_tc == nullptr) {

			// code block for this pc not present, we need to translate new code
			std::unique_ptr<translated_code_t> tc(new translated_code_t(cpu));
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
				((cpu->cpu_flags & CPU_SINGLE_STEP) >> 3) |
				((cpu->cpu_ctx.regs.eflags & RF_MASK) >> 9) | // if rf is set, we need to clear it after the first instr executed
				((cpu->cpu_ctx.regs.eflags & TF_MASK) >> 1); // if tf is set, we need to raise a DB exp after every instruction
			disas_ctx.virt_pc = virt_pc;
			disas_ctx.pc = pc;

			if constexpr (!is_trap) {
				const auto it = cpu->hook_map.find(disas_ctx.virt_pc);
				bool take_hook;
				if constexpr (is_tramp) {
					take_hook = (it != cpu->hook_map.end()) && !(cpu->cpu_ctx.hflags & HFLG_TRAMP);
				}
				else {
					take_hook = it != cpu->hook_map.end();
				}

				if (take_hook) {
					cpu->instr_eip = CONST32(disas_ctx.virt_pc - cpu->cpu_ctx.regs.cs_hidden.base);
					hook_emit(cpu, it->second.get());
				}
				else {
					// start guest code translation
					cpu_translate(cpu, &disas_ctx);
				}
			}
			else {
				// don't take hooks if we are executing a trapped instr. Otherwise, if the trapped instr is also hooked, we will take the hook instead of executing it
				cpu_translate(cpu, &disas_ctx);
				raise_exp_inline_emit(cpu, CONST32(0), CONST16(0), CONST16(EXP_DB), LD_R32(EIP_idx));
				cpu->bb = getBB();
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
			tc->virt_pc = virt_pc;
			tc->cs_base = cpu->cpu_ctx.regs.cs_hidden.base;
			tc->cpu_flags = (cpu->cpu_ctx.hflags & HFLG_CONST) | (cpu->cpu_ctx.regs.eflags & EFLAGS_CONST);
			tc->ptr_code = reinterpret_cast<entry_t>(cpu->jit->lookup("main")->getAddress());
			assert(tc->ptr_code);
			tc->jmp_offset[0] = reinterpret_cast<entry_t>(cpu->jit->lookup("exit")->getAddress());
			tc->jmp_offset[1] = tc->jmp_offset[2] = tc->jmp_offset[0];
			assert(tc->jmp_offset[0]);
			tc->jmp_offset[3] = &cpu_dbg_int;
			tc->jmp_offset[4] = &cpu_do_int;

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
						tc_cache_purge(cpu);
						prev_tc = nullptr;
					}
					tc_cache_insert(cpu, pc, std::move(tc));
				}

				cpu_suppress_trampolines<is_tramp>(cpu);
				cpu->cpu_flags &= ~(CPU_DISAS_ONE | CPU_ALLOW_CODE_WRITE | CPU_FORCE_INSERT);
				tc_run_code(&cpu->cpu_ctx, ptr_tc);
				prev_tc = nullptr;
				continue;
			}
			else {
				if ((cpu->num_tc) == CODE_CACHE_MAX_SIZE) {
					tc_cache_purge(cpu);
					prev_tc = nullptr;
				}
				tc_cache_insert(cpu, pc, std::move(tc));
			}
		}

		cpu_suppress_trampolines<is_tramp>(cpu);

		// see if we can link the previous tc with the current one
		if (prev_tc != nullptr) {
			switch (prev_tc->flags & TC_FLG_LINK_MASK)
			{
			case 0:
				break;

			case TC_FLG_DST_ONLY:
			case TC_FLG_COND_DST_ONLY:
				tc_link_dst_only(prev_tc, ptr_tc);
				break;

			case TC_FLG_DIRECT:
				tc_link_direct(prev_tc, ptr_tc);
				break;

			case TC_FLG_RET:
			case TC_FLG_INDIRECT:
				cpu->ibtc.insert_or_assign(virt_pc, ptr_tc);
				break;

			default:
				LIB86CPU_ABORT();
			}
		}

		prev_tc = tc_run_code(&cpu->cpu_ctx, ptr_tc);
	}
}

translated_code_t *
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
			retry_exp:
			try {
				// the exception handler always returns nullptr
				return cpu_raise_exception(cpu_ctx);
			}
			catch (host_exp_t type) {
				assert((type == host_exp_t::pf_exp) || (type == host_exp_t::de_exp));

				// page fault or debug exception while delivering another exception
				goto retry_exp;
			}
		}
		break;

		case host_exp_t::de_exp: {
			// debug exception trap (mem/io r/w watch) while excecuting the translated code.
			// We set CPU_DBG_TRAP, so that we can execute the trapped instruction without triggering again a de exp,
			// and then jump to the debug handler. Note thate eip points to the trapped instr, so we can execute it.
			assert(cpu_ctx->exp_info.exp_data.idx == EXP_DB);

			cpu_ctx->cpu->cpu_flags |= CPU_DISAS_ONE;
			cpu_ctx->hflags |= HFLG_DBG_TRAP;
			cpu_ctx->regs.eip = cpu_ctx->exp_info.exp_data.eip;
			// run the main loop only once, since we only execute the trapped instr
			int i = 0;
			cpu_main_loop<false, true>(cpu_ctx->cpu, [&i]() { return i++ == 0; });
		}
		[[fallthrough]];

		case host_exp_t::cpu_mode_changed:
		case host_exp_t::halt_tc:
			return nullptr;

		default:
			LIB86CPU_ABORT_msg("Unknown host exception in %s", __func__);
		}
	}
}

lc86_status
cpu_start(cpu_t *cpu)
{
	// guard against the case gen_int_fn raises an exception before the debugger is even initialized
	try {
		gen_int_fn(cpu);
	}
	catch (lc86_exp_abort &exp) {
		last_error = exp.what();
		return exp.get_code();
	}

	if (cpu->cpu_flags & CPU_DBG_PRESENT) {
		std::promise<bool> promise;
		std::future<bool> fut = promise.get_future();
		std::thread(dbg_main_wnd, cpu, std::ref(promise)).detach();
		bool has_err = fut.get();
		if (has_err) {
			return lc86_status::internal_error;
		}
		// wait until the debugger continues execution, so that users have a chance to set breakpoints and/or inspect the guest code
		guest_running.wait(false);
	}

	try {
		cpu_main_loop<false, false>(cpu, []() { return true; });
	}
	catch (lc86_exp_abort &exp) {
		if (cpu->cpu_flags & CPU_DBG_PRESENT) {
			dbg_should_close();
		}

		last_error = exp.what();
		return exp.get_code();
	}

	assert(0);

	return set_last_error(lc86_status::internal_error);
}

void
cpu_exec_trampoline(cpu_t *cpu, const uint32_t ret_eip)
{
	// set the trampoline flag, so that we can call the trampoline tc instead of the hook tc
	cpu->cpu_ctx.hflags |= HFLG_TRAMP;
	cpu_main_loop<true, false>(cpu, [cpu, ret_eip]() { return cpu->cpu_ctx.regs.eip != ret_eip; });
}

template translated_code_t *cpu_raise_exception<true>(cpu_ctx_t *cpu_ctx);
template translated_code_t *cpu_raise_exception<false>(cpu_ctx_t *cpu_ctx);
