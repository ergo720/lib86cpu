/*
 * x86 translation code
 *
 * ergo720                Copyright (c) 2019
 */

#include "internal.h"
#include "memory.h"
#include "main_wnd.h"
#include "debugger.h"
#include "helpers.h"
#include "clock.h"

#ifdef LIB86CPU_X64_EMITTER
#include "x64/jit.h"
#endif

#define BAD LIB86CPU_ABORT_msg("Encountered unimplemented instruction %s", log_instr(disas_ctx->virt_pc - cpu->instr_bytes, &instr).c_str())


void
cpu_reset(cpu_t *cpu)
{
	std::memset(&cpu->cpu_ctx.regs, 0, sizeof(regs_t));
	cpu->cpu_ctx.regs.eip = 0x0000FFF0;
	cpu->cpu_ctx.regs.edx = 0x0000068A;
	cpu->cpu_ctx.regs.cs = 0xF000;
	cpu->cpu_ctx.regs.cs_hidden.base = 0xFFFF0000;
	cpu->cpu_ctx.regs.es_hidden.limit = cpu->cpu_ctx.regs.cs_hidden.limit = cpu->cpu_ctx.regs.ss_hidden.limit =
	cpu->cpu_ctx.regs.ds_hidden.limit = cpu->cpu_ctx.regs.fs_hidden.limit = cpu->cpu_ctx.regs.gs_hidden.limit = 0xFFFF;
	cpu->cpu_ctx.regs.cs_hidden.flags = ((1 << 15) | (1 << 12) | (1 << 11) | (1 << 9) | (1 << 8)); // present, code, readable, accessed
	cpu->cpu_ctx.regs.es_hidden.flags = cpu->cpu_ctx.regs.ss_hidden.flags = cpu->cpu_ctx.regs.ds_hidden.flags =
	cpu->cpu_ctx.regs.fs_hidden.flags = cpu->cpu_ctx.regs.gs_hidden.flags = ((1 << 15) | (1 << 12) | (1 << 9) | (1 << 8)); // present, data, writable, accessed
	cpu->cpu_ctx.regs.eflags = 0x2;
	cpu->cpu_ctx.regs.cr0 = 0x60000010;
	cpu->cpu_ctx.regs.dr[6] = DR6_RES_MASK;
	cpu->cpu_ctx.regs.dr[7] = DR7_RES_MASK;
	cpu->cpu_ctx.regs.idtr_hidden.limit = cpu->cpu_ctx.regs.gdtr_hidden.limit = cpu->cpu_ctx.regs.ldtr_hidden.limit =
	cpu->cpu_ctx.regs.tr_hidden.limit = 0xFFFF;
	cpu->cpu_ctx.regs.ldtr_hidden.flags = ((1 << 15) | (2 << 8)); // present, ldt
	cpu->cpu_ctx.regs.tr_hidden.flags = ((1 << 15) | (11 << 8)); // present, 32bit tss busy
	cpu->cpu_ctx.regs.tag = 0x5555;
	cpu->a20_mask = 0xFFFFFFFF; // gate closed
	cpu->cpu_ctx.exp_info.old_exp = EXP_INVALID;
	cpu->msr.mtrr.def_type = 0;
	std::memset(cpu->msr.mtrr.phys_var, 0, sizeof(cpu->msr.mtrr.phys_var));
	std::memset(cpu->msr.mtrr.phys_fixed, 0, sizeof(cpu->msr.mtrr.phys_fixed));
	tsc_init(cpu);
}

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

template<bool is_int, bool is_hw>
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

		constexpr uint16_t ext_flg = is_int ? 0 : 1; // EXT flag clear for INT instructions, set otherwise

		if (idx * 8 + 7 > cpu_ctx->regs.idtr_hidden.limit) {
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2 + ext_flg;
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
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2 + ext_flg;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		uint32_t dpl = (desc & SEG_DESC_DPL) >> 45;
		uint32_t cpl = cpu_ctx->hflags & HFLG_CPL;
		if (is_int && (dpl < cpl)) { // only INT instructions check the dpl of the gate in the idt
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		if ((desc & SEG_DESC_P) == 0) {
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2 + ext_flg;
			cpu_ctx->exp_info.exp_data.idx = EXP_NP;
			return cpu_raise_exception(cpu_ctx);
		}

		uint16_t sel = (desc & 0xFFFF0000) >> 16;
		if ((sel >> 2) == 0) {
			cpu_ctx->exp_info.exp_data.code = ext_flg;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		addr_t code_desc_addr;
		uint64_t code_desc;
		if (read_seg_desc_helper(cpu, sel, code_desc_addr, code_desc, eip)) {
			cpu_ctx->exp_info.exp_data.code += ext_flg;
			return cpu_raise_exception(cpu_ctx);
		}

		dpl = (code_desc & SEG_DESC_DPL) >> 45;
		if (dpl > cpl) {
			cpu_ctx->exp_info.exp_data.code = (sel & 0xFFFC) + ext_flg;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		if ((code_desc & SEG_DESC_P) == 0) {
			cpu_ctx->exp_info.exp_data.code = (sel & 0xFFFC) + ext_flg;
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
				cpu_ctx->exp_info.exp_data.code += ext_flg;
				return cpu_raise_exception(cpu_ctx);
			}

			if ((new_ss >> 2) == 0) {
				cpu_ctx->exp_info.exp_data.code = ext_flg;
				cpu_ctx->exp_info.exp_data.idx = EXP_TS;
				return cpu_raise_exception(cpu_ctx);
			}

			if (read_seg_desc_helper(cpu, new_ss, ss_desc_addr, ss_desc, eip)) {
				cpu_ctx->exp_info.exp_data.code += ext_flg;
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
				cpu_ctx->exp_info.exp_data.code = (new_ss & 0xFFFC) + ext_flg;
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
		if constexpr (is_int || is_hw) {
			// INT instructions and hw interrupts don't push error codes
			has_code = 0;
		}
		else {
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
			cpu_ctx->regs.dr[7] &= ~DR7_GD_MASK;
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
			cpu_ctx->regs.dr[7] &= ~DR7_GD_MASK;
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

translated_code_t::translated_code_t() noexcept
{
	size = 0;
	flags = 0;
	ptr_code = nullptr;
}

static inline uint32_t
tc_hash(addr_t pc)
{
	return pc & (CODE_CACHE_MAX_SIZE - 1);
}

template<bool remove_hook, bool is_virt>
void tc_invalidate(cpu_ctx_t *cpu_ctx, addr_t addr, [[maybe_unused]] uint8_t size, [[maybe_unused]] uint32_t eip)
{
	bool halt_tc = false;
	addr_t phys_addr;
	uint8_t is_code;

	if constexpr (remove_hook) {
		if constexpr (is_virt) {
			phys_addr = get_write_addr(cpu_ctx->cpu, addr, 2, cpu_ctx->regs.eip, &is_code);
		}
		else {
			phys_addr = addr;
		}
	}
	else {
		if (cpu_ctx->cpu->cpu_flags & CPU_ALLOW_CODE_WRITE) {
			return;
		}

		if constexpr (is_virt) {
			try {
				phys_addr = get_write_addr(cpu_ctx->cpu, addr, 2, eip, &is_code);
			}
			catch (host_exp_t type) {
				// because all callers of this function translate the address already, this should never happen
				LIB86CPU_ABORT_msg("Unexpected page fault in %s", __func__);
			}
		}
		else {
			phys_addr = addr;
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
								it->get()->guest_flags == flags) {
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

template void tc_invalidate<true, true>(cpu_ctx_t * cpu_ctx, addr_t addr, [[maybe_unused]] uint8_t size, [[maybe_unused]] uint32_t eip);
template void tc_invalidate<true, false>(cpu_ctx_t *cpu_ctx, addr_t addr, [[maybe_unused]] uint8_t size, [[maybe_unused]] uint32_t eip);
template void tc_invalidate<false, true>(cpu_ctx_t * cpu_ctx, addr_t addr, [[maybe_unused]] uint8_t size, [[maybe_unused]] uint32_t eip);
template void tc_invalidate<false, false>(cpu_ctx_t *cpu_ctx, addr_t addr, [[maybe_unused]] uint8_t size, [[maybe_unused]] uint32_t eip);

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
			tc->guest_flags == flags) {
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

template<bool should_flush_tlb>
void tc_should_clear_cache_and_tlb(cpu_t *cpu, addr_t start, addr_t end)
{
	for (uint32_t tlb_idx_s = start >> PAGE_SHIFT, tlb_idx_e = end >> PAGE_SHIFT; tlb_idx_s <= tlb_idx_e; ++tlb_idx_s) {
		if (cpu->cpu_ctx.tlb[tlb_idx_s] & TLB_CODE) {
			tc_cache_clear(cpu);
			break;
		}
	}

	if constexpr (should_flush_tlb) {
		tlb_flush(cpu, TLB_zero);
		cpu->cached_regions.clear();
		cpu->cached_regions.push_back(nullptr);
	}
}

void
tc_cache_clear(cpu_t *cpu)
{
	// Use this when you want to destroy all tc's but without affecting the actual code allocated. E.g: on x86-64, you'll want to keep the .pdata sections
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
	// This is like tc_cache_clear, but it also frees all code allocated. E.g: on x86-64, the jit also emits .pdata sections that hold the exception tables
	// necessary to unwind the stack of the JITed functions
	tc_cache_clear(cpu);
	cpu->jit->destroy_all_code();
	cpu->jit->gen_int_fn();
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

entry_t
link_indirect_handler(cpu_ctx_t *cpu_ctx, translated_code_t *tc)
{
	const auto it = cpu_ctx->cpu->ibtc.find(get_pc(cpu_ctx));

	if (it != cpu_ctx->cpu->ibtc.end()) {
		if (it->second->cs_base == cpu_ctx->regs.cs_hidden.base &&
			it->second->guest_flags == ((cpu_ctx->hflags & HFLG_CONST) | (cpu_ctx->regs.eflags & EFLAGS_CONST)) &&
			((it->second->virt_pc & ~PAGE_MASK) == (tc->virt_pc & ~PAGE_MASK))) {
			return it->second->ptr_code;
		}
	}

	return tc->jmp_offset[2];
}

static void
cpu_translate(cpu_t *cpu, disas_ctx_t *disas_ctx)
{
	cpu->translate_next = 1;
	cpu->virt_pc = disas_ctx->virt_pc;

	ZydisDecodedInstruction instr;
	ZydisDecoder decoder;
	ZyanStatus status;

	init_instr_decoder(disas_ctx, &decoder);

	do {
		cpu->instr_eip = cpu->virt_pc - cpu->cpu_ctx.regs.cs_hidden.base;

		try {
			status = decode_instr(cpu, disas_ctx, &decoder, &instr);
		}
		catch (host_exp_t type) {
			// this happens on instr breakpoints (not int3)
			assert(type == host_exp_t::de_exp);
			cpu->jit->gen_raise_exp_inline(0, 0, EXP_DB, cpu->instr_eip);
			disas_ctx->flags |= DISAS_FLG_DBG_FAULT;
			return;
		}

		if (ZYAN_SUCCESS(status)) {
			// successfully decoded

			cpu->instr_bytes = instr.length;
			disas_ctx->flags |= ((disas_ctx->virt_pc & ~PAGE_MASK) != ((disas_ctx->virt_pc + cpu->instr_bytes - 1) & ~PAGE_MASK)) << 2;
			disas_ctx->pc += cpu->instr_bytes;
			disas_ctx->virt_pc += cpu->instr_bytes;

			// att syntax uses percentage symbols to designate the operands, which will cause an error/crash if we (or the client)
			// attempts to interpret them as conversion specifiers, so we pass the formatted instruction as an argument
			LOG(log_level::debug, "0x%08X  %s", disas_ctx->virt_pc - cpu->instr_bytes, instr_logfn(disas_ctx->virt_pc - cpu->instr_bytes, &instr).c_str());
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
				cpu->jit->gen_raise_exp_inline(0, 0, EXP_UD, cpu->instr_eip);
				return;

			case ZYDIS_STATUS_NO_MORE_DATA:
				// buffer < 15 bytes
				cpu->cpu_flags &= ~(CPU_DISAS_ONE | CPU_ALLOW_CODE_WRITE);
				if (disas_ctx->exp_data.idx == EXP_PF) {
					// buffer size reduced because of page fault on second page
					disas_ctx->flags |= DISAS_FLG_FETCH_FAULT;
					cpu->jit->gen_raise_exp_inline(disas_ctx->exp_data.fault_addr, disas_ctx->exp_data.code, disas_ctx->exp_data.idx, disas_ctx->exp_data.eip);
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
					cpu->jit->gen_raise_exp_inline(disas_ctx->exp_data.fault_addr, disas_ctx->exp_data.code, disas_ctx->exp_data.idx, disas_ctx->exp_data.eip);
				}
				else {
					cpu->jit->gen_raise_exp_inline(0, 0, EXP_GP, disas_ctx->virt_pc - cpu->cpu_ctx.regs.cs_hidden.base);
				}
				return;
			}

			default:
				LIB86CPU_ABORT_msg("Unhandled zydis decode return status");
			}
		}


		if ((disas_ctx->flags & DISAS_FLG_CS32) ^ ((instr.attributes & ZYDIS_ATTRIB_HAS_OPERANDSIZE) >> 34)) {
			cpu->size_mode = SIZE32;
		}
		else {
			cpu->size_mode = SIZE16;
		}

		if ((disas_ctx->flags & DISAS_FLG_CS32) ^ ((instr.attributes & ZYDIS_ATTRIB_HAS_ADDRESSSIZE) >> 35)) {
			cpu->addr_mode = ADDR32;
		}
		else {
			cpu->addr_mode = ADDR16;
		}

		switch (instr.mnemonic)
		{
		case ZYDIS_MNEMONIC_AAA:
			cpu->jit->aaa(&instr);
			break;

		case ZYDIS_MNEMONIC_AAD:
			cpu->jit->aad(&instr);
			break;

		case ZYDIS_MNEMONIC_AAM:
			cpu->jit->aam(&instr);
			break;

		case ZYDIS_MNEMONIC_AAS:
			cpu->jit->aas(&instr);
			break;

		case ZYDIS_MNEMONIC_ADC:
			cpu->jit->adc(&instr);
			break;

		case ZYDIS_MNEMONIC_ADD:
			cpu->jit->add(&instr);
			break;

		case ZYDIS_MNEMONIC_AND:
			cpu->jit->and_(&instr);
			break;

		case ZYDIS_MNEMONIC_ARPL:
			cpu->jit->arpl(&instr);
			break;

		case ZYDIS_MNEMONIC_BOUND:
			cpu->jit->bound(&instr);
			break;

		case ZYDIS_MNEMONIC_BSF:
			cpu->jit->bsf(&instr);
			break;

		case ZYDIS_MNEMONIC_BSR:
			cpu->jit->bsr(&instr);
			break;

		case ZYDIS_MNEMONIC_BSWAP:
			cpu->jit->bswap(&instr);
			break;

		case ZYDIS_MNEMONIC_BT:
			cpu->jit->bt(&instr);
			break;

		case ZYDIS_MNEMONIC_BTC:
			cpu->jit->btc(&instr);
			break;

		case ZYDIS_MNEMONIC_BTR:
			cpu->jit->btr(&instr);
			break;

		case ZYDIS_MNEMONIC_BTS:
			cpu->jit->bts(&instr);
			break;

		case ZYDIS_MNEMONIC_CALL:
			cpu->jit->call(&instr);
			break;

		case ZYDIS_MNEMONIC_CBW:
			cpu->jit->cbw(&instr);
			break;

		case ZYDIS_MNEMONIC_CDQ:
			cpu->jit->cdq(&instr);
			break;

		case ZYDIS_MNEMONIC_CLC:
			cpu->jit->clc(&instr);
			break;

		case ZYDIS_MNEMONIC_CLD:
			cpu->jit->cld(&instr);
			break;

		case ZYDIS_MNEMONIC_CLI:
			cpu->jit->cli(&instr);
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
		case ZYDIS_MNEMONIC_CMOVZ:
			cpu->jit->cmovcc(&instr);
			break;

		case ZYDIS_MNEMONIC_CMP:
			cpu->jit->cmp(&instr);
			break;

		case ZYDIS_MNEMONIC_CMPSB:
		case ZYDIS_MNEMONIC_CMPSW:
		case ZYDIS_MNEMONIC_CMPSD:
			cpu->jit->cmps(&instr);
			break;

		case ZYDIS_MNEMONIC_CMPXCHG8B:   BAD;
		case ZYDIS_MNEMONIC_CMPXCHG:     BAD;
		case ZYDIS_MNEMONIC_CPUID:
			cpu->jit->cpuid(&instr);
			break;

		case ZYDIS_MNEMONIC_CWD:
			cpu->jit->cwd(&instr);
			break;

		case ZYDIS_MNEMONIC_CWDE:
			cpu->jit->cwde(&instr);
			break;

		case ZYDIS_MNEMONIC_DAA:
			cpu->jit->daa(&instr);
			break;

		case ZYDIS_MNEMONIC_DAS:
			cpu->jit->das(&instr);
			break;

		case ZYDIS_MNEMONIC_DEC:
			cpu->jit->dec(&instr);
			break;

		case ZYDIS_MNEMONIC_DIV:
			cpu->jit->div(&instr);
			break;

		case ZYDIS_MNEMONIC_ENTER: BAD;
		case ZYDIS_MNEMONIC_HLT:
			cpu->jit->hlt(&instr);
			break;

		case ZYDIS_MNEMONIC_IDIV:
			cpu->jit->idiv(&instr);
			break;

		case ZYDIS_MNEMONIC_IMUL:
			cpu->jit->imul(&instr);
			break;

		case ZYDIS_MNEMONIC_IN:
			cpu->jit->in(&instr);
			break;

		case ZYDIS_MNEMONIC_INC:
			cpu->jit->inc(&instr);
			break;

		case ZYDIS_MNEMONIC_INSB:
		case ZYDIS_MNEMONIC_INSD:
		case ZYDIS_MNEMONIC_INSW:
			cpu->jit->ins(&instr);
			break;

		case ZYDIS_MNEMONIC_INT3:
			cpu->jit->int3(&instr);
			break;

		case ZYDIS_MNEMONIC_INT:
			cpu->jit->intn(&instr);
			break;

		case ZYDIS_MNEMONIC_INTO:        BAD;
		case ZYDIS_MNEMONIC_INVD:        BAD;
		case ZYDIS_MNEMONIC_INVLPG:      BAD;
		case ZYDIS_MNEMONIC_IRET:
		case ZYDIS_MNEMONIC_IRETD:
			cpu->jit->iret(&instr);
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
		case ZYDIS_MNEMONIC_JNLE:
			cpu->jit->jcc(&instr);
			break;

		case ZYDIS_MNEMONIC_JMP:
			cpu->jit->jmp(&instr);
			break;

		case ZYDIS_MNEMONIC_LAHF:
			cpu->jit->lahf(&instr);
			break;

		case ZYDIS_MNEMONIC_LAR:         BAD;
		case ZYDIS_MNEMONIC_LEA:
			cpu->jit->lea(&instr);
			break;

		case ZYDIS_MNEMONIC_LEAVE:
			cpu->jit->leave(&instr);
			break;

		case ZYDIS_MNEMONIC_LGDT:
			cpu->jit->lgdt(&instr);
			break;

		case ZYDIS_MNEMONIC_LIDT:
			cpu->jit->lidt(&instr);
			break;

		case ZYDIS_MNEMONIC_LLDT:
			cpu->jit->lldt(&instr);
			break;

		case ZYDIS_MNEMONIC_LMSW:        BAD;
		case ZYDIS_MNEMONIC_LODSB:
		case ZYDIS_MNEMONIC_LODSD:
		case ZYDIS_MNEMONIC_LODSW:
			cpu->jit->lods(&instr);
			break;

		case ZYDIS_MNEMONIC_LOOP:
		case ZYDIS_MNEMONIC_LOOPE:
		case ZYDIS_MNEMONIC_LOOPNE:
			cpu->jit->loop(&instr);
			break;

		case ZYDIS_MNEMONIC_LSL:         BAD;
		case ZYDIS_MNEMONIC_LDS:
			cpu->jit->lds(&instr);
			break;

		case ZYDIS_MNEMONIC_LES:
			cpu->jit->les(&instr);
			break;

		case ZYDIS_MNEMONIC_LFS:
			cpu->jit->lfs(&instr);
			break;

		case ZYDIS_MNEMONIC_LGS:
			cpu->jit->lgs(&instr);
			break;

		case ZYDIS_MNEMONIC_LSS:
			cpu->jit->lss(&instr);
			break;

		case ZYDIS_MNEMONIC_LTR:
			cpu->jit->ltr(&instr);
			break;

		case ZYDIS_MNEMONIC_MOV:
			cpu->jit->mov(&instr);
			break;

		case ZYDIS_MNEMONIC_MOVD:BAD;
		case ZYDIS_MNEMONIC_MOVSB:
		case ZYDIS_MNEMONIC_MOVSD:
		case ZYDIS_MNEMONIC_MOVSW:
			cpu->jit->movs(&instr);
			break;

		case ZYDIS_MNEMONIC_MOVSX:
			cpu->jit->movsx(&instr);
			break;

		case ZYDIS_MNEMONIC_MOVZX:
			cpu->jit->movzx(&instr);
			break;

		case ZYDIS_MNEMONIC_MUL:
			cpu->jit->mul(&instr);
			break;

		case ZYDIS_MNEMONIC_NEG:
			cpu->jit->neg(&instr);
			break;

		case ZYDIS_MNEMONIC_NOP:
			// nothing to do
			break;

		case ZYDIS_MNEMONIC_NOT:
			cpu->jit->not_(&instr);
			break;

		case ZYDIS_MNEMONIC_OR:
			cpu->jit->or_(&instr);
			break;

		case ZYDIS_MNEMONIC_OUT:
			cpu->jit->out(&instr);
			break;

		case ZYDIS_MNEMONIC_OUTSB:BAD;
		case ZYDIS_MNEMONIC_OUTSD:BAD;
		case ZYDIS_MNEMONIC_OUTSW:BAD;
		case ZYDIS_MNEMONIC_POP:
			cpu->jit->pop(&instr);
			break;

		case ZYDIS_MNEMONIC_POPA:
		case ZYDIS_MNEMONIC_POPAD:
			cpu->jit->popa(&instr);
			break;

		case ZYDIS_MNEMONIC_POPF:
		case ZYDIS_MNEMONIC_POPFD:
			cpu->jit->popf(&instr);
			break;

		case ZYDIS_MNEMONIC_PUSH:
			cpu->jit->push(&instr);
			break;

		case ZYDIS_MNEMONIC_PUSHA:
		case ZYDIS_MNEMONIC_PUSHAD:
			cpu->jit->pusha(&instr);
			break;

		case ZYDIS_MNEMONIC_PUSHF:
		case ZYDIS_MNEMONIC_PUSHFD:
			cpu->jit->pushf(&instr);
			break;

		case ZYDIS_MNEMONIC_RCL:
			cpu->jit->rcl(&instr);
			break;

		case ZYDIS_MNEMONIC_RCR:
			cpu->jit->rcr(&instr);
			break;

		case ZYDIS_MNEMONIC_RDMSR:
			cpu->jit->rdmsr(&instr);
			break;

		case ZYDIS_MNEMONIC_RDPMC:       BAD;
		case ZYDIS_MNEMONIC_RDTSC:
			cpu->jit->rdtsc(&instr);
			break;

		case ZYDIS_MNEMONIC_RET:
			cpu->jit->ret(&instr);
			break;

		case ZYDIS_MNEMONIC_ROL:
			cpu->jit->rol(&instr);
			break;

		case ZYDIS_MNEMONIC_ROR:
			cpu->jit->ror(&instr);
			break;

		case ZYDIS_MNEMONIC_RSM:         BAD;
		case ZYDIS_MNEMONIC_SAHF:
			cpu->jit->sahf(&instr);
			break;

		case ZYDIS_MNEMONIC_SAR:
			cpu->jit->sar(&instr);
			break;

		case ZYDIS_MNEMONIC_SBB:
			cpu->jit->sbb(&instr);
			break;

		case ZYDIS_MNEMONIC_SCASB:
		case ZYDIS_MNEMONIC_SCASD:
		case ZYDIS_MNEMONIC_SCASW:
			cpu->jit->scas(&instr);
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
		case ZYDIS_MNEMONIC_SETZ:
			cpu->jit->setcc(&instr);
			break;

		case ZYDIS_MNEMONIC_SGDT:        BAD;
		case ZYDIS_MNEMONIC_SHL:
			cpu->jit->shl(&instr);
			break;

		case ZYDIS_MNEMONIC_SHLD:
			cpu->jit->shld(&instr);
			break;

		case ZYDIS_MNEMONIC_SHR:
			cpu->jit->shr(&instr);
			break;

		case ZYDIS_MNEMONIC_SHRD:
			cpu->jit->shrd(&instr);
			break;

		case ZYDIS_MNEMONIC_SIDT:        BAD;
		case ZYDIS_MNEMONIC_SLDT:        BAD;
		case ZYDIS_MNEMONIC_SMSW:        BAD;
		case ZYDIS_MNEMONIC_STC:
			cpu->jit->stc(&instr);
			break;

		case ZYDIS_MNEMONIC_STD:
			cpu->jit->std(&instr);
			break;

		case ZYDIS_MNEMONIC_STI:
			cpu->jit->sti(&instr);
			break;

		case ZYDIS_MNEMONIC_STOSB:
		case ZYDIS_MNEMONIC_STOSD:
		case ZYDIS_MNEMONIC_STOSW:
			cpu->jit->stos(&instr);
			break;

		case ZYDIS_MNEMONIC_STR:         BAD;
		case ZYDIS_MNEMONIC_SUB:
			cpu->jit->sub(&instr);
			break;

		case ZYDIS_MNEMONIC_SYSENTER:    BAD;
		case ZYDIS_MNEMONIC_SYSEXIT:     BAD;
		case ZYDIS_MNEMONIC_TEST:
			cpu->jit->test(&instr);
			break;

		case ZYDIS_MNEMONIC_UD1:         BAD;
		case ZYDIS_MNEMONIC_UD2:         BAD;
		case ZYDIS_MNEMONIC_VERR:
			cpu->jit->verr(&instr);
			break;

		case ZYDIS_MNEMONIC_VERW:
			cpu->jit->verw(&instr);
			break;

		case ZYDIS_MNEMONIC_WBINVD:
			cpu->jit->wbinvd(&instr);
			break;

		case ZYDIS_MNEMONIC_WRMSR:
			cpu->jit->wrmsr(&instr);
			break;

		case ZYDIS_MNEMONIC_XADD:        BAD;
		case ZYDIS_MNEMONIC_XCHG:
			cpu->jit->xchg(&instr);
			break;

		case ZYDIS_MNEMONIC_XLAT:        BAD;
		case ZYDIS_MNEMONIC_XOR:
			cpu->jit->xor_(&instr);
			break;

		default:
			LIB86CPU_ABORT();
		}

		cpu->virt_pc += cpu->instr_bytes;
		cpu->tc->size += cpu->instr_bytes;

	} while ((cpu->translate_next | (disas_ctx->flags & (DISAS_FLG_PAGE_CROSS | DISAS_FLG_ONE_INSTR))) == 1);
}

uint32_t
cpu_do_int(cpu_ctx_t *cpu_ctx, uint32_t int_flg)
{
	cpu_ctx->cpu->clear_int_fn(cpu_ctx);

	if (int_flg & CPU_ABORT_INT) {
		// this also happens when the user closes the debugger window
		throw lc86_exp_abort("Received abort signal, terminating the emulation", lc86_status::success);
	}

	if (int_flg & (CPU_A20_INT | CPU_REGION_INT)) {
		cpu_t *cpu = cpu_ctx->cpu;
		if (int_flg & CPU_A20_INT) {
			cpu->a20_mask = cpu->new_a20;
			tlb_flush(cpu, TLB_zero);
			cpu->cached_regions.clear();
			cpu->cached_regions.push_back(nullptr);
			tc_cache_clear(cpu);
			if (int_flg & CPU_REGION_INT) {
				// the a20 interrupt has already flushed the tlb and the code cache, so just update the as object
				std::for_each(cpu->regions_changed.begin(), cpu->regions_changed.end(), [cpu](auto &pair) {
					if (pair.first) {
						if (pair.second->type == mem_type::ram) {
							if (auto ram = as_memory_search_addr(cpu, cpu->ram_start); ram->type == mem_type::ram) {
								cpu->memory_space_tree->erase(ram->start, ram->end);
							}
							cpu->ram_start = pair.second->start;
						}
						cpu->memory_space_tree->insert(std::move(pair.second));
					}
					else {
						cpu->memory_space_tree->erase(pair.second->start, pair.second->end);
					}
					});
				cpu->regions_changed.clear();
			}
		}
		else {
			std::for_each(cpu->regions_changed.begin(), cpu->regions_changed.end(), [cpu](auto &pair) {
				addr_t start = pair.second->start, end = pair.second->end;
				if (pair.first) {
					if (pair.second->type == mem_type::ram) {
						if (auto ram = as_memory_search_addr(cpu, cpu->ram_start); ram->type == mem_type::ram) {
							cpu->memory_space_tree->erase(ram->start, ram->end);
						}
						cpu->ram_start = pair.second->start;
					}
					cpu->memory_space_tree->insert(std::move(pair.second));
				}
				else {
					cpu->memory_space_tree->erase(start, end);
				}
				// avoid flushing the tlb and subpages for every region, but instead only do it once outside the loop
				tc_should_clear_cache_and_tlb<false>(cpu, start, end);
			});
			tlb_flush(cpu, TLB_zero);
			cpu->cached_regions.clear();
			cpu->cached_regions.push_back(nullptr);
			cpu->regions_changed.clear();
		}
	}

	if (((int_flg & CPU_HW_INT) | (cpu_ctx->regs.eflags & IF_MASK)) == (IF_MASK | CPU_HW_INT)) {
		cpu_ctx->exp_info.exp_data.fault_addr = 0;
		cpu_ctx->exp_info.exp_data.code = 0;
		cpu_ctx->exp_info.exp_data.idx = cpu_ctx->cpu->get_int_vec();
		cpu_ctx->exp_info.exp_data.eip = cpu_ctx->regs.eip;
		cpu_raise_exception<false, true>(cpu_ctx);
		return 1;
	}

	return 0;
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
			std::unique_ptr<translated_code_t> tc(new translated_code_t);

			cpu->tc = tc.get();
			cpu->jit->gen_tc_prologue();

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

			if constexpr (is_trap) {
				// don't take hooks if we are executing a trapped instr. Otherwise, if the trapped instr is also hooked, we will take the hook instead of executing it
				cpu_translate(cpu, &disas_ctx);
			}
			else {
				const auto it = cpu->hook_map.find(disas_ctx.virt_pc);
				bool take_hook;
				if constexpr (is_tramp) {
					take_hook = (it != cpu->hook_map.end()) && !(cpu->cpu_ctx.hflags & HFLG_TRAMP);
				}
				else {
					take_hook = it != cpu->hook_map.end();
				}

				if (take_hook) {
					cpu->instr_eip = disas_ctx.virt_pc - cpu->cpu_ctx.regs.cs_hidden.base;
					cpu->jit->gen_hook(it->second);
				}
				else {
					// start guest code translation
					cpu_translate(cpu, &disas_ctx);
				}
			}

			cpu->jit->gen_tc_epilogue();

			cpu->tc->pc = pc;
			cpu->tc->virt_pc = virt_pc;
			cpu->tc->cs_base = cpu->cpu_ctx.regs.cs_hidden.base;
			cpu->tc->guest_flags = (cpu->cpu_ctx.hflags & HFLG_CONST) | (cpu->cpu_ctx.regs.eflags & EFLAGS_CONST);
			cpu->jit->gen_code_block();

			// we are done with code generation for this block, so we null the tc and bb pointers to prevent accidental usage
			ptr_tc = cpu->tc;
			cpu->tc = nullptr;

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
			return nullptr;
		}

		case host_exp_t::cpu_mode_changed:
			tc_cache_purge(cpu_ctx->cpu);
			[[fallthrough]];

		case host_exp_t::halt_tc:
			return nullptr;

		default:
			LIB86CPU_ABORT_msg("Unknown host exception in %s", __func__);
		}
	}
}

template<bool run_forever>
lc86_status cpu_start(cpu_t *cpu)
{
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
		if constexpr (run_forever) {
			cpu_main_loop<false, false>(cpu, []() { return true; });
		}
		else {
			cpu->cpu_ctx.hflags |= HFLG_TIMEOUT;
			cpu_timer_set_now(cpu);
			cpu->cpu_ctx.exit_requested = 0;
			if (cpu->cpu_ctx.is_halted) {
				// if the cpu was previously halted, then we must keep waiting until the next hw int
				cpu->jit->halt_loop();
				if (cpu->cpu_ctx.is_halted) {
					// if it is still halted, then it must be a timeout
					cpu->cpu_ctx.hflags &= ~HFLG_TIMEOUT;
					return lc86_status::timeout;
				}
			}
			cpu_main_loop<false, false>(cpu, [cpu]() { return !cpu->cpu_ctx.exit_requested; });
			cpu->cpu_ctx.hflags &= ~HFLG_TIMEOUT;
			return lc86_status::timeout;
		}
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

template translated_code_t *cpu_raise_exception<true, true>(cpu_ctx_t *cpu_ctx);
template translated_code_t *cpu_raise_exception<true, false>(cpu_ctx_t *cpu_ctx);
template translated_code_t *cpu_raise_exception<false, true>(cpu_ctx_t *cpu_ctx);
template translated_code_t *cpu_raise_exception<false, false>(cpu_ctx_t *cpu_ctx);
template void tc_should_clear_cache_and_tlb<true>(cpu_t *cpu, addr_t start, addr_t end);
template lc86_status cpu_start<true>(cpu_t *cpu);
template lc86_status cpu_start<false>(cpu_t *cpu);
