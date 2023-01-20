/*
 * memory support
 *
 * ergo720                Copyright (c) 2019
 */

#include "internal.h"
#include "memory.h"
#include <assert.h>


static uint32_t
tlb_gen_access_mask(cpu_t *cpu, uint8_t user, uint8_t is_write)
{
	uint32_t mask;

	switch (user)
	{
	case 0:
		mask = is_write ? (TLB_SUP_READ | TLB_SUP_WRITE) : (cpu->cpu_ctx.regs.cr0 & CR0_WP_MASK) != 0 ?
			TLB_SUP_READ : (TLB_SUP_READ | TLB_SUP_WRITE);
		break;

	case 4:
		mask = is_write ? (TLB_SUP_READ | TLB_SUP_WRITE | TLB_USER_READ | TLB_USER_WRITE) :
			(cpu->cpu_ctx.regs.cr0 & CR0_WP_MASK) != 0 ? (TLB_SUP_READ | TLB_USER_READ) : (TLB_SUP_READ | TLB_SUP_WRITE | TLB_USER_READ);
		break;

	default:
		LIB86CPU_ABORT();
	}

	return mask;
}

static addr_t
correct_phys_addr(cpu_t *cpu, addr_t phys_addr, const memory_region_t<addr_t> *&region)
{
	// this function applies two corrections to the physical address:
	// 1. if region is alias, it resolves it and calculates the final addr the aliased addr is pointing to
	// 2. it masks the address with the current state of the a20 gate

	if (region->type == mem_type::alias) {
		uint32_t offset = 0;
		while (region->aliased_region) {
			offset += (region->start - (region->alias_offset + region->aliased_region->start));
			region = region->aliased_region;
		}
		phys_addr -= offset;
	}

	return phys_addr & cpu->a20_mask;
}

template<bool is_fetch>
static addr_t tlb_fill(cpu_t *cpu, addr_t addr, addr_t phys_addr, uint32_t prot)
{
	assert((prot & ~PAGE_MASK) == 0);

	// if the tlb set is full, then the replacement policy used is "random replacement"

	uint64_t tag;
	tlb_t *tlb = nullptr;
	if constexpr (is_fetch) {
		uint32_t idx = (addr >> PAGE_SHIFT) & ITLB_IDX_MASK;
		tag = (static_cast<uint64_t>(addr) << ITLB_TAG_SHIFT64) & ITLB_TAG_MASK64;
		for (unsigned i = 0; i < ITLB_NUM_LINES; ++i) {
			if (!(cpu->itlb[idx][i].entry & TLB_VALID)) {
				tlb = &cpu->itlb[idx][i];
				break;
			}
		}
		if (!tlb) {
			std::uniform_int_distribution<uint32_t> dis(0, ITLB_NUM_LINES - 1);
			tlb = &cpu->itlb[idx][dis(cpu->rng_gen)];
		}
	}
	else {
		uint32_t idx = (addr >> PAGE_SHIFT) & DTLB_IDX_MASK;
		tag = (static_cast<uint64_t>(addr) << DTLB_TAG_SHIFT64) & DTLB_TAG_MASK64;
		for (unsigned i = 0; i < DTLB_NUM_LINES; ++i) {
			if (!(cpu->dtlb[idx][i].entry & TLB_VALID)) {
				tlb = &cpu->dtlb[idx][i];
				break;
			}
		}
		if (!tlb) {
			std::uniform_int_distribution<uint32_t> dis(0, DTLB_NUM_LINES - 1);
			tlb = &cpu->dtlb[idx][dis(cpu->rng_gen)];
		}
	}

	const memory_region_t<addr_t> *region = as_memory_search_addr(cpu, phys_addr);
	addr_t start_page = phys_addr & ~PAGE_MASK;
	addr_t end_page = ((static_cast<uint64_t>(phys_addr) + PAGE_SIZE) & ~PAGE_MASK) - 1; // the cast avoids overflow on the last page at 0xFFFFF000
	phys_addr = correct_phys_addr(cpu, phys_addr, region);

	if (prot & MMU_SET_CODE) {
		prot &= ~MMU_SET_CODE;
		cpu->smc.set(phys_addr >> PAGE_SHIFT);
	}

	if ((region->start <= start_page) && (region->end >= end_page)) {
		// region spans the entire page

		if (region->type == mem_type::ram) {
			tlb->entry = tag | (phys_addr & ~PAGE_MASK) | (prot | TLB_RAM);
			tlb->region = const_cast<memory_region_t<addr_t> *>(region);
		}
		else if (region->type == mem_type::unmapped) {
			tlb->entry = tag | (phys_addr & ~PAGE_MASK) | prot;
		}
		else {
			if (region->type == mem_type::mmio) {
				prot |= TLB_MMIO;
			}
			else {
				cpu->smc.reset(phys_addr >> PAGE_SHIFT);
				prot |= TLB_ROM;
			}
			tlb->entry = tag | (phys_addr & ~PAGE_MASK) | prot;
			tlb->region = const_cast<memory_region_t<addr_t> *>(region);
		}
	}
	else {
		// region doesn't cover the entire page

		tlb->entry = tag | (phys_addr & ~PAGE_MASK) | (prot | TLB_SUBPAGE);
	}

	return phys_addr;
}

template<bool flush_global>
void tlb_flush(cpu_t *cpu)
{
	if constexpr (flush_global) {
		std::memset(cpu->itlb, 0, sizeof(cpu->itlb));
		std::memset(cpu->dtlb, 0, sizeof(cpu->dtlb));
	}
	else {
		for (auto &set : cpu->itlb) {
			for (auto &line : set) {
				if (!(line.entry & TLB_GLOBAL)) {
					line.entry = 0;
					line.region = nullptr;
				}
			}
		}
		for (auto &set : cpu->dtlb) {
			for (auto &line : set) {
				if (!(line.entry & TLB_GLOBAL)) {
					line.entry = 0;
					line.region = nullptr;
				}
			}
		}
	}
}

int8_t
check_page_access(cpu_t *cpu, uint8_t access_level, uint8_t mem_access)
{
	// 0 = access denied, 1 = access granted, -1 = error

	// two rows because when wp flag of cr0 is 1, then supervisor cannot write to supervisor read only pages
	static constexpr int8_t level_zero[2][7] = { // s/r page
		{ 1, -1, 1, -1, 0, -1, 0 },
		{ 1, -1, 0, -1, 0, -1, 0 },
	};

	static constexpr int8_t level_two[7] = { // s/w page
		1, -1, 1, -1, 0, -1, 0,
	};

	// two rows because when wp flag of cr0 is 1, then supervisor cannot write to user read only pages
	static constexpr int8_t level_four[2][7] = { // u/r page
		{ 1, -1, 1, -1, 1, -1, 0 },
		{ 1, -1, 0, -1, 1, -1, 0 },
	};

	static constexpr int8_t level_six[7] = { // u/w page
		1, -1, 1, -1, 1, -1, 1,
	};

	int8_t access;

	switch (access_level)
	{
	case 0:
		access = level_zero[(cpu->cpu_ctx.regs.cr0 & CR0_WP_MASK) >> 16][mem_access];
		break;

	case 2:
		access = level_two[mem_access];
		break;

	case 4:
		access = level_four[(cpu->cpu_ctx.regs.cr0 & CR0_WP_MASK) >> 16][mem_access];
		break;

	case 6:
		access = level_six[mem_access];
		break;

	default:
		LIB86CPU_ABORT_msg("Invalid access_level \"%c\" used in %s", access_level, __func__);
	}

	assert(access != -1);

	return access;
}

int8_t
check_page_privilege(cpu_t *cpu, uint8_t pde_priv, uint8_t pte_priv)
{
	// 0 = sup,ro; 2 = sup,r/w; 4 = user,ro; 6 = user,r/w; -1 = error
	static constexpr int8_t access_table[7][7] = {
		{ 0, -1, 2, -1, 0, -1, 2 },
		{ -1, -1, -1, -1, -1, -1, -1 },
		{ 2, -1, 2, -1, 2, -1, 2 },
		{ -1, -1, -1, -1, -1, -1, -1 },
		{ 0, -1, 2, -1, 4, -1, 4 },
		{ -1, -1, -1, -1, -1, -1, -1 },
		{ 2, -1, 2, -1, 4, -1, 6 },
	};

	int8_t access_lv = access_table[pde_priv][pte_priv];
	assert(access_lv != -1);

	return access_lv;
}

template<bool raise_host_exp>
static inline void
mmu_raise_page_fault(cpu_t *cpu, addr_t addr, uint32_t eip, disas_ctx_t *disas_ctx, uint8_t err_code, uint8_t is_write, uint8_t cpu_lv)
{
	// NOTE: the u/s bit of the error code should reflect the actual cpl even if the memory access is privileged
	if constexpr (raise_host_exp) {
		assert(disas_ctx == nullptr);
		cpu->cpu_ctx.exp_info.exp_data.fault_addr = addr;
		cpu->cpu_ctx.exp_info.exp_data.code = err_code | (is_write << 1) | cpu_lv;
		cpu->cpu_ctx.exp_info.exp_data.idx = EXP_PF;
		cpu->cpu_ctx.exp_info.exp_data.eip = eip;
		throw host_exp_t::pf_exp;
	}
	else {
		assert(disas_ctx != nullptr);
		disas_ctx->exp_data.fault_addr = addr;
		disas_ctx->exp_data.code = err_code | (is_write << 1) | cpu_lv;
		disas_ctx->exp_data.idx = EXP_PF;
		disas_ctx->exp_data.eip = eip;
	}
}

// NOTE: flags: bit 0 -> is_write, bit 1 -> is_priv, bit 4 -> set_code
template<bool is_fetch, bool should_fill_tlb = true, bool raise_host_exp = true>
addr_t mmu_translate_addr(cpu_t *cpu, addr_t addr, uint32_t flags, uint32_t eip, disas_ctx_t *disas_ctx = nullptr)
{
	uint32_t is_write = flags & MMU_IS_WRITE;
	uint32_t set_code = flags & MMU_SET_CODE;

	if (!(cpu->cpu_ctx.regs.cr0 & CR0_PG_MASK)) {
		if constexpr (should_fill_tlb) {
			return tlb_fill<is_fetch>(cpu, addr, addr, TLB_SUP_READ | TLB_SUP_WRITE | TLB_USER_READ | TLB_USER_WRITE | (is_write << 9) | set_code);
		}
		else {
			const memory_region_t<addr_t> *region = as_memory_search_addr(cpu, addr);
			return correct_phys_addr(cpu, addr, region);
		}
	}
	else {
		uint8_t is_priv = flags & MMU_IS_PRIV;
		uint8_t err_code = 0;
		uint8_t cpu_lv = (cpu->cpu_ctx.hflags & HFLG_CPL) != 3 ? 0 : 4;
		addr_t pde_addr = (cpu->cpu_ctx.regs.cr3 & CR3_PD_MASK) | (addr >> PAGE_SHIFT_LARGE) * 4;
		const memory_region_t<addr_t> *pde_region = as_memory_search_addr(cpu, pde_addr);
		pde_addr = correct_phys_addr(cpu, pde_addr, pde_region);
		uint32_t pde = as_memory_dispatch_read<uint32_t>(cpu, pde_addr, pde_region);

		if (!(pde & PTE_PRESENT)) {
			mmu_raise_page_fault<raise_host_exp>(cpu, addr, eip, disas_ctx, err_code, is_write, cpu_lv);
			return 0;
		}
		
		uint8_t mem_access = (is_write << 1) | ((cpu_lv >> is_priv) & 4);
		uint8_t pde_priv = (pde & PTE_WRITE) | (pde & PTE_USER);
		if ((pde & PTE_LARGE) && (cpu->cpu_ctx.regs.cr4 & CR4_PSE_MASK)) {
			if (check_page_access(cpu, pde_priv, mem_access)) {
				if (!(pde & PTE_ACCESSED) || is_write) {
					pde |= PTE_ACCESSED;
					if (is_write) {
						pde |= PTE_DIRTY;
					}
					as_memory_dispatch_write<uint32_t>(cpu, pde_addr, pde, pde_region);
				}
				if constexpr (should_fill_tlb) {
					return tlb_fill<is_fetch>(cpu, addr, (pde & PTE_ADDR_4M) | (addr & PAGE_MASK_LARGE),
						tlb_gen_access_mask(cpu, pde_priv & PTE_USER, pde_priv & PTE_WRITE)
						| (is_write << 9) | set_code | ((pde & PTE_GLOBAL) & ((cpu->cpu_ctx.regs.cr4 & CR4_PGE_MASK) << 1)));
				}
				else {
					addr_t phys_addr = (pde & PTE_ADDR_4M) | (addr & PAGE_MASK_LARGE);
					const memory_region_t<addr_t> *region = as_memory_search_addr(cpu, phys_addr);
					return correct_phys_addr(cpu, phys_addr, region);
				}
			}
			err_code = 1;
			mmu_raise_page_fault<raise_host_exp>(cpu, addr, eip, disas_ctx, err_code, is_write, cpu_lv);
			return 0;
		}

		addr_t pte_addr = (pde & PTE_ADDR_4K) | ((addr >> PAGE_SHIFT) & 0x3FF) * 4;
		const memory_region_t<addr_t> *pte_region = as_memory_search_addr(cpu, pte_addr);
		pte_addr = correct_phys_addr(cpu, pte_addr, pte_region);
		uint32_t pte = as_memory_dispatch_read<uint32_t>(cpu, pte_addr, pte_region);

		if (!(pte & PTE_PRESENT)) {
			mmu_raise_page_fault<raise_host_exp>(cpu, addr, eip, disas_ctx, err_code, is_write, cpu_lv);
			return 0;
		}

		int8_t access_lv = check_page_privilege(cpu, pde_priv, (pte & PTE_WRITE) | (pte & PTE_USER));
		if (check_page_access(cpu, access_lv, mem_access)) {
			if (!(pde & PTE_ACCESSED)) {
				// NOTE: pdes that map page tables do not use the dirty bit. Also note that we must check this here because, if a pde is valid but the pte is not,
				// a page fault will occur and the accessed bit should not be set
				pde |= PTE_ACCESSED;
				as_memory_dispatch_write<uint32_t>(cpu, pde_addr, pde, pde_region);
			}
			if (!(pte & PTE_ACCESSED) || is_write) {
				pte |= PTE_ACCESSED;
				if (is_write) {
					pte |= PTE_DIRTY;
				}
				as_memory_dispatch_write<uint32_t>(cpu, pte_addr, pte, pte_region);
			}
			if constexpr (should_fill_tlb) {
				return tlb_fill<is_fetch>(cpu, addr, (pte & PTE_ADDR_4K) | (addr & PAGE_MASK),
					tlb_gen_access_mask(cpu, access_lv & PTE_USER, access_lv & PTE_WRITE)
					| (is_write << 9) | set_code | ((pte & PTE_GLOBAL) & ((cpu->cpu_ctx.regs.cr4 & CR4_PGE_MASK) << 1)));
			}
			else {
				addr_t phys_addr = (pte & PTE_ADDR_4K) | (addr & PAGE_MASK);
				const memory_region_t<addr_t> *region = as_memory_search_addr(cpu, phys_addr);
				return correct_phys_addr(cpu, phys_addr, region);
			}
		}
		err_code = 1;

		mmu_raise_page_fault<raise_host_exp>(cpu, addr, eip, disas_ctx, err_code, is_write, cpu_lv);
		return 0;
	}
}

// These functions below only get the address of a single byte and thus do not need to check for a page boundary crossing. They return a corrected
// physical address taking into account memory aliasing and region start offset
addr_t
get_read_addr(cpu_t *cpu, addr_t addr, uint8_t is_priv, uint32_t eip)
{
	uint32_t idx = (addr >> PAGE_SHIFT) & DTLB_IDX_MASK;
	uint64_t mem_access = tlb_access[0][(cpu->cpu_ctx.hflags & HFLG_CPL) >> is_priv];
	uint64_t tag = ((static_cast<uint64_t>(addr) << DTLB_TAG_SHIFT64) & DTLB_TAG_MASK64) | mem_access;
	mem_access |= DTLB_TAG_MASK64;
	for (unsigned i = 0; i < DTLB_NUM_LINES; ++i) {
		if (((cpu->dtlb[idx][i].entry & mem_access) ^ tag) == 0) {
			return (cpu->dtlb[idx][i].entry & ~PAGE_MASK) | (addr & PAGE_MASK);
		}
	}

	return mmu_translate_addr<false>(cpu, addr, is_priv, eip);
}

addr_t
get_write_addr(cpu_t *cpu, addr_t addr, uint8_t is_priv, uint32_t eip, bool *is_code)
{
	// this also needs to check for the dirty flag, to catch the case where the first access to the page is a read and then a write happens, so that
	// we give the mmu the chance to set the dirty flag in the pte

	uint32_t idx = (addr >> PAGE_SHIFT) & DTLB_IDX_MASK;
	uint64_t mem_access = tlb_access[1][(cpu->cpu_ctx.hflags & HFLG_CPL) >> is_priv];
	uint64_t tag = ((static_cast<uint64_t>(addr) << DTLB_TAG_SHIFT64) & DTLB_TAG_MASK64) | mem_access;
	mem_access |= DTLB_TAG_MASK64;
	for (unsigned i = 0; i < DTLB_NUM_LINES; ++i) {
		if (((cpu->dtlb[idx][i].entry & mem_access) ^ tag) == 0) {
			if (!(cpu->dtlb[idx][i].entry & TLB_DIRTY)) {
				cpu->dtlb[idx][i].entry |= TLB_DIRTY;
				mmu_translate_addr<false, false>(cpu, addr, MMU_IS_WRITE | is_priv, eip);
			}
			addr_t phys_addr = (cpu->dtlb[idx][i].entry & ~PAGE_MASK) | (addr & PAGE_MASK);
			*is_code = cpu->smc[phys_addr >> PAGE_SHIFT];
			return phys_addr;
		}
	}

	addr_t phys_addr = mmu_translate_addr<false>(cpu, addr, MMU_IS_WRITE | is_priv, eip);
	*is_code = cpu->smc[phys_addr >> PAGE_SHIFT];
	return phys_addr;
}

addr_t
get_code_addr(cpu_t *cpu, addr_t addr, uint32_t eip)
{
	// this is only used for ram fetching, so we don't need to check for privileged accesses

	uint32_t idx = (addr >> PAGE_SHIFT) & ITLB_IDX_MASK;
	uint64_t mem_access = tlb_access[0][cpu->cpu_ctx.hflags & HFLG_CPL];
	uint64_t tag = ((static_cast<uint64_t>(addr) << ITLB_TAG_SHIFT64) & ITLB_TAG_MASK64) | mem_access;
	mem_access |= ITLB_TAG_MASK64;
	for (unsigned i = 0; i < ITLB_NUM_LINES; ++i) {
		if (((cpu->itlb[idx][i].entry & mem_access) ^ tag) == 0) {
			return (cpu->itlb[idx][i].entry & ~PAGE_MASK) | (addr & PAGE_MASK);
		}
	}

	return mmu_translate_addr<true>(cpu, addr, MMU_SET_CODE, eip);
}

template<bool set_smc>
addr_t get_code_addr(cpu_t *cpu, addr_t addr, uint32_t eip, disas_ctx_t *disas_ctx)
{
	// overloaded get_code_addr that does not throw host exceptions, used in cpu_translate and by the debugger
	// NOTE: the debugger should not set the smc, since it doesn't execute the instructions

	uint32_t idx = (addr >> PAGE_SHIFT) & ITLB_IDX_MASK;
	uint64_t mem_access = tlb_access[0][cpu->cpu_ctx.hflags & HFLG_CPL];
	uint64_t tag = ((static_cast<uint64_t>(addr) << ITLB_TAG_SHIFT64) & ITLB_TAG_MASK64) | mem_access;
	mem_access |= ITLB_TAG_MASK64;
	for (unsigned i = 0; i < ITLB_NUM_LINES; ++i) {
		if (((cpu->itlb[idx][i].entry & mem_access) ^ tag) == 0) {
			return (cpu->itlb[idx][i].entry & ~PAGE_MASK) | (addr & PAGE_MASK);
		}
	}

	return mmu_translate_addr<true, true, false>(cpu, addr, set_smc ? MMU_SET_CODE : 0, eip, disas_ctx);
}

size_t
as_ram_dispatch_read(cpu_t *cpu, addr_t addr, size_t size, const memory_region_t<addr_t> *region, uint8_t *buffer)
{
#if defined(_WIN64)
	size_t bytes_to_read = std::min((region->end - addr) + 1ULL, size);
#else
	size_t bytes_to_read = std::min((region->end - addr) + 1, size);
#endif

	switch (region->type)
	{
	case mem_type::ram:
		std::memcpy(buffer, get_ram_host_ptr(cpu, region, addr), bytes_to_read);
		break;

	case mem_type::rom:
		std::memcpy(buffer, get_rom_host_ptr(region, addr), bytes_to_read);
		break;

	case mem_type::alias: {
		const memory_region_t<addr_t> *alias = region;
		AS_RESOLVE_ALIAS();
		return as_ram_dispatch_read(cpu, region->start + alias_offset + (addr - alias->start), bytes_to_read, region, buffer);
	}
	break;

	default:
		return 0;
	}

	return bytes_to_read;
}

void
ram_fetch(cpu_t *cpu, disas_ctx_t *disas_ctx, uint8_t *buffer)
{
	// NOTE: annoyingly, this check is already done in cpu_main_loop. If that raises a debug exception, we won't even reach here,
	// and if it doesn't this check is useless. Perhaps find a way to avoid redoing the check here. Note that this can be skipped only the first
	// time this is called by decode_instr!
	cpu_check_data_watchpoints(cpu, disas_ctx->virt_pc, 1, DR7_TYPE_INSTR, disas_ctx->virt_pc - cpu->cpu_ctx.regs.cs_hidden.base);

	if ((disas_ctx->virt_pc & ~PAGE_MASK) != ((disas_ctx->virt_pc + X86_MAX_INSTR_LENGTH - 1) & ~PAGE_MASK)) {
		size_t bytes_to_read, bytes_in_first_page;
		bytes_to_read = bytes_in_first_page = (PAGE_SIZE - (disas_ctx->virt_pc & PAGE_MASK));
		bytes_to_read = as_ram_dispatch_read(cpu, disas_ctx->pc, bytes_to_read, as_memory_search_addr(cpu, disas_ctx->pc), buffer);
		if (bytes_to_read < bytes_in_first_page) {
			// ram/rom region ends before end of buffer
			disas_ctx->instr_buff_size = bytes_to_read;
			return;
		}

		addr_t addr = get_code_addr<true>(cpu, disas_ctx->virt_pc + bytes_in_first_page, disas_ctx->virt_pc - cpu->cpu_ctx.regs.cs_hidden.base, disas_ctx);
		if (disas_ctx->exp_data.idx == EXP_PF) {
			// a page fault will be raised when fetching from the second page
			disas_ctx->instr_buff_size = bytes_in_first_page;
			return;
		}

		bytes_to_read = (X86_MAX_INSTR_LENGTH - bytes_to_read);
		buffer += bytes_in_first_page;
		bytes_to_read = as_ram_dispatch_read(cpu, addr, bytes_to_read, as_memory_search_addr(cpu, addr), buffer);
		disas_ctx->instr_buff_size = bytes_to_read + bytes_in_first_page;
	}
	else {
		disas_ctx->instr_buff_size = as_ram_dispatch_read(cpu, disas_ctx->pc, disas_ctx->instr_buff_size, as_memory_search_addr(cpu, disas_ctx->pc), buffer);
	}
}

// memory read helper invoked by the jitted code
template<typename T>
T mem_read_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_priv)
{
	uint32_t page_idx1 = addr & ~PAGE_MASK;
	uint32_t page_idx2 = (addr + sizeof(T) - 1) & ~PAGE_MASK;
	uint32_t idx = (addr >> PAGE_SHIFT) & DTLB_IDX_MASK;
	uint64_t mem_access = (tlb_access[0][(cpu_ctx->hflags & HFLG_CPL) >> is_priv]);
	uint64_t tag = ((static_cast<uint64_t>(addr) << DTLB_TAG_SHIFT64) & DTLB_TAG_MASK64) | page_idx2 | mem_access;
	mem_access |= DTLB_TAG_MASK64;

	// interrogate the dtlb
	// this checks the page privilege access (mem_access) and also if the last byte of the read is in the same page as the first (addr + sizeof(T) - 1)
	// reads that cross pages always result in tlb misses
	for (unsigned i = 0; i < DTLB_NUM_LINES; ++i) {
		if ((((cpu_ctx->cpu->dtlb[idx][i].entry & mem_access) | page_idx1) ^ tag) == 0) {
			cpu_check_data_watchpoints(cpu_ctx->cpu, addr, sizeof(T), DR7_TYPE_DATA_RW, eip);

			tlb_t *tlb = &cpu_ctx->cpu->dtlb[idx][i];
			addr_t phys_addr = (tlb->entry & ~PAGE_MASK) | (addr & PAGE_MASK);

			// tlb hit, check the region type
			switch (tlb->entry & (TLB_RAM | TLB_ROM | TLB_MMIO | TLB_SUBPAGE))
			{
			case TLB_RAM:
				// it's ram, access it directly
				return *reinterpret_cast<T *>(&cpu_ctx->ram[phys_addr - tlb->region->buff_off_start]);

			case TLB_ROM:
				// it's rom, tlb holds the rom region
				return *reinterpret_cast<T *>(&tlb->region->rom_ptr[phys_addr - tlb->region->buff_off_start]);

			case TLB_MMIO: {
				// it's mmio, tlb holds the mmio region
				const memory_region_t<addr_t> *mmio = tlb->region;
				if constexpr (sizeof(T) == 1) {
					return mmio->handlers.fnr8(phys_addr, mmio->opaque);
				}
				else if constexpr (sizeof(T) == 2) {
					return mmio->handlers.fnr16(phys_addr, mmio->opaque);
				}
				else if constexpr (sizeof(T) == 4) {
					return mmio->handlers.fnr32(phys_addr, mmio->opaque);
				}
				else if constexpr (sizeof(T) == 8) {
					return mmio->handlers.fnr64(phys_addr, mmio->opaque);
				}
				else {
					LIB86CPU_ABORT_msg("Unexpected size %u in %s", sizeof(T), __func__);
				}
			}

			case TLB_SUBPAGE:
				// this page is backed by multiple regions
				return as_memory_dispatch_read<T>(cpu_ctx->cpu, phys_addr, as_memory_search_addr(cpu_ctx->cpu, phys_addr));

			default:
				// because all other region types are cached, this should only happen with the unmapped region
				LOG(log_level::warn, "Memory read to unmapped memory at address %#010x with size %d", addr, sizeof(T));
				return std::numeric_limits<T>::max();
			}
		}
	}

	// tlb miss
	return mem_read_slow<T>(cpu_ctx->cpu, addr, eip, is_priv);
}

// memory write helper invoked by the jitted code
template<typename T, bool dont_write>
void mem_write_helper(cpu_ctx_t *cpu_ctx, addr_t addr, T val, uint32_t eip, uint8_t is_priv)
{
	// if dont_write is true, then no write will happen and we only check if the access would fault. This is used by the ENTER instruction to check
	// if a stack push with the final value of (e)sp will cause a page fault

	uint32_t page_idx1 = addr & ~PAGE_MASK;
	uint32_t page_idx2 = (addr + sizeof(T) - 1) & ~PAGE_MASK;
	uint32_t idx = (addr >> PAGE_SHIFT) & DTLB_IDX_MASK;
	uint64_t mem_access = (tlb_access[1][(cpu_ctx->hflags & HFLG_CPL) >> is_priv]) | TLB_DIRTY;
	uint64_t tag = ((static_cast<uint64_t>(addr) << DTLB_TAG_SHIFT64) & DTLB_TAG_MASK64) | page_idx2 | mem_access;
	mem_access |= DTLB_TAG_MASK64;

	// interrogate the dtlb
	// this checks the page privilege access (mem_access), if the last byte of the write is in the same page as the first (addr + sizeof(T) - 1) and
	// the tlb dirty flag. Writes that cross pages always result in tlb misses, and writes without the dirty flag set miss only once
	for (unsigned i = 0; i < DTLB_NUM_LINES; ++i) {
		if ((((cpu_ctx->cpu->dtlb[idx][i].entry & mem_access) | page_idx1) ^ tag) == 0) {
			if constexpr (dont_write) {
				// If the tlb hits, then the access is valid
				return;
			}

			cpu_check_data_watchpoints(cpu_ctx->cpu, addr, sizeof(T), DR7_TYPE_DATA_W, eip);

			tlb_t *tlb = &cpu_ctx->cpu->dtlb[idx][i];
			addr_t phys_addr = (tlb->entry & ~PAGE_MASK) | (addr & PAGE_MASK);

			if (cpu_ctx->cpu->smc[phys_addr >> PAGE_SHIFT]) {
				tc_invalidate(cpu_ctx, phys_addr, sizeof(T), eip);
			}

			// tlb hit, check the region type
			switch (tlb->entry & (TLB_RAM | TLB_ROM | TLB_MMIO | TLB_SUBPAGE))
			{
			case TLB_RAM:
				// it's ram, access it directly
				*reinterpret_cast<T *>(&cpu_ctx->ram[phys_addr - tlb->region->buff_off_start]) = val;
				return;

			case TLB_ROM:
				// it's rom, ignore it
				return;

			case TLB_MMIO: {
				// it's mmio, tlb holds the region pointer
				const memory_region_t<addr_t> *mmio = tlb->region;
				if constexpr (sizeof(T) == 1) {
					mmio->handlers.fnw8(phys_addr, val, mmio->opaque);
				}
				else if constexpr (sizeof(T) == 2) {
					mmio->handlers.fnw16(phys_addr, val, mmio->opaque);
				}
				else if constexpr (sizeof(T) == 4) {
					mmio->handlers.fnw32(phys_addr, val, mmio->opaque);
				}
				else if constexpr (sizeof(T) == 8) {
					mmio->handlers.fnw64(phys_addr, val, mmio->opaque);
				}
				else {
					LIB86CPU_ABORT_msg("Unexpected size %u in %s", sizeof(T), __func__);
				}
				return;
			}

			case TLB_SUBPAGE:
				// this page is backed by multiple regions
				as_memory_dispatch_write<T>(cpu_ctx->cpu, phys_addr, val, as_memory_search_addr(cpu_ctx->cpu, phys_addr));
				return;

			default:
				// because all other region types are cached, this should only happen with the unmapped region
				LOG(log_level::warn, "Memory write to unmapped memory at address %#010x with size %d", addr, sizeof(T));
				return;
			}
		}
	}

	if constexpr (dont_write) {
		// If the tlb misses, then the access might still be valid if the mmu can translate the address
		if ((sizeof(T) != 1) && ((addr & ~PAGE_MASK) != ((addr + sizeof(T) - 1) & ~PAGE_MASK))) {
			volatile addr_t phys_addr_s = mmu_translate_addr<false>(cpu_ctx->cpu, addr, MMU_IS_WRITE | is_priv, eip);
			volatile addr_t phys_addr_e = mmu_translate_addr<false>(cpu_ctx->cpu, addr + sizeof(T) - 1, MMU_IS_WRITE | is_priv, eip);
		}
		else {
			volatile addr_t phys_addr = mmu_translate_addr<false>(cpu_ctx->cpu, addr, MMU_IS_WRITE | is_priv, eip);
		}
	}
	else {
		// tlb miss
		mem_write_slow<T>(cpu_ctx->cpu, addr, val, eip, is_priv);
	}
}

// io read helper invoked by the jitted code
template<typename T>
T io_read_helper(cpu_ctx_t *cpu_ctx, port_t port, uint32_t eip)
{
	cpu_check_io_watchpoints(cpu_ctx->cpu, port, sizeof(T), DR7_TYPE_IO_RW, eip);
	return io_read<T>(cpu_ctx->cpu, port);
}

// io write helper invoked by the jitted code
template<typename T>
void io_write_helper(cpu_ctx_t *cpu_ctx, port_t port, T val, uint32_t eip)
{
	cpu_check_io_watchpoints(cpu_ctx->cpu, port, sizeof(T), DR7_TYPE_IO_RW, eip);
	io_write<T>(cpu_ctx->cpu, port, val);
}

template uint8_t mem_read_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_priv);
template uint16_t mem_read_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_priv);
template uint32_t mem_read_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_priv);
template uint64_t mem_read_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_priv);
template void mem_write_helper<uint8_t, false>(cpu_ctx_t *cpu_ctx, addr_t addr, uint8_t val, uint32_t eip, uint8_t is_priv);
template void mem_write_helper<uint16_t, false>(cpu_ctx_t *cpu_ctx, addr_t addr, uint16_t val, uint32_t eip, uint8_t is_priv);
template void mem_write_helper<uint32_t, false>(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t val, uint32_t eip, uint8_t is_priv);
template void mem_write_helper<uint64_t, false>(cpu_ctx_t *cpu_ctx, addr_t addr, uint64_t val, uint32_t eip, uint8_t is_priv);
template void mem_write_helper<uint8_t, true>(cpu_ctx_t *cpu_ctx, addr_t addr, uint8_t val, uint32_t eip, uint8_t is_priv);
template void mem_write_helper<uint16_t, true>(cpu_ctx_t *cpu_ctx, addr_t addr, uint16_t val, uint32_t eip, uint8_t is_priv);
template void mem_write_helper<uint32_t, true>(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t val, uint32_t eip, uint8_t is_priv);
template void mem_write_helper<uint64_t, true>(cpu_ctx_t *cpu_ctx, addr_t addr, uint64_t val, uint32_t eip, uint8_t is_priv);

template uint8_t io_read_helper(cpu_ctx_t *cpu_ctx, port_t port, uint32_t eip);
template uint16_t io_read_helper(cpu_ctx_t *cpu_ctx, port_t port, uint32_t eip);
template uint32_t io_read_helper(cpu_ctx_t *cpu_ctx, port_t port, uint32_t eip);
template void io_write_helper(cpu_ctx_t *cpu_ctx, port_t port, uint8_t val, uint32_t eip);
template void io_write_helper(cpu_ctx_t *cpu_ctx, port_t port, uint16_t val, uint32_t eip);
template void io_write_helper(cpu_ctx_t *cpu_ctx, port_t port, uint32_t val, uint32_t eip);

template addr_t get_code_addr<false>(cpu_t *cpu, addr_t addr, uint32_t eip, disas_ctx_t *disas_ctx);
template addr_t get_code_addr<true>(cpu_t *cpu, addr_t addr, uint32_t eip, disas_ctx_t *disas_ctx);

template void tlb_flush<false>(cpu_t *cpu);
template void tlb_flush<true>(cpu_t *cpu);
