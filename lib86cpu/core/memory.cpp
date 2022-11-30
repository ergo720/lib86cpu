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
	// this function applies three corrections to the physical address:
	// 1. if region is alias, it resolves it and calculates the final addr the aliased addr is pointing to
	// 2. if region is ram or rom, it subtracts the region start, so that phys_addr can be used to index the ram/rom buffer
	// 3. it masks the address with the current state of the a20 gate

	if (region->type == mem_type::alias) {
		uint32_t offset = 0;
		while (region->aliased_region) {
			offset += (region->start - (region->alias_offset + region->aliased_region->start));
			region = region->aliased_region;
		}
		phys_addr -= offset;
	}

	if ((region->type == mem_type::ram) || (region->type == mem_type::rom)) {
		phys_addr -= region->start;
	}

	return phys_addr & cpu->a20_mask;
}

static addr_t
tlb_fill(cpu_t *cpu, addr_t addr, addr_t phys_addr, uint32_t prot)
{
	assert((prot & ~PAGE_MASK) == 0);

	unsigned tlb_idx = addr >> PAGE_SHIFT;
	const memory_region_t<addr_t> *region = as_memory_search_addr(cpu, phys_addr);
	phys_addr = correct_phys_addr(cpu, phys_addr, region);
	addr_t start_page = phys_addr & ~PAGE_MASK;
	addr_t end_page = ((static_cast<uint64_t>(phys_addr) + PAGE_SIZE) & ~PAGE_MASK) - 1; // the cast avoids overflow on the last page at 0xFFFFF000

	if ((region->start <= start_page) && (region->end >= end_page)) {
		// region spans the entire page

		if (region->type == mem_type::ram) {
			cpu->cpu_ctx.tlb[tlb_idx] = (phys_addr & ~PAGE_MASK) | (prot | TLB_RAM) | (cpu->cpu_ctx.tlb[tlb_idx] & TLB_WATCH);
		}
		else if (region->type == mem_type::unmapped) {
			cpu->cpu_ctx.tlb[tlb_idx] = (phys_addr & ~PAGE_MASK) | prot | (cpu->cpu_ctx.tlb[tlb_idx] & TLB_WATCH);
		}
		else {
			subpage_t *subpage;
			uint32_t subpage_idx;
			if (cpu->cpu_ctx.tlb[tlb_idx] & (TLB_ROM | TLB_MMIO)) {
				// don't add duplicates
				subpage_idx = cpu->cpu_ctx.tlb[tlb_idx] >> PAGE_SHIFT;
				subpage = &cpu->subpages[subpage_idx];
			}
			else {
				subpage = &cpu->subpages.emplace_back(subpage_t{});
				subpage->cached_region_idx = new uint16_t[1];
				subpage_idx = cpu->subpages.size() - 1;
			}

			// always write phys_addr in the case we are here because the tlb entry was flushed
			subpage->phys_addr = phys_addr & ~PAGE_MASK;

			const auto it = std::find_if(cpu->cached_regions.begin(), cpu->cached_regions.end(), [region](const memory_region_t<addr_t> *region2) {
				return region == region2;
				});
			if (it == cpu->cached_regions.end()) {
				cpu->cached_regions.emplace_back(region);
				subpage->cached_region_idx[0] = cpu->cached_regions.size() - 1;
			}
			else {
				// don't add duplicates
				subpage->cached_region_idx[0] = it - cpu->cached_regions.begin();
			}

			if (region->type == mem_type::mmio) {
				prot |= TLB_MMIO;
			}
			else {
				prot &= ~TLB_CODE;
				prot |= TLB_ROM;
			}
			cpu->cpu_ctx.tlb[tlb_idx] = (subpage_idx << PAGE_SHIFT) | prot | (cpu->cpu_ctx.tlb[tlb_idx] & TLB_WATCH);
		}
	}
	else {
		// region doesn't cover the entire page

		subpage_t *subpage;
		uint32_t subpage_idx;
		if (cpu->cpu_ctx.tlb[tlb_idx] & TLB_SUBPAGE) {
			// don't add duplicates
			subpage_idx = cpu->cpu_ctx.tlb[tlb_idx] >> PAGE_SHIFT;
			subpage = &cpu->subpages[subpage_idx];
		}
		else {
			subpage = &cpu->subpages.emplace_back(subpage_t{});
			subpage->cached_region_idx = new uint16_t[PAGE_SIZE]();
			subpage_idx = cpu->subpages.size() - 1;
		}

		// always write phys_addr in the case we are here because the tlb entry was flushed
		subpage->phys_addr = phys_addr & ~PAGE_MASK;

		uint32_t region_idx;
		const auto it = std::find_if(cpu->cached_regions.begin(), cpu->cached_regions.end(), [region](const memory_region_t<addr_t> *region2) {
			return region == region2;
			});
		if (it == cpu->cached_regions.end()) {
			cpu->cached_regions.emplace_back(region);
			region_idx = cpu->cached_regions.size() - 1;
		}
		else {
			// don't add duplicates
			region_idx = it - cpu->cached_regions.begin();
		}

		unsigned start_idx = std::max(start_page, region->start) & PAGE_MASK;
		unsigned end_idx = std::min(end_page, region->end) & PAGE_MASK;
		for (unsigned idx = start_idx; idx <= end_idx; ++idx) {
			subpage->cached_region_idx[idx] = region_idx;
		}

		cpu->cpu_ctx.tlb[tlb_idx] = (subpage_idx << PAGE_SHIFT) | (prot | TLB_SUBPAGE) | (cpu->cpu_ctx.tlb[tlb_idx] & TLB_WATCH);
	}

	return phys_addr;
}

void
tlb_flush(cpu_t *cpu, int n)
{
	switch (n)
	{
	case TLB_zero: {
		uint32_t tlb_watch_idx[8], tlb_watch[8] = { 0 };
		bool mem_watch[4];
		for (int idx = 0; idx < 4; ++idx) {
			mem_watch[idx] = cpu_get_watchpoint_type(cpu, idx) != DR7_TYPE_IO_RW;
			if (mem_watch[idx]) {
				size_t wp_len = cpu_get_watchpoint_lenght(cpu, idx);
				uint32_t dr = cpu->cpu_ctx.regs.dr[idx];
				tlb_watch_idx[idx * 2] = dr >> PAGE_SHIFT;
				tlb_watch_idx[idx * 2 + 1] = (dr + wp_len - 1) >> PAGE_SHIFT;
				tlb_watch[idx * 2] = cpu->cpu_ctx.tlb[tlb_watch_idx[idx * 2]] & TLB_WATCH;
				if (tlb_watch_idx[idx * 2] != tlb_watch_idx[idx * 2 + 1]) {
					tlb_watch[idx * 2 + 1] = cpu->cpu_ctx.tlb[tlb_watch_idx[idx * 2 + 1]] & TLB_WATCH;
				}
			}
		}
		for (uint32_t &tlb_entry : cpu->cpu_ctx.tlb) {
			tlb_entry = 0;
		}
		for (int idx = 0; idx < 4; ++idx) {
			if (mem_watch[idx]) {
				cpu->cpu_ctx.tlb[tlb_watch_idx[idx * 2]] = tlb_watch[idx * 2];
				cpu->cpu_ctx.tlb[tlb_watch_idx[idx * 2 + 1]] = tlb_watch[idx * 2 + 1];
			}
		}
	}
	break;

	case TLB_keep_cw:
		for (uint32_t &tlb_entry : cpu->cpu_ctx.tlb) {
			tlb_entry = (tlb_entry & (TLB_CODE | TLB_WATCH));
		}
		break;

	case TLB_no_g:
		for (uint32_t &tlb_entry : cpu->cpu_ctx.tlb) {
			if (!(tlb_entry & TLB_GLOBAL)) {
				tlb_entry = (tlb_entry & (TLB_CODE | TLB_WATCH));
			}
		}
		break;

	default:
		LIB86CPU_ABORT();
	}

	cpu->subpages.clear();
}

int8_t
check_page_access(cpu_t *cpu, uint8_t access_level, uint8_t mem_access)
{
	// 0 = access denied, 1 = access granted, -1 = error

	// two rows because when wp flag of cr0 is 1, then supervisor cannot write to supervisor read only pages
	static const int8_t level_zero[2][7] = { // s/r page
		{ 1, -1, 1, -1, 0, -1, 0 },
		{ 1, -1, 0, -1, 0, -1, 0 },
	};

	static const int8_t level_two[7] = { // s/w page
		1, -1, 1, -1, 0, -1, 0,
	};

	// two rows because when wp flag of cr0 is 1, then supervisor cannot write to user read only pages
	static const int8_t level_four[2][7] = { // u/r page
		{ 1, -1, 1, -1, 1, -1, 0 },
		{ 1, -1, 0, -1, 1, -1, 0 },
	};

	static const int8_t level_six[7] = { // u/w page
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
	static const int8_t access_table[7][7] = {
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

// NOTE: flags: bit 0 -> is_write, bit 1 -> is_priv, bit 4 -> is_code
template<bool raise_host_exp = true>
addr_t mmu_translate_addr(cpu_t *cpu, addr_t addr, uint8_t flags, uint32_t eip, disas_ctx_t *disas_ctx = nullptr)
{
	uint8_t is_code = flags & TLB_CODE;

	if (!(cpu->cpu_ctx.regs.cr0 & CR0_PG_MASK)) {
		return tlb_fill(cpu, addr, addr, TLB_SUP_READ | TLB_SUP_WRITE | TLB_USER_READ | TLB_USER_WRITE | ((flags & 1) << 9) | is_code);
	}
	else {
		static const uint8_t cpl_to_page_priv[4] = { 0, 0, 0, 4 };

		uint8_t is_write = flags & 1;
		uint8_t is_priv = flags & 2;
		uint8_t err_code = 0;
		uint8_t cpu_lv = cpl_to_page_priv[cpu->cpu_ctx.hflags & HFLG_CPL];
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
				return tlb_fill(cpu, addr, (pde & PTE_ADDR_4M) | (addr & PAGE_MASK_LARGE),
					tlb_gen_access_mask(cpu, pde_priv & PTE_USER, pde_priv & PTE_WRITE)
					| is_code | (is_write << 9) | ((pde & PTE_GLOBAL) & ((cpu->cpu_ctx.regs.cr4 & CR4_PGE_MASK) << 1)));
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
			return tlb_fill(cpu, addr, (pte & PTE_ADDR_4K) | (addr & PAGE_MASK),
				tlb_gen_access_mask(cpu, access_lv & PTE_USER, access_lv & PTE_WRITE)
				| is_code | (is_write << 9) | ((pte & PTE_GLOBAL) & ((cpu->cpu_ctx.regs.cr4 & CR4_PGE_MASK) << 1)));
		}
		err_code = 1;

		mmu_raise_page_fault<raise_host_exp>(cpu, addr, eip, disas_ctx, err_code, is_write, cpu_lv);
		return 0;
	}
}

static addr_t
get_phys_addr(cpu_t *cpu, addr_t addr, uint32_t tlb_entry)
{
	switch (tlb_entry & (TLB_RAM | TLB_ROM | TLB_MMIO | TLB_SUBPAGE))
	{
	case TLB_RAM:
	default:
		return (tlb_entry & ~PAGE_MASK) | (addr & PAGE_MASK);

	case TLB_ROM:
	case TLB_MMIO:
	case TLB_SUBPAGE:
		return (cpu->subpages[tlb_entry >> PAGE_SHIFT].phys_addr) | (addr & PAGE_MASK);
	}
}

// These functions below only get the address of a single byte and thus do not need to check for a page boundary crossing. They return a corrected
// physical address taking into account memory aliasing and region start offset
addr_t
get_read_addr(cpu_t *cpu, addr_t addr, uint8_t is_priv, uint32_t eip)
{
	uint32_t tlb_entry = cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT];
	if ((tlb_entry & (tlb_access[0][(cpu->cpu_ctx.hflags & HFLG_CPL) >> is_priv])) == 0) {
		return mmu_translate_addr(cpu, addr, is_priv, eip);
	}

	return get_phys_addr(cpu, addr, tlb_entry);
}

addr_t
get_write_addr(cpu_t *cpu, addr_t addr, uint8_t is_priv, uint32_t eip, uint8_t *is_code)
{
	// this also needs to check for the dirty flag, to catch the case where the first access to the page is a read and then a write happens, so that
	// we give the mmu the chance to set the dirty flag in the tlb

	uint32_t tlb_entry = cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT];
	*is_code = tlb_entry & TLB_CODE;
	if (((tlb_access[1][(cpu->cpu_ctx.hflags & HFLG_CPL) >> is_priv]) | TLB_DIRTY) ^ (tlb_entry & ((tlb_access[1][(cpu->cpu_ctx.hflags & HFLG_CPL) >> is_priv]) | TLB_DIRTY))) {
		return mmu_translate_addr(cpu, addr, 1 | is_priv, eip);
	}

	return get_phys_addr(cpu, addr, tlb_entry);
}

addr_t
get_code_addr(cpu_t *cpu, addr_t addr, uint32_t eip)
{
	// this is only used for ram fetching, so we don't need to check for privileged accesses

	uint32_t tlb_entry = cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT];
	if ((tlb_entry & (tlb_access[0][cpu->cpu_ctx.hflags & HFLG_CPL])) == 0) {
		return mmu_translate_addr(cpu, addr, TLB_CODE, eip);
	}

	cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT] = tlb_entry | TLB_CODE;
	return get_phys_addr(cpu, addr, tlb_entry);
}

addr_t
get_code_addr(cpu_t *cpu, addr_t addr, uint32_t eip, uint32_t is_code, disas_ctx_t *disas_ctx)
{
	// overloaded get_code_addr that does not throw host exceptions, used in cpu_translate and by the debugger
	// NOTE: the debugger should not set is_code, since it doesn't execute the instructions

	uint32_t tlb_entry = cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT];
	if ((tlb_entry & (tlb_access[0][cpu->cpu_ctx.hflags & HFLG_CPL])) == 0) {
		return mmu_translate_addr<false>(cpu, addr, is_code, eip, disas_ctx);
	}

	cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT] = tlb_entry | is_code;
	return get_phys_addr(cpu, addr, tlb_entry);
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
		std::memcpy(buffer, get_ram_host_ptr(cpu, addr), bytes_to_read);
		break;

	case mem_type::rom:
		std::memcpy(buffer, get_rom_host_ptr(cpu, region, addr), bytes_to_read);
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

		addr_t addr = get_code_addr(cpu, disas_ctx->virt_pc + bytes_in_first_page, disas_ctx->virt_pc - cpu->cpu_ctx.regs.cs_hidden.base, TLB_CODE, disas_ctx);
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
	uint32_t tlb_idx1 = addr >> PAGE_SHIFT;
	uint32_t tlb_idx2 = (addr + sizeof(T) - 1) >> PAGE_SHIFT;
	uint32_t tlb_entry = cpu_ctx->tlb[tlb_idx1];
	uint32_t mem_access = tlb_access[0][(cpu_ctx->hflags & HFLG_CPL) >> is_priv];

	// interrogate the tlb
	// this checks the page privilege access (mem_access) and also if the last byte of the read is in the same page as the first (addr + sizeof(T) - 1)
	// reads that cross pages or that reside in a page where a watchpoint is installed always result in tlb misses
	if ((((tlb_entry & (mem_access | TLB_WATCH)) | (tlb_idx1 << PAGE_SHIFT)) ^ (mem_access | (tlb_idx2 << PAGE_SHIFT))) == 0) {
		// tlb hit, check the region type
		switch (tlb_entry & (TLB_RAM | TLB_ROM | TLB_MMIO | TLB_SUBPAGE))
		{
		case TLB_RAM: {
			// it's ram, tlb holds the physical address
			addr_t phys_addr = (tlb_entry & ~PAGE_MASK) | (addr & PAGE_MASK);
			T ret = *reinterpret_cast<T *>(&cpu_ctx->ram[phys_addr]);
			if constexpr (is_big_endian) {
				swap_byte_order<T>(ret);
			}
			return ret;
		}

		case TLB_ROM: {
			// it's rom, tlb holds the index to find the rom subpage
			const subpage_t *subpage = &cpu_ctx->cpu->subpages[tlb_entry >> PAGE_SHIFT];
			addr_t phys_addr = subpage->phys_addr | (addr & PAGE_MASK);
			const memory_region_t<addr_t> *rom = cpu_ctx->cpu->cached_regions[subpage->cached_region_idx[0]];
			T ret = *reinterpret_cast<T *>(&cpu_ctx->cpu->vec_rom[rom->rom_idx][phys_addr]);
			if constexpr (is_big_endian) {
				swap_byte_order<T>(ret);
			}
			return ret;
		}

		case TLB_MMIO: {
			// it's mmio, tlb holds the index to find the mmio subpage
			const subpage_t *subpage = &cpu_ctx->cpu->subpages[tlb_entry >> PAGE_SHIFT];
			addr_t phys_addr = subpage->phys_addr | (addr & PAGE_MASK);
			const memory_region_t<addr_t> *mmio = cpu_ctx->cpu->cached_regions[subpage->cached_region_idx[0]];
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

		case TLB_SUBPAGE: {
			// this page is backed by multiple regions
			const subpage_t *subpage = &cpu_ctx->cpu->subpages[tlb_entry >> PAGE_SHIFT];
			addr_t phys_addr = subpage->phys_addr | (addr & PAGE_MASK);
			const memory_region_t<addr_t> *region = cpu_ctx->cpu->cached_regions[subpage->cached_region_idx[addr & PAGE_MASK]];
			if (region) {
				return as_memory_dispatch_read<T>(cpu_ctx->cpu, phys_addr, region);
			}
			else {
				// this will happen when a write is performed for the first time on a different region of the subpage
				return mem_read_slow<T>(cpu_ctx->cpu, addr, eip, is_priv);
			}
		}

		default:
			// because all other region types are cached, this should only happen with the unmapped region
			LOG(log_level::warn, "Memory read to unmapped memory at address %#010x with size %d", addr, sizeof(T));
			return std::numeric_limits<T>::max();
		}
	}

	// tlb miss
	return mem_read_slow<T>(cpu_ctx->cpu, addr, eip, is_priv);
}

// memory write helper invoked by the jitted code
template<typename T>
void mem_write_helper(cpu_ctx_t *cpu_ctx, addr_t addr, T val, uint32_t eip, uint8_t is_priv)
{
	uint32_t tlb_idx1 = addr >> PAGE_SHIFT;
	uint32_t tlb_idx2 = (addr + sizeof(T) - 1) >> PAGE_SHIFT;
	uint32_t tlb_entry = cpu_ctx->tlb[tlb_idx1];
	uint32_t mem_access = (tlb_access[1][(cpu_ctx->hflags & HFLG_CPL) >> is_priv]) | TLB_DIRTY;

	// interrogate the tlb
	// this checks the page privilege access (mem_access), if the last byte of the write is in the same page as the first (addr + sizeof(T) - 1) and
	// the tlb dirty flag. Writes that cross pages or that hit a page where a watchpoint is installed or there is translated code always result in tlb misses,
	// and writes without the dirty flag set miss only once
	if ((((tlb_entry & (mem_access | TLB_CODE | TLB_WATCH)) | (tlb_idx1 << PAGE_SHIFT)) ^ (mem_access | (tlb_idx2 << PAGE_SHIFT))) == 0) {
		// tlb hit, check the region type
		switch (tlb_entry & (TLB_RAM | TLB_ROM | TLB_MMIO | TLB_SUBPAGE))
		{
		case TLB_RAM: {
			// it's ram, access it directly
			if constexpr (is_big_endian) {
				swap_byte_order<T>(val);
			}
			addr_t phys_addr = (tlb_entry & ~PAGE_MASK) | (addr & PAGE_MASK);
			*reinterpret_cast<T *>(&cpu_ctx->ram[phys_addr]) = val;
			return;
		}

		case TLB_ROM:
			// it's rom, ignore it
			return;

		case TLB_MMIO: {
			// it's mmio, tlb holds the index to find the mmio subpage
			const subpage_t *subpage = &cpu_ctx->cpu->subpages[tlb_entry >> PAGE_SHIFT];
			addr_t phys_addr = subpage->phys_addr | (addr & PAGE_MASK);
			const memory_region_t<addr_t> *mmio = cpu_ctx->cpu->cached_regions[subpage->cached_region_idx[0]];
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

		case TLB_SUBPAGE: {
			// this page is backed by multiple regions
			const subpage_t *subpage = &cpu_ctx->cpu->subpages[tlb_entry >> PAGE_SHIFT];
			addr_t phys_addr = subpage->phys_addr | (addr & PAGE_MASK);
			const memory_region_t<addr_t> *region = cpu_ctx->cpu->cached_regions[subpage->cached_region_idx[addr & PAGE_MASK]];
			if (region) {
				as_memory_dispatch_write<T>(cpu_ctx->cpu, phys_addr, val, region);
			}
			else {
				// this will happen when a write is performed for the first time on a different region of the subpage
				mem_write_slow<T>(cpu_ctx->cpu, addr, val, eip, is_priv);
			}
			return;
		}

		default:
			// because all other region types are cached, this should only happen with the unmapped region
			LOG(log_level::warn, "Memory write to unmapped memory at address %#010x with size %d", addr, sizeof(T));
			return;
		}
	}

	// tlb miss, acccess the memory region with is_phys flag=0
	mem_write_slow<T>(cpu_ctx->cpu, addr, val, eip, is_priv);
}

// io read helper invoked by the jitted code
template<typename T>
T io_read_helper(cpu_ctx_t *cpu_ctx, port_t port)
{
	// TODO: check for io watchpoints
	return io_read<T>(cpu_ctx->cpu, port);
}

// io write helper invoked by the jitted code
template<typename T>
void io_write_helper(cpu_ctx_t *cpu_ctx, port_t port, T val)
{
	// TODO: check for io watchpoints
	io_write<T>(cpu_ctx->cpu, port, val);
}

template uint8_t mem_read_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_priv);
template uint16_t mem_read_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_priv);
template uint32_t mem_read_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_priv);
template uint64_t mem_read_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_priv);
template void mem_write_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint8_t val, uint32_t eip, uint8_t is_priv);
template void mem_write_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint16_t val, uint32_t eip, uint8_t is_priv);
template void mem_write_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t val, uint32_t eip, uint8_t is_priv);
template void mem_write_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint64_t val, uint32_t eip, uint8_t is_priv);

template uint8_t io_read_helper(cpu_ctx_t *cpu_ctx, port_t port);
template uint16_t io_read_helper(cpu_ctx_t *cpu_ctx, port_t port);
template uint32_t io_read_helper(cpu_ctx_t *cpu_ctx, port_t port);
template void io_write_helper(cpu_ctx_t *cpu_ctx, port_t port, uint8_t val);
template void io_write_helper(cpu_ctx_t *cpu_ctx, port_t port, uint16_t val);
template void io_write_helper(cpu_ctx_t *cpu_ctx, port_t port, uint32_t val);
