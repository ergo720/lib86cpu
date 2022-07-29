/*
 * memory support
 *
 * ergo720                Copyright (c) 2019
 */

#include "internal.h"
#include "memory.h"
#include <assert.h>


void
rom_flush_cached(cpu_t *cpu, memory_region_t<addr_t> *rom)
{
	auto it = std::find_if(cpu->rom_regions.begin(), cpu->rom_regions.end(), [rom](const cached_rom_region &region) {
		return rom == region.rom;
		});

	if (it != cpu->rom_regions.end()) {
		// erasing an element invalidates all iterators/pointers to that element and after it, and element indices are changed as well, so we need
		// to flush all entries of the affected regions
		tlb_flush(cpu, TLB_rom);
		cpu->rom_regions.erase(it);
	}
}

void
mmio_flush_cached(cpu_t *cpu, memory_region_t<addr_t> *mmio)
{
	auto it = std::find_if(cpu->mmio_regions.begin(), cpu->mmio_regions.end(), [mmio](const cached_mmio_region &region) {
		return mmio == region.mmio;
		});

	if (it != cpu->mmio_regions.end()) {
		// erasing an element invalidates all iterators/pointers to that element and after it, and element indices are changed as well, so we need
		// to flush all entries of the affected regions
		tlb_flush(cpu, TLB_mmio);
		cpu->mmio_regions.erase(it);
	}
}

void
iotlb_fill(cpu_t *cpu, port_t port, memory_region_t<port_t> *io)
{
	auto it = std::find_if(cpu->iotlb_regions.begin(), cpu->iotlb_regions.end(), [io](const cached_io_region &region) {
		return io == region.io;
		});

	if (it == cpu->iotlb_regions.end()) {
		// note that emplace_back can invalidate all iterators/pointers, but not the element indices, so we don't need to flush the iotlb
		cpu->iotlb_regions.emplace_back(io, io->read_handler, io->write_handler, io->opaque);
		cpu->iotlb_regions_ptr = &cpu->iotlb_regions[0];
		it = std::prev(cpu->iotlb_regions.end(), 1);
	}

	unsigned iotlb_idx = port >> IO_SHIFT;
	cpu->cpu_ctx.iotlb[iotlb_idx] = ((cpu->cpu_ctx.iotlb[iotlb_idx] & IOTLB_WATCH) | (IOTLB_VALID | (std::distance(cpu->iotlb_regions.begin(), it) << IO_SHIFT)));
}

void
iotlb_flush(cpu_t *cpu, memory_region_t<port_t> *io)
{
	auto it = std::find_if(cpu->iotlb_regions.begin(), cpu->iotlb_regions.end(), [io](const cached_io_region &region) {
		return io == region.io;
		});

	if (it != cpu->iotlb_regions.end()) {
		// erasing an element invalidates all iterators/pointers to that element and after it, and element indices are changed as well, so we need
		// to flush all entries of the affected regions
		std::for_each(it, cpu->iotlb_regions.end(), [cpu](const cached_io_region &region) {
			for (port_t port = region.io->start; port <= region.io->end; port += IO_SIZE) {
				unsigned iotlb_idx = port >> IO_SHIFT;
				cpu->cpu_ctx.iotlb[iotlb_idx] = (cpu->cpu_ctx.iotlb[iotlb_idx] & IOTLB_WATCH);
			}
			});
		cpu->iotlb_regions.erase(it);
		cpu->iotlb_regions_ptr = &cpu->iotlb_regions[0];
	}
}

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

static void
tlb_fill(cpu_t *cpu, addr_t addr, addr_t phys_addr, uint32_t prot)
{
	assert((prot & ~PAGE_MASK) == 0);

	uint32_t offset = 0;
	unsigned tlb_idx = addr >> PAGE_SHIFT;
	memory_region_t<addr_t> *region = as_memory_search_addr<uint8_t>(cpu, phys_addr);

	if (region->type == mem_type::alias) {
		while (region->aliased_region) {
			offset += (region->start - (region->alias_offset + region->aliased_region->start));
			region = region->aliased_region;
		}
	}

	if (region->type == mem_type::ram) {
		phys_addr -= (offset - region->start);
		cpu->cpu_ctx.tlb[tlb_idx] = (phys_addr & ~PAGE_MASK) | (prot | TLB_RAM) | (cpu->cpu_ctx.tlb[tlb_idx] & TLB_WATCH);
	}
	else if (region->type == mem_type::rom) {
		prot &= ~TLB_CODE;

		auto it = std::find_if(cpu->rom_regions.begin(), cpu->rom_regions.end(), [region](const cached_rom_region &region2) {
			return region == region2.rom;
			});

		if (it == cpu->rom_regions.end()) {
			// note that emplace_back can invalidate all iterators/pointers, but not the element indices, so we don't need to flush the iotlb
			cpu->rom_regions.emplace_back(region, cpu->vec_rom[region->rom_idx].get());
			it = std::prev(cpu->rom_regions.end(), 1);
		}

		phys_addr -= (offset - region->start);
		cpu->cpu_ctx.tlb[tlb_idx] = (phys_addr & ~PAGE_MASK) | prot | TLB_ROM | (cpu->cpu_ctx.tlb[tlb_idx] & TLB_WATCH);
		cpu->cpu_ctx.tlb_region_idx[tlb_idx] = std::distance(cpu->rom_regions.begin(), it);
	}
	else if (region->type == mem_type::mmio) {
		auto it = std::find_if(cpu->mmio_regions.begin(), cpu->mmio_regions.end(), [region](const cached_mmio_region &region2) {
			return region == region2.mmio;
			});

		if (it == cpu->mmio_regions.end()) {
			// note that emplace_back can invalidate all iterators/pointers, but not the element indices, so we don't need to flush the iotlb
			cpu->mmio_regions.emplace_back(region, region->read_handler, region->write_handler, region->opaque);
			it = std::prev(cpu->mmio_regions.end(), 1);
		}

		cpu->cpu_ctx.tlb[tlb_idx] = (phys_addr & ~PAGE_MASK) | prot | TLB_MMIO | (cpu->cpu_ctx.tlb[tlb_idx] & TLB_WATCH);
		cpu->cpu_ctx.tlb_region_idx[tlb_idx] = std::distance(cpu->mmio_regions.begin(), it);
	}
	else {
		cpu->cpu_ctx.tlb[tlb_idx] = (phys_addr & ~PAGE_MASK) | prot | (cpu->cpu_ctx.tlb[tlb_idx] & TLB_WATCH);
	}
}

void
tlb_flush(cpu_t *cpu, int n)
{
	switch (n)
	{
	case TLB_zero:
		for (uint32_t &tlb_entry : cpu->cpu_ctx.tlb) {
			tlb_entry = (tlb_entry & TLB_WATCH);
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

	case TLB_rom:
		for (uint32_t &tlb_entry : cpu->cpu_ctx.tlb) {
			if (tlb_entry & TLB_ROM) {
				tlb_entry = (tlb_entry & TLB_WATCH);
			}
		}
		break;

	case TLB_mmio:
		for (uint32_t &tlb_entry : cpu->cpu_ctx.tlb) {
			if (tlb_entry & TLB_MMIO) {
				tlb_entry = (tlb_entry & TLB_WATCH);
			}
		}
		break;

	default:
		LIB86CPU_ABORT();
	}

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
		tlb_fill(cpu, addr, addr, TLB_SUP_READ | TLB_SUP_WRITE | TLB_USER_READ | TLB_USER_WRITE | ((flags & 1) << 9) | is_code);
		return addr;
	}
	else {
		static const uint8_t cpl_to_page_priv[4] = { 0, 0, 0, 4 };

		uint8_t is_write = flags & 1;
		uint8_t is_priv = flags & 2;
		uint8_t err_code = 0;
		uint8_t cpu_lv = cpl_to_page_priv[cpu->cpu_ctx.hflags & HFLG_CPL];
		addr_t pde_addr = (cpu->cpu_ctx.regs.cr3 & CR3_PD_MASK) | (addr >> PAGE_SHIFT_LARGE) * 4;
		uint32_t pde = as_memory_dispatch_read<uint32_t>(cpu, pde_addr, as_memory_search_addr<uint8_t>(cpu, pde_addr));

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
					as_memory_dispatch_write<uint32_t>(cpu, pde_addr, pde, as_memory_search_addr<uint8_t>(cpu, pde_addr));
				}
				addr_t phys_addr = (pde & PTE_ADDR_4M) | (addr & PAGE_MASK_LARGE);
				tlb_fill(cpu, addr, phys_addr,
					tlb_gen_access_mask(cpu, pde_priv & PTE_USER, pde_priv & PTE_WRITE)
					| is_code | (is_write << 9) | ((pde & PTE_GLOBAL) & ((cpu->cpu_ctx.regs.cr4 & CR4_PGE_MASK) << 1)));
				return phys_addr;
			}
			err_code = 1;
			mmu_raise_page_fault<raise_host_exp>(cpu, addr, eip, disas_ctx, err_code, is_write, cpu_lv);
			return 0;
		}

		addr_t pte_addr = (pde & PTE_ADDR_4K) | ((addr >> PAGE_SHIFT) & 0x3FF) * 4;
		uint32_t pte = as_memory_dispatch_read<uint32_t>(cpu, pte_addr, as_memory_search_addr<uint8_t>(cpu, pte_addr));

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
				as_memory_dispatch_write<uint32_t>(cpu, pde_addr, pde, as_memory_search_addr<uint8_t>(cpu, pde_addr));
			}
			if (!(pte & PTE_ACCESSED) || is_write) {
				pte |= PTE_ACCESSED;
				if (is_write) {
					pte |= PTE_DIRTY;
				}
				as_memory_dispatch_write<uint32_t>(cpu, pte_addr, pte, as_memory_search_addr<uint8_t>(cpu, pte_addr));
			}
			addr_t phys_addr = (pte & PTE_ADDR_4K) | (addr & PAGE_MASK);
			tlb_fill(cpu, addr, phys_addr,
				tlb_gen_access_mask(cpu, access_lv & PTE_USER, access_lv & PTE_WRITE)
				| is_code | (is_write << 9) | ((pte & PTE_GLOBAL) & ((cpu->cpu_ctx.regs.cr4 & CR4_PGE_MASK) << 1)));
			return phys_addr;
		}
		err_code = 1;

		mmu_raise_page_fault<raise_host_exp>(cpu, addr, eip, disas_ctx, err_code, is_write, cpu_lv);
		return 0;
	}
}

// These functions below only get the address of a single byte and thus do not need to check for a page boundary crossing
addr_t
get_read_addr(cpu_t *cpu, addr_t addr, uint8_t is_priv, uint32_t eip)
{
	uint32_t tlb_entry = cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT];
	if ((tlb_entry & (tlb_access[0][(cpu->cpu_ctx.hflags & HFLG_CPL) >> is_priv])) == 0) {
		return mmu_translate_addr(cpu, addr, is_priv, eip);
	}

	return (tlb_entry & ~PAGE_MASK) | (addr & PAGE_MASK);
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

	return (tlb_entry & ~PAGE_MASK) | (addr & PAGE_MASK);
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
	return (tlb_entry & ~PAGE_MASK) | (addr & PAGE_MASK);
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
	return (tlb_entry & ~PAGE_MASK) | (addr & PAGE_MASK);
}

size_t
as_ram_dispatch_read(cpu_t *cpu, addr_t addr, size_t size, memory_region_t<addr_t> *region, uint8_t *buffer)
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
		std::memcpy(buffer, get_rom_host_ptr(cpu, region, addr), bytes_to_read);
		break;

	case mem_type::alias: {
		memory_region_t<addr_t> *alias = region;
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
		bytes_to_read = as_ram_dispatch_read(cpu, disas_ctx->pc, bytes_to_read, as_memory_search_addr<uint8_t>(cpu, disas_ctx->pc), buffer);
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
		bytes_to_read = as_ram_dispatch_read(cpu, addr, bytes_to_read, as_memory_search_addr<uint8_t>(cpu, addr), buffer);
		disas_ctx->instr_buff_size = bytes_to_read + bytes_in_first_page;
	}
	else {
		disas_ctx->instr_buff_size = as_ram_dispatch_read(cpu, disas_ctx->pc, disas_ctx->instr_buff_size, as_memory_search_addr<uint8_t>(cpu, disas_ctx->pc), buffer);
	}
}

// memory read helper invoked by the llvm generated code
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
		addr_t phys_addr = (tlb_entry & ~PAGE_MASK) | (addr & PAGE_MASK);
		switch (tlb_entry & (TLB_RAM | TLB_ROM | TLB_MMIO))
		{
		case TLB_RAM: {
			// it's ram, access it directly
			T ret = *reinterpret_cast<T *>(&cpu_ctx->ram[phys_addr]);
			if constexpr (is_big_endian) {
				sys::swapByteOrder<T>(ret);
			}
			return ret;
		}

		case TLB_ROM: {
			// it's rom, find the buffer pointer and access it directly
			cached_rom_region *rom = &cpu_ctx->cpu->rom_regions[cpu_ctx->tlb_region_idx[tlb_idx1]];
			T ret = *reinterpret_cast<T *>(&rom->buffer[phys_addr]);
			if constexpr (is_big_endian) {
				sys::swapByteOrder<T>(ret);
			}
			return ret;
		}

		case TLB_MMIO: {
			// it's mmio, invoke the handler directly
			cached_mmio_region *mmio = &cpu_ctx->cpu->mmio_regions[cpu_ctx->tlb_region_idx[tlb_idx1]];
			return mmio->read_handler(phys_addr, sizeof(T), mmio->opaque);
		}

		default:
			// unknown region type, acccess the memory region with the external handler
			// because all other region types are cached, this should only happen with the unmapped region
			return mem_read<T>(cpu_ctx->cpu, phys_addr, eip, 1 | is_priv);
		}
	}

	// tlb miss, acccess the memory region with is_phys flag=0
	return mem_read<T>(cpu_ctx->cpu, addr, eip, is_priv);
}

// memory write helper invoked by the llvm generated code
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
		addr_t phys_addr = (tlb_entry & ~PAGE_MASK) | (addr & PAGE_MASK);
		switch (tlb_entry & (TLB_RAM | TLB_ROM | TLB_MMIO))
		{
		case TLB_RAM:
			// it's ram, access it directly
			if constexpr (is_big_endian) {
				sys::swapByteOrder<T>(val);
			}
			*reinterpret_cast<T *>(&cpu_ctx->ram[phys_addr]) = val;
			return;

		case TLB_ROM:
			// it's rom, ignore it
			return;

		case TLB_MMIO: {
			// it's mmio, invoke the handler directly
			cached_mmio_region *mmio = &cpu_ctx->cpu->mmio_regions[cpu_ctx->tlb_region_idx[tlb_idx1]];
			mmio->write_handler(phys_addr, sizeof(T), val, mmio->opaque);
			return;
		}

		default:
			// unknown region type, acccess the memory region with the external handler
			// because all other region types are cached, this should only happen with the unmapped region
			mem_write<T>(cpu_ctx->cpu, phys_addr, val, eip, 1 | is_priv);
			return;
		}
	}

	// tlb miss, acccess the memory region with is_phys flag=0
	mem_write<T>(cpu_ctx->cpu, addr, val, eip, is_priv);
}

uint8_t
io_read8(cpu_ctx_t *cpu_ctx, port_t port)
{
	return io_read<uint8_t>(cpu_ctx->cpu, port);
}

uint16_t
io_read16(cpu_ctx_t *cpu_ctx, port_t port)
{
	return io_read<uint16_t>(cpu_ctx->cpu, port);
}

uint32_t
io_read32(cpu_ctx_t *cpu_ctx, port_t port)
{
	return io_read<uint32_t>(cpu_ctx->cpu, port);
}

void
io_write8(cpu_ctx_t *cpu_ctx, port_t port, uint8_t value)
{
	io_write<uint8_t>(cpu_ctx->cpu, port, value);
}

void
io_write16(cpu_ctx_t *cpu_ctx, port_t port, uint16_t value)
{
	io_write<uint16_t>(cpu_ctx->cpu, port, value);
}

void
io_write32(cpu_ctx_t *cpu_ctx, port_t port, uint32_t value)
{
	io_write<uint32_t>(cpu_ctx->cpu, port, value);
}

template uint8_t mem_read_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_priv);
template uint16_t mem_read_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_priv);
template uint32_t mem_read_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_priv);
template uint64_t mem_read_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_priv);
template void mem_write_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint8_t val, uint32_t eip, uint8_t is_priv);
template void mem_write_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint16_t val, uint32_t eip, uint8_t is_priv);
template void mem_write_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t val, uint32_t eip, uint8_t is_priv);
template void mem_write_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint64_t val, uint32_t eip, uint8_t is_priv);
