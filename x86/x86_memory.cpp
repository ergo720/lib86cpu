/*
 * memory support
 *
 * ergo720                Copyright (c) 2019
 */

#include "x86_internal.h"
#include "x86_memory.h"
#include <assert.h>


static uint32_t
tlb_gen_access_mask(cpu_t *cpu, uint8_t user, uint8_t is_write)
{
	uint32_t mask;

	switch (user)
	{
	case 0:
		mask = is_write ? (TLB_SUP_READ | TLB_SUP_WRITE) : TLB_SUP_READ;
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

	memory_region_t<addr_t> *region = as_memory_search_addr<uint8_t>(cpu, phys_addr);
	if (region->type == MEM_RAM) {
		phys_addr -= region->start;
		prot |= TLB_RAM;
	}

	cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT] = (phys_addr & ~PAGE_MASK) | prot;
}

void
tlb_flush(cpu_t *cpu)
{
	for (uint32_t &tlb_entry : cpu->cpu_ctx.tlb) {
		tlb_entry = 0;
	}
}

void
tlb_flush(cpu_t *cpu, uint8_t dummy)
{
	for (uint32_t &tlb_entry : cpu->cpu_ctx.tlb) {
		if (!(tlb_entry & TLB_GLOBAL)) {
			tlb_entry = 0;
		}
	}
}

int8_t
check_page_access(cpu_t *cpu, uint8_t access_level, uint8_t mem_access)
{
	// 0 = access denied, 1 = access granted, -1 = error
	static const int8_t level_zero[7] = {
		1, -1, 0, -1, 0, -1, 0,
	};

	static const int8_t level_two[7] = {
		1, -1, 1, -1, 0, -1, 0,
	};

	// two rows because when wp flag of cr0 is 1, then supervisor cannot write to user read only pages
	static const int8_t level_four[2][7] = {
		{ 1, -1, 1, -1, 1, -1, 0 },
		{ 1, -1, 0, -1, 1, -1, 0 },
	};

	static const int8_t level_six[7] = {
		1, -1, 1, -1, 1, -1, 1,
	};

	int8_t access;

	switch (access_level)
	{
	case 0:
		access = level_zero[mem_access];
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
		LIB86CPU_ABORT_msg("Invalid access_level \"%c\" used in %s\n", access_level, __func__);
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

// NOTE: flags: bit 0 -> is_write, bit 1 -> is_priv, bit 4 -> is_code
addr_t
mmu_translate_addr(cpu_t *cpu, addr_t addr, uint8_t flags, uint32_t eip)
{
	uint8_t is_code = flags & TLB_CODE;

	if (!(cpu->cpu_ctx.regs.cr0 & CR0_PG_MASK)) {
		tlb_fill(cpu, addr, addr, TLB_SUP_READ | TLB_SUP_WRITE | TLB_USER_READ | TLB_USER_WRITE | is_code);
		return addr;
	}
	else {
		static const uint8_t cpl_to_page_priv[4] = { 0, 0, 0, 4 };

		uint8_t is_write = flags & 1;
		uint8_t is_priv = flags & 2;
		uint8_t err_code = 0;
		uint8_t cpu_lv = cpl_to_page_priv[cpu->cpu_ctx.hflags & HFLG_CPL];
		addr_t pte_addr = (cpu->cpu_ctx.regs.cr3 & CR3_PD_MASK) | (addr >> PAGE_SHIFT_LARGE) * 4;
		uint32_t pte = ram_read<uint32_t>(cpu, get_ram_host_ptr(cpu, cpu->pt_mr, pte_addr));

		if (!(pte & PTE_PRESENT)) {
			goto page_fault;
		}
		
		uint8_t mem_access = (is_write << 1) | ((cpu_lv >> is_priv) & 4);
		uint8_t pde_priv = (pte & PTE_WRITE) | (pte & PTE_USER);
		if ((pte & PTE_LARGE) && (cpu->cpu_ctx.regs.cr4 & CR4_PSE_MASK)) {
			if (check_page_access(cpu, pde_priv, mem_access)) {
				if (!(pte & PTE_ACCESSED) || is_write) {
					pte |= PTE_ACCESSED;
					if (is_write) {
						pte |= PTE_DIRTY;
					}
					ram_write<uint32_t>(cpu, get_ram_host_ptr(cpu, cpu->pt_mr, pte_addr), pte);
				}
				addr_t phys_addr = (pte & PTE_ADDR_4M) | (addr & PAGE_MASK_LARGE);
				tlb_fill(cpu, addr, phys_addr,
					tlb_gen_access_mask(cpu, pde_priv & PTE_USER, pde_priv & PTE_WRITE)
					| is_code | ((pte & PTE_GLOBAL) & ((cpu->cpu_ctx.regs.cr4 & CR4_PGE_MASK) << 1)));
				return phys_addr;
			}
			err_code = 1;
			goto page_fault;
		}

		pte_addr = (pte & PTE_ADDR_4K) | ((addr >> PAGE_SHIFT) & 0x3FF) * 4;
		pte = ram_read<uint32_t>(cpu, get_ram_host_ptr(cpu, cpu->pt_mr, pte_addr));

		if (!(pte & PTE_PRESENT)) {
			goto page_fault;
		}

		int8_t access_lv = check_page_privilege(cpu, pde_priv, (pte & PTE_WRITE) | (pte & PTE_USER));
		if (check_page_access(cpu, access_lv, mem_access)) {
			if (!(pte & PTE_ACCESSED) || is_write) {
				pte |= PTE_ACCESSED;
				if (is_write) {
					pte |= PTE_DIRTY;
				}
				ram_write<uint32_t>(cpu, get_ram_host_ptr(cpu, cpu->pt_mr, pte_addr), pte);
			}
			addr_t phys_addr = (pte & PTE_ADDR_4K) | (addr & PAGE_MASK);
			tlb_fill(cpu, addr, phys_addr,
				tlb_gen_access_mask(cpu, access_lv & PTE_USER, access_lv & PTE_WRITE)
				| is_code | ((pte & PTE_GLOBAL) & ((cpu->cpu_ctx.regs.cr4 & CR4_PGE_MASK) << 1)));
			return phys_addr;
		}
		err_code = 1;

	page_fault:
		exp_data_t exp_data { addr, err_code | (is_write << 1) | (cpu_lv >> 3), EXP_PF, eip };
		throw exp_data;
	}
}

addr_t
get_read_addr(cpu_t *cpu, addr_t addr, uint8_t is_priv, uint32_t eip)
{
	uint32_t tlb_entry = cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT];
	if ((tlb_access[0][(cpu->cpu_ctx.hflags & HFLG_CPL) >> is_priv]) ^ (tlb_entry & (tlb_access[0][(cpu->cpu_ctx.hflags & HFLG_CPL) >> is_priv]))) {
		return mmu_translate_addr(cpu, addr, is_priv, eip);
	}

	return (tlb_entry & ~PAGE_MASK) | (addr & PAGE_MASK);
}

addr_t
get_write_addr(cpu_t *cpu, addr_t addr, uint8_t is_priv, uint32_t eip, uint8_t *is_code)
{
	*is_code = 0;
	uint32_t tlb_entry = cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT];
	if ((tlb_access[1][(cpu->cpu_ctx.hflags & HFLG_CPL) >> is_priv]) ^ (tlb_entry & (tlb_access[1][(cpu->cpu_ctx.hflags & HFLG_CPL) >> is_priv]))) {
		return mmu_translate_addr(cpu, addr, 1 | is_priv, eip);
	}

	*is_code = tlb_entry & TLB_CODE;
	return (tlb_entry & ~PAGE_MASK) | (addr & PAGE_MASK);
}

addr_t
get_code_addr(cpu_t *cpu, addr_t addr, uint32_t eip)
{
	// this is only used for ram fetching, so we don't need to check for privileged accesses and is_write

	uint32_t tlb_entry = cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT];
	if ((tlb_access[0][cpu->cpu_ctx.hflags & HFLG_CPL]) ^ (tlb_entry & (tlb_access[0][cpu->cpu_ctx.hflags & HFLG_CPL]))) {
		return mmu_translate_addr(cpu, addr, TLB_CODE, eip);
	}

	cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT] = tlb_entry | TLB_CODE;
	return (tlb_entry & ~PAGE_MASK) | (addr & PAGE_MASK);
}

void
check_instr_length(cpu_t *cpu, addr_t start_pc, addr_t pc, size_t size)
{
	pc += size;
	if (pc - start_pc > X86_MAX_INSTR_LENGTH) {
		volatile addr_t addr = get_code_addr(cpu, pc - 1, start_pc - cpu->cpu_ctx.regs.cs_hidden.base);
		exp_data_t exp_data { 0, 0, EXP_GP, start_pc - cpu->cpu_ctx.regs.cs_hidden.base };
		throw exp_data;
	}
}

uint8_t
mem_read8(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_phys)
{
	return mem_read<uint8_t>(cpu_ctx->cpu, addr, eip, is_phys);
}

uint16_t
mem_read16(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_phys)
{
	return mem_read<uint16_t>(cpu_ctx->cpu, addr, eip, is_phys);
}

uint32_t
mem_read32(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_phys)
{
	return mem_read<uint32_t>(cpu_ctx->cpu, addr, eip, is_phys);
}

uint64_t
mem_read64(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_phys)
{
	return mem_read<uint64_t>(cpu_ctx->cpu, addr, eip, is_phys);
}

void
mem_write8(cpu_ctx_t *cpu_ctx, addr_t addr, uint8_t value, uint32_t eip, uint8_t is_phys, translated_code_t *tc)
{
	mem_write<uint8_t>(cpu_ctx->cpu, addr, value, eip, is_phys, tc);
}

void
mem_write16(cpu_ctx_t *cpu_ctx, addr_t addr, uint16_t value, uint32_t eip, uint8_t is_phys, translated_code_t *tc)
{
	mem_write<uint16_t>(cpu_ctx->cpu, addr, value, eip, is_phys, tc);
}

void
mem_write32(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t value, uint32_t eip, uint8_t is_phys, translated_code_t *tc)
{
	mem_write<uint32_t>(cpu_ctx->cpu, addr, value, eip, is_phys, tc);
}

void
mem_write64(cpu_ctx_t *cpu_ctx, addr_t addr, uint64_t value, uint32_t eip, uint8_t is_phys, translated_code_t *tc)
{
	mem_write<uint64_t>(cpu_ctx->cpu, addr, value, eip, is_phys, tc);
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
