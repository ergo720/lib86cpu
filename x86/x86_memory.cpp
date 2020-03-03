/*
 * memory support
 *
 * ergo720                Copyright (c) 2019
 */

#include "x86_internal.h"
#include "x86_memory.h"
#include <assert.h>


int8_t
check_page_access(cpu_t *cpu, uint8_t access_level, uint8_t cpu_level)
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
		access = level_zero[cpu_level];
		break;

	case 2:
		access = level_two[cpu_level];
		break;

	case 4:
		access = level_four[(cpu->cpu_ctx.regs.cr0 & CR0_WP_MASK) >> 16][cpu_level];
		break;

	case 6:
		access = level_six[cpu_level];
		break;

	default:
		LIB86CPU_ABORT_msg("Invalid access_level \"%c\" used in %s\n", access_level, __func__);
	}

	assert(access != -1);

	return access;
}

int8_t
check_page_privilege(cpu_t *cpu, uint8_t cpu_level, uint8_t pde_priv, uint8_t pte_priv)
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

	return check_page_access(cpu, access_lv, cpu_level);
}

addr_t
mmu_translate_addr(cpu_t *cpu, addr_t addr, uint8_t is_write, uint32_t eip)
{
	if (!(cpu->cpu_ctx.regs.cr0 & CR0_PG_MASK)) {
		return addr;
	}
	else {
		static const uint8_t cpl_to_page_priv[4] = { 0, 0, 0, 1 << CPL_PRIV_SHIFT };

		uint32_t err_code = 0;
		addr_t pte_addr = (cpu->cpu_ctx.regs.cr3 & CR3_PD_MASK) | (addr >> PAGE_SHIFT_LARGE) * 4;
		uint32_t pte = ram_read<uint32_t>(cpu, get_ram_host_ptr(cpu, cpu->pt_mr, pte_addr));

		if (!(pte & PTE_PRESENT)) {
			goto page_fault;
		}

		uint8_t cpu_lv = (is_write << 1) | ((cpl_to_page_priv[cpu->cpu_ctx.hflags & HFLG_CPL] & (cpu->cpu_ctx.hflags & HFLG_CPL_PRIV)) >> 3);
		uint8_t pde_priv = (pte & PTE_WRITE) | (pte & PTE_USER);
		if ((pte & PTE_LARGE) && (cpu->cpu_ctx.regs.cr4 & CR4_PSE_MASK)) {
			if (check_page_access(cpu, pde_priv, cpu_lv)) {
				if (!(pte & PTE_ACCESSED) || is_write) {
					pte |= PTE_ACCESSED;
					if (is_write) {
						pte |= PTE_DIRTY;
					}
					ram_write<uint32_t>(cpu, get_ram_host_ptr(cpu, cpu->pt_mr, pte_addr), pte);
				}
				return (pte & PTE_ADDR_4M) | (addr & PAGE_MASK_LARGE);
			}
			err_code = 1;
			goto page_fault;
		}

		pte_addr = (pte & PTE_ADDR_4K) | ((addr >> PAGE_SHIFT) & 0x3FF) * 4;
		pte = ram_read<uint32_t>(cpu, get_ram_host_ptr(cpu, cpu->pt_mr, pte_addr));

		if (!(pte & PTE_PRESENT)) {
			goto page_fault;
		}

		if (check_page_privilege(cpu, cpu_lv, pde_priv, (pte & PTE_WRITE) | (pte & PTE_USER))) {
			if (!(pte & PTE_ACCESSED) || is_write) {
				pte |= PTE_ACCESSED;
				if (is_write) {
					pte |= PTE_DIRTY;
				}
				ram_write<uint32_t>(cpu, get_ram_host_ptr(cpu, cpu->pt_mr, pte_addr), pte);
			}
			return (pte & PTE_ADDR_4K) | (addr & PAGE_MASK);
		}
		err_code = 1;

	page_fault:
		cpu->cpu_ctx.hflags |= HFLG_CPL_PRIV;
		cpu->exp_fault_addr = addr;
		cpu->exp_idx = EXP_PF;
		cpu->exp_code = err_code | (is_write << 1) | (cpl_to_page_priv[cpu->cpu_ctx.hflags & HFLG_CPL] >> 3);
		throw eip;
	}
}

void
check_instr_length(cpu_t *cpu, addr_t start_pc, addr_t pc, size_t size)
{
	pc += size;
	if (pc - start_pc > X86_MAX_INSTR_LENGTH) {
		volatile addr_t addr = mmu_translate_addr(cpu, pc - 1, 0, start_pc - cpu->cpu_ctx.regs.cs_hidden.base);
		cpu->exp_idx = EXP_GP;
		cpu->exp_code = 0;
		throw start_pc - cpu->cpu_ctx.regs.cs_hidden.base;
	}
}

uint8_t
mem_read8(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip)
{
	return mem_read<uint8_t>(cpu_ctx->cpu, addr, eip);
}

uint16_t
mem_read16(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip)
{
	return mem_read<uint16_t>(cpu_ctx->cpu, addr, eip);
}

uint32_t
mem_read32(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip)
{
	return mem_read<uint32_t>(cpu_ctx->cpu, addr, eip);
}

uint64_t
mem_read64(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip)
{
	return mem_read<uint64_t>(cpu_ctx->cpu, addr, eip);
}

void
mem_write8(cpu_ctx_t *cpu_ctx, addr_t addr, uint8_t value, uint32_t eip)
{
	mem_write<uint8_t>(cpu_ctx->cpu, addr, value, eip);
}

void
mem_write16(cpu_ctx_t *cpu_ctx, addr_t addr, uint16_t value, uint32_t eip)
{
	mem_write<uint16_t>(cpu_ctx->cpu, addr, value, eip);
}

void
mem_write32(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t value, uint32_t eip)
{
	mem_write<uint32_t>(cpu_ctx->cpu, addr, value, eip);
}

void
mem_write64(cpu_ctx_t *cpu_ctx, addr_t addr, uint64_t value, uint32_t eip)
{
	mem_write<uint64_t>(cpu_ctx->cpu, addr, value, eip);
}

uint8_t
io_read8(cpu_ctx_t *cpu_ctx, port_t port, uint32_t eip)
{
	return io_read<uint8_t>(cpu_ctx->cpu, port);
}

uint16_t
io_read16(cpu_ctx_t *cpu_ctx, port_t port, uint32_t eip)
{
	return io_read<uint16_t>(cpu_ctx->cpu, port);
}

uint32_t
io_read32(cpu_ctx_t *cpu_ctx, port_t port, uint32_t eip)
{
	return io_read<uint32_t>(cpu_ctx->cpu, port);
}

void
io_write8(cpu_ctx_t *cpu_ctx, port_t port, uint8_t value, uint32_t eip)
{
	io_write<uint8_t>(cpu_ctx->cpu, port, value);
}

void
io_write16(cpu_ctx_t *cpu_ctx, port_t port, uint16_t value, uint32_t eip)
{
	io_write<uint16_t>(cpu_ctx->cpu, port, value);
}

void
io_write32(cpu_ctx_t *cpu_ctx, port_t port, uint32_t value, uint32_t eip)
{
	io_write<uint32_t>(cpu_ctx->cpu, port, value);
}
