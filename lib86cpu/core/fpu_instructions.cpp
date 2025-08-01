/*
 * fpu instruction helpers
 *
 * ergo720                Copyright (c) 2023
 */

#include "instructions.h"


void
fxsave_helper(cpu_ctx_t *cpu_ctx, addr_t addr)
{
	mem_write_helper<uint16_t>(cpu_ctx, addr, cpu_ctx->regs.fctrl, 0);
	mem_write_helper<uint16_t>(cpu_ctx, addr + 2, read_fstatus(cpu_ctx->cpu), 0);
	uint8_t ftag_abridged = 0;
	for (unsigned i = 0; i < 8; ++i) {
		ftag_abridged |= (((cpu_ctx->regs.ftags[i] == FPU_TAG_EMPTY) ? 0 : 1) << i);
	}
	mem_write_helper<uint8_t>(cpu_ctx, addr + 4, ftag_abridged, 0);
	mem_write_helper<uint16_t>(cpu_ctx, addr + 6, cpu_ctx->regs.fop, 0);
	mem_write_helper<uint32_t>(cpu_ctx, addr + 8, cpu_ctx->regs.fip, 0);
	mem_write_helper<uint16_t>(cpu_ctx, addr + 12, cpu_ctx->regs.fcs, 0);
	mem_write_helper<uint32_t>(cpu_ctx, addr + 16, cpu_ctx->regs.fdp, 0);
	mem_write_helper<uint16_t>(cpu_ctx, addr + 20, cpu_ctx->regs.fds, 0);
	if (cpu_ctx->hflags & HFLG_CR4_OSFXSR) {
		mem_write_helper<uint32_t>(cpu_ctx, addr + 24, cpu_ctx->regs.mxcsr, 0);
		mem_write_helper<uint32_t>(cpu_ctx, addr + 28, MXCSR_MASK, 0);
	}
	for (unsigned i = 0; i < 8; ++i) {
		mem_write_helper<uint80_t>(cpu_ctx, addr + 32 + 16 * i, cpu_ctx->regs.fr[i], 0);
	}
	if (cpu_ctx->hflags & HFLG_CR4_OSFXSR) {
		for (unsigned i = 0; i < 8; ++i) {
			mem_write_helper<uint128_t>(cpu_ctx, addr + 160 + 16 * i, cpu_ctx->regs.xmm[i], 0);
		}
	}
}

uint32_t
fxrstor_helper(cpu_ctx_t *cpu_ctx, addr_t addr)
{
	// must be 16 byte aligned
	if (addr & 15) {
		return 1;
	}

	// PF check for the first and last byte we are going to read
	volatile addr_t pf_check1 = get_read_addr(cpu_ctx->cpu, addr, 0);
	volatile addr_t pf_check2 = get_read_addr(cpu_ctx->cpu, addr + 288 - 1, 0);

	// check reserved bits of mxcsr
	if (cpu_ctx->hflags & HFLG_CR4_OSFXSR) {
		uint32_t temp = mem_read_helper<uint32_t>(cpu_ctx, addr + 24, 0);
		if (temp & ~MXCSR_MASK) {
			return 1;
		}
		cpu_ctx->regs.mxcsr = temp;
		cpu_ctx->shadow_mxcsr = (temp | (MXCSR_EXP_ALL << 7)) & ~MXCSR_EXP_ALL; // daz must be zero already because of the above check done with MXCSR_MASK
	}

	cpu_ctx->regs.fctrl = (mem_read_helper<uint16_t>(cpu_ctx, addr, 0) | 0x40);
	cpu_ctx->fpu_data.frp = cpu_ctx->regs.fctrl | FPU_EXP_ALL;
	write_fstatus(cpu_ctx->cpu, mem_read_helper<uint16_t>(cpu_ctx, addr + 2, 0));
	uint8_t ftag_abridged = mem_read_helper<uint8_t>(cpu_ctx, addr + 4, 0);
	cpu_ctx->regs.fop = (mem_read_helper<uint16_t>(cpu_ctx, addr + 6, 0) & 0x7FF);
	cpu_ctx->regs.fip = mem_read_helper<uint32_t>(cpu_ctx, addr + 8, 0);
	cpu_ctx->regs.fcs = mem_read_helper<uint16_t>(cpu_ctx, addr + 12, 0);
	cpu_ctx->regs.fdp = mem_read_helper<uint32_t>(cpu_ctx, addr + 16, 0);
	cpu_ctx->regs.fds = mem_read_helper<uint16_t>(cpu_ctx, addr + 20, 0);
	for (unsigned i = 0; i < 8; ++i) {
		cpu_ctx->regs.fr[i] = mem_read_helper<uint80_t>(cpu_ctx, addr + 32 + 16 * i, 0);
	}
	if (cpu_ctx->hflags & HFLG_CR4_OSFXSR) {
		for (unsigned i = 0; i < 8; ++i) {
			cpu_ctx->regs.xmm[i] = mem_read_helper<uint128_t>(cpu_ctx, addr + 160 + 16 * i, 0);
		}
	}
	uint16_t temp_ftop = cpu_ctx->fpu_data.ftop;
	cpu_ctx->fpu_data.ftop = 0; // set ftop to zero so that we can use fpu_update_tag below
	for (unsigned i = 0; i < 8; ++i) {
		if (!(ftag_abridged & (1 << i))) { // empty
			fpu_update_tag<false>(cpu_ctx, i);
		}
		else {
			fpu_update_tag<true>(cpu_ctx, i);
		}
	}
	cpu_ctx->fpu_data.ftop = temp_ftop;

	return 0;
}
