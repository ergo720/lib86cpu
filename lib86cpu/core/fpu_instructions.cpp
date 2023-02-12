/*
 * fpu instruction helpers
 *
 * ergo720                Copyright (c) 2023
 */

#include "instructions.h"


void
fxsave_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip)
{
	mem_write_helper<uint16_t>(cpu_ctx, addr, cpu_ctx->regs.fctrl, eip, 0);
	addr += 2;
	mem_write_helper<uint16_t>(cpu_ctx, addr, read_fstatus(cpu_ctx->cpu), eip, 0);
	addr += 2;
	uint8_t ftag_abridged = 0;
	for (unsigned i = 0; i < 8; ++i) {
		ftag_abridged |= (((cpu_ctx->regs.ftags[i] == FPU_TAG_EMPTY) ? 0 : 1) << i);
	}
	mem_write_helper<uint8_t>(cpu_ctx, addr, ftag_abridged, eip, 0);
	addr += 2;
	mem_write_helper<uint16_t>(cpu_ctx, addr, cpu_ctx->regs.fop, eip, 0);
	addr += 2;
	mem_write_helper<uint32_t>(cpu_ctx, addr, cpu_ctx->regs.fip, eip, 0);
	addr += 4;
	mem_write_helper<uint16_t>(cpu_ctx, addr, cpu_ctx->regs.fcs, eip, 0);
	addr += 4;
	mem_write_helper<uint32_t>(cpu_ctx, addr, cpu_ctx->regs.fdp, eip, 0);
	addr += 4;
	mem_write_helper<uint16_t>(cpu_ctx, addr, cpu_ctx->regs.fds, eip, 0);
	addr += 4;
	if (cpu_ctx->hflags & HFLG_CR4_OSFXSR) {
		mem_write_helper<uint32_t>(cpu_ctx, addr, cpu_ctx->regs.mxcsr, eip, 0);
		addr += 4;
		mem_write_helper<uint32_t>(cpu_ctx, addr, 0, eip, 0);
		addr += 4;
	}
	else {
		addr += 8;
	}
	for (unsigned i = 0; i < 8; ++i) {
		mem_write_helper<uint80_t>(cpu_ctx, addr, cpu_ctx->regs.fr[i], eip, 0);
		addr += 16;
	}
	if (cpu_ctx->hflags & HFLG_CR4_OSFXSR) {
		for (unsigned i = 0; i < 8; ++i) {
			mem_write_helper<uint128_t>(cpu_ctx, addr, cpu_ctx->regs.xmm[i], eip, 0);
			addr += 16;
		}
	}
}

uint32_t
fxrstor_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip)
{
	// must be 16 byte aligned
	if (addr & 15) {
		return 1;
	}

	// PF check for the first and last byte we are going to read
	volatile addr_t pf_check1 = get_read_addr(cpu_ctx->cpu, addr, 0, eip);
	volatile addr_t pf_check2 = get_read_addr(cpu_ctx->cpu, addr + 288 - 1, 0, eip);

	// check reserved bits of mxcsr
	if (cpu_ctx->hflags & HFLG_CR4_OSFXSR) {
		uint32_t temp = mem_read_helper<uint32_t>(cpu_ctx, addr + 24, eip, 0);
		if (temp & ~MXCSR_MASK) {
			return 1;
		}
		cpu_ctx->regs.mxcsr = temp;
	}

	cpu_ctx->regs.fctrl = mem_read_helper<uint16_t>(cpu_ctx, addr, eip, 0) | 0x40;
	cpu_ctx->fpu_data.frp = cpu_ctx->regs.fctrl | FPU_EXP_ALL | 0x40;
	addr += 2;
	write_fstatus(cpu_ctx->cpu, mem_read_helper<uint16_t>(cpu_ctx, addr, eip, 0));
	addr += 2;
	uint8_t ftag_abridged = mem_read_helper<uint8_t>(cpu_ctx, addr, eip, 0);
	addr += 2;
	cpu_ctx->regs.fop = mem_read_helper<uint16_t>(cpu_ctx, addr, eip, 0);
	addr += 2;
	cpu_ctx->regs.fip = mem_read_helper<uint32_t>(cpu_ctx, addr, eip, 0);
	addr += 4;
	cpu_ctx->regs.fcs = mem_read_helper<uint16_t>(cpu_ctx, addr, eip, 0);
	addr += 4;
	cpu_ctx->regs.fdp = mem_read_helper<uint32_t>(cpu_ctx, addr, eip, 0);
	addr += 4;
	cpu_ctx->regs.fds = mem_read_helper<uint16_t>(cpu_ctx, addr, eip, 0);
	addr += (4 + 8);
	for (unsigned i = 0; i < 8; ++i) {
		cpu_ctx->regs.fr[i] = mem_read_helper<uint80_t>(cpu_ctx, addr, eip, 0);
		addr += 16;
	}
	if (cpu_ctx->hflags & HFLG_CR4_OSFXSR) {
		for (unsigned i = 0; i < 8; ++i) {
			cpu_ctx->regs.xmm[i] = mem_read_helper<uint128_t>(cpu_ctx, addr, eip, 0);
			addr += 16;
		}
	}
	for (unsigned i = 0; i < 8; ++i) {
		if (!(ftag_abridged & (1 << i))) { // empty
			cpu_ctx->regs.ftags[i] = FPU_TAG_EMPTY;
		}
		else {
			uint16_t exp = cpu_ctx->regs.fr[i].high & 0x7FFF;
			uint64_t mant = cpu_ctx->regs.fr[i].low;
			if (exp == 0 && mant == 0) { // zero
				cpu_ctx->regs.ftags[i] = FPU_TAG_ZERO;
			}
			else if ((exp == 0) || // denormal
				(exp == 0x7FFF) || // NaN or infinity
				((mant & (1ULL << 63)) == 0)) { // unnormal
				cpu_ctx->regs.ftags[i] = FPU_TAG_SPECIAL;
			}
			else { // normal
				cpu_ctx->regs.ftags[i] = FPU_TAG_VALID;
			}
		}
	}

	return 0;
}
