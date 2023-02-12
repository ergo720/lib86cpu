/*
 * x87 fpu support
 *
 * ergo720                Copyright (c) 2023
 */

#include "internal.h"


void
fpu_init(cpu_t *cpu)
{
	// other fpu regs are already zeroed out by cpu_reset
	cpu->cpu_ctx.regs.fctrl = 0x40;
	cpu->cpu_ctx.fpu_data.ftop = 0;
	cpu->cpu_ctx.fpu_data.fes = 0;
	cpu->cpu_ctx.fpu_data.frp = cpu->cpu_ctx.regs.fctrl | FPU_EXP_ALL;
	for (auto &tag : cpu->cpu_ctx.regs.ftags) {
		tag = FPU_TAG_ZERO;
	}
}

void
fpu_update_tag(cpu_ctx_t *cpu_ctx, uint32_t idx)
{
	uint16_t exp = cpu_ctx->regs.fr[idx].high & 0x7FFF;
	uint64_t mant = cpu_ctx->regs.fr[idx].low;
	if (exp == 0 && mant == 0) { // zero
		cpu_ctx->regs.ftags[idx] = FPU_TAG_ZERO;
	}
	else if ((exp == 0) || // denormal
		(exp == 0x7FFF) || // NaN or infinity
		((mant & (1ULL << 63)) == 0)) { // unnormal
		cpu_ctx->regs.ftags[idx] = FPU_TAG_SPECIAL;
	}
	else { // normal
		cpu_ctx->regs.ftags[idx] = FPU_TAG_VALID;
	}
}
