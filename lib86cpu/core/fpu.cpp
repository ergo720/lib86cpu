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
	cpu->cpu_ctx.fpu_data.ftss = 0;
	cpu->cpu_ctx.fpu_data.fes = 0;
	cpu->cpu_ctx.regs.fctrl = 0x40;
	for (auto &tag : cpu->cpu_ctx.regs.ftags) {
		tag = FPU_TAG_ZERO;
	}

	// match host fpu control word to guest, but leave fpu exceptions masked
	cpu->set_fctrl_fn(FPU_EXP_ALL | (FPU_SINGLE_PRECISION << 8) | (FPU_ROUND_NEAR << 10) | 0x40);
}
