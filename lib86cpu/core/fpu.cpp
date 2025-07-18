/*
 * x87 fpu support
 *
 * ergo720                Copyright (c) 2023
 */

#include "internal.h"
#include "memory_management.h"


void
fpu_init(cpu_t *cpu)
{
	// other fpu regs are already zeroed out by cpu_reset
	cpu->cpu_ctx.regs.fctrl = 0x40;
	cpu->cpu_ctx.regs.fstatus = 0;
	cpu->cpu_ctx.fpu_data.ftop = 0;
	cpu->cpu_ctx.fpu_data.frp = cpu->cpu_ctx.regs.fctrl | FPU_EXP_ALL;
	for (auto &tag : cpu->cpu_ctx.regs.ftags) {
		tag = FPU_TAG_ZERO;
	}
}

static void
fpu_push(cpu_ctx_t *cpu_ctx)
{
	cpu_ctx->fpu_data.ftop = (cpu_ctx->fpu_data.ftop - 1) & 7;
}

static void
fpu_pop(cpu_ctx_t *cpu_ctx)
{
	cpu_ctx->regs.ftags[cpu_ctx->fpu_data.ftop] = FPU_TAG_EMPTY;
	cpu_ctx->fpu_data.ftop = (cpu_ctx->fpu_data.ftop + 1) & 7;
}

template<bool is_push>
void fpu_update_tag(cpu_ctx_t *cpu_ctx, uint32_t st_num)
{
	uint32_t idx = (st_num + cpu_ctx->fpu_data.ftop) & 7;
	if constexpr (is_push) {
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
	else {
		cpu_ctx->regs.ftags[idx] = FPU_TAG_EMPTY;
	}
}

static bool
fpu_is_tag_empty(cpu_ctx_t *cpu_ctx, uint32_t st_num)
{
	return cpu_ctx->regs.ftags[(st_num + cpu_ctx->fpu_data.ftop) & 7] == FPU_TAG_EMPTY;
}

void
fpu_update_ptr(cpu_ctx_t *cpu_ctx, uint64_t instr_info)
{
	cpu_ctx->regs.fcs = cpu_ctx->regs.cs;
	cpu_ctx->regs.fip = cpu_ctx->regs.eip;
	cpu_ctx->regs.fop = ((instr_info >> 48) & 0x7FF);
	if (instr_info & (1ULL << 63)) {
		cpu_ctx->regs.fds = *(uint16_t *)(((instr_info >> 32) & 0xFFFF) + (uint8_t *)cpu_ctx);
		cpu_ctx->regs.fdp = instr_info & 0xFFFFFFFF;
	}
}

static void
fpu_stack_fault(cpu_ctx_t *cpu_ctx, uint32_t exception)
{
	assert(exception & FPU_EXP_INVALID);

	exception &= (FPU_EXP_ALL | FPU_SW_SF | FPU_SW_C1);
	uint32_t unmasked = (exception & ~cpu_ctx->regs.fctrl) & FPU_EXP_ALL;
	if (unmasked) {
		cpu_ctx->regs.fstatus |= FPU_SW_ES;
	}

	cpu_ctx->regs.fstatus |= exception;
	if (exception & FPU_SW_SF) {
		if (!(exception & FPU_SW_C1)) {
			cpu_ctx->regs.fstatus &= ~FPU_SW_C1;
		}
	}
}

uint32_t
fpu_stack_overflow(cpu_ctx_t *cpu_ctx)
{
	if (fpu_is_tag_empty(cpu_ctx, -1) == false) {
		if (cpu_ctx->regs.fctrl & FPU_EXP_INVALID) {
			// masked stack fault response
			fpu_push(cpu_ctx);
			uint32_t idx = cpu_ctx->fpu_data.ftop; // always pushes to st0
			cpu_ctx->regs.fr[idx].low = FPU_QNAN_FLOAT80_LOW;
			cpu_ctx->regs.fr[idx].high = FPU_QNAN_FLOAT80_HIGH;
			cpu_ctx->regs.ftags[idx] = FPU_TAG_SPECIAL;
		}

		fpu_stack_fault(cpu_ctx, FPU_STACK_OVERFLOW);

		return 1;
	}

	return 0;
}

uint32_t
fpu_stack_underflow_reg(cpu_ctx_t *cpu_ctx, uint32_t st_num_src, uint32_t st_num_dst, uint32_t should_pop)
{
	// checks for stack underflow when the destination is a register

	if (fpu_is_tag_empty(cpu_ctx, st_num_src)) {
		if (cpu_ctx->regs.fctrl & FPU_EXP_INVALID) {
			// masked stack fault response
			uint32_t idx = (st_num_dst + cpu_ctx->fpu_data.ftop) & 7;
			cpu_ctx->regs.fr[idx].low = FPU_QNAN_FLOAT80_LOW;
			cpu_ctx->regs.fr[idx].high = FPU_QNAN_FLOAT80_HIGH;
			cpu_ctx->regs.ftags[idx] = FPU_TAG_SPECIAL;
			if (should_pop) {
				fpu_pop(cpu_ctx);
			}
		}

		fpu_stack_fault(cpu_ctx, FPU_STACK_UNDERFLOW);

		return 1;
	}

	return 0;
}

template<typename T, T qnan>
uint32_t fpu_stack_underflow_mem(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t st_num_src, uint32_t should_pop)
{
	// checks for stack underflow when the destination is a memory location

	if (fpu_is_tag_empty(cpu_ctx, st_num_src)) {
		if (cpu_ctx->regs.fctrl & FPU_EXP_INVALID) {
			// masked stack fault response
			mem_write_helper<T>(cpu_ctx, addr, qnan, 0);
			if (should_pop) {
				fpu_pop(cpu_ctx);
			}
		}

		fpu_stack_fault(cpu_ctx, FPU_STACK_UNDERFLOW);

		return 1;
	}

	return 0;
}

template JIT_API void fpu_update_tag<true>(cpu_ctx_t *cpu_ctx, uint32_t idx);
template JIT_API void fpu_update_tag<false>(cpu_ctx_t *cpu_ctx, uint32_t idx);
template JIT_API uint32_t fpu_stack_underflow_mem<uint16_t, FPU_QNAN_INT16>(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t st_num_src, uint32_t should_pop);
template JIT_API uint32_t fpu_stack_underflow_mem<uint32_t, FPU_QNAN_INT32>(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t st_num_src, uint32_t should_pop);
template JIT_API uint32_t fpu_stack_underflow_mem<uint32_t, FPU_QNAN_FLOAT32>(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t st_num_src, uint32_t should_pop);
template JIT_API uint32_t fpu_stack_underflow_mem<uint64_t, FPU_QNAN_INT64>(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t st_num_src, uint32_t should_pop);
template JIT_API uint32_t fpu_stack_underflow_mem<uint64_t, FPU_QNAN_FLOAT64>(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t st_num_src, uint32_t should_pop);
template JIT_API uint32_t fpu_stack_underflow_mem<uint80_t, uint80_t{FPU_QNAN_FLOAT80_LOW, FPU_QNAN_FLOAT80_HIGH}>(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t st_num_src, uint32_t should_pop);
