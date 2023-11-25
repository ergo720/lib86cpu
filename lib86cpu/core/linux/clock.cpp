/*
 * cpu tsc clock and host timer
 *
 * ergo720                Copyright (c) 2023
 */

#include "clock.h"
#include "internal.h"
#include <time.h>


uint64_t
get_current_time()
{
	timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

void
tsc_init(cpu_t *cpu)
{
	cpu->timer.host_freq = 0;
	cpu->tsc_clock.last_host_ticks = get_current_time();
}

void
cpu_rdtsc_helper(cpu_ctx_t *cpu_ctx)
{
	uint64_t elapsed_us = get_current_time() - cpu_ctx->cpu->tsc_clock.last_host_ticks;
	elapsed_us = muldiv128(elapsed_us, cpu_ctx->cpu->tsc_clock.cpu_freq, 1000000) + cpu_ctx->cpu->tsc_clock.offset;
	cpu_ctx->regs.edx = (elapsed_us >> 32);
	cpu_ctx->regs.eax = elapsed_us;
}

void
cpu_timer_set_now(cpu_t *cpu)
{
	cpu->timer.last_time = get_current_time();
}

uint32_t
cpu_timer_helper(cpu_ctx_t *cpu_ctx)
{
	// always check for interrupts first. Otherwise, if the cpu consistently timeouts at every code block, it will never check for interrupts
	if (uint32_t ret = cpu_do_int(cpu_ctx, cpu_ctx->cpu->read_int_fn(cpu_ctx))) {
		return ret;
	}

	uint64_t elapsed_us = get_current_time() - cpu_ctx->cpu->timer.last_time;
	if (elapsed_us >= cpu_ctx->cpu->timer.timeout_time) {
		return CPU_TIMEOUT_INT;
	}

	return CPU_NO_INT;
}
