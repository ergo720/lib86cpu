/*
 * cpu tsc clock and host timer
 *
 * ergo720                Copyright (c) 2021
 */

#include "clock.h"
#include "internal.h"
#include "Windows.h"


uint64_t
get_current_time()
{
	LARGE_INTEGER now;
	QueryPerformanceCounter(&now);
	return static_cast<uint64_t>(now.QuadPart);
}

void
tsc_init(cpu_t *cpu)
{
	LARGE_INTEGER freq;
	QueryPerformanceFrequency(&freq);
	cpu->timer.host_freq = freq.QuadPart;
	cpu->tsc_clock.last_host_ticks = get_current_time();
}

void
cpu_rdtsc_helper(cpu_ctx_t *cpu_ctx)
{
	uint64_t elapsed_us = get_current_time() - cpu_ctx->cpu->tsc_clock.last_host_ticks;
	elapsed_us = muldiv128(elapsed_us, cpu_ctx->cpu->tsc_clock.cpu_freq, cpu_ctx->cpu->timer.host_freq) + cpu_ctx->cpu->tsc_clock.offset;
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
	uint64_t elapsed_us = get_current_time() - cpu_ctx->cpu->timer.last_time;
	elapsed_us *= 1000000;
	elapsed_us /= cpu_ctx->cpu->timer.host_freq;
	if (elapsed_us >= cpu_ctx->cpu->timer.timeout_time) {
		cpu_ctx->cpu->exit_requested = true;
		return CPU_TIMEOUT_INT;
	}

	return CPU_NO_INT;
}
