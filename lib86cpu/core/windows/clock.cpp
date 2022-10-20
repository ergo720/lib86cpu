/*
 * cpu clock
 *
 * ergo720                Copyright (c) 2021
 */

#include "clock.h"
#include "Windows.h"


void
tsc_init(cpu_t *cpu)
{
	LARGE_INTEGER freq, now;
	QueryPerformanceFrequency(&freq);
	cpu->clock.host_freq = freq.QuadPart;
	QueryPerformanceCounter(&now);
	cpu->clock.last_host_ticks = now.QuadPart;
}

void
cpu_rdtsc_handler(cpu_ctx_t *cpu_ctx)
{
	LARGE_INTEGER now;
	QueryPerformanceCounter(&now);
	uint64_t elapsed_ns = static_cast<uint64_t>(now.QuadPart) - cpu_ctx->cpu->clock.last_host_ticks;
	cpu_ctx->cpu->clock.last_host_ticks = now.QuadPart;
	elapsed_ns *= 1000000000;
	elapsed_ns /= cpu_ctx->cpu->clock.host_freq;
	uint64_t elapsed_ticks = elapsed_ns / 1000000000;
	elapsed_ticks *= cpu_ctx->cpu->clock.freq;
	cpu_ctx->cpu->clock.tsc += elapsed_ticks;
	cpu_ctx->regs.edx = (cpu_ctx->cpu->clock.tsc >> 32);
	cpu_ctx->regs.eax = cpu_ctx->cpu->clock.tsc;
}
