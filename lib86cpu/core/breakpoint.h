/*
 * x86 debug watchpoint exports
 *
 * ergo720                Copyright (c) 2021
 */

#pragma once


void cpu_check_data_watchpoints(cpu_t *cpu, addr_t addr, size_t size, int type, uint32_t eip);
void cpu_check_io_watchpoints(cpu_t *cpu, port_t port, size_t size, int type, uint32_t eip);
bool cpu_check_watchpoint_enabled(cpu_t *cpu, int idx);
int cpu_get_watchpoint_type(cpu_t *cpu, int idx);
size_t cpu_get_watchpoint_lenght(cpu_t *cpu, int idx);
