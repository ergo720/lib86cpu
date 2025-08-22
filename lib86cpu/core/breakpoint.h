/*
 * x86 debug watchpoint exports
 *
 * ergo720                Copyright (c) 2021
 */

#pragma once


void cpu_check_data_watchpoints(cpu_t *cpu, addr_t addr, uint32_t size, int type);
void cpu_check_io_watchpoints(cpu_t *cpu, port_t port, uint32_t size, int type);
bool cpu_check_watchpoint_enabled(cpu_t *cpu, unsigned idx);
uint32_t cpu_get_watchpoint_type(cpu_t *cpu, unsigned idx);
uint32_t cpu_get_watchpoint_length(cpu_t *cpu, unsigned idx);
