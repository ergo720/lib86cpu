/*
 * x86 debug watchpoint exports
 *
 * ergo720                Copyright (c) 2021
 */

#pragma once


void cpu_check_data_watchpoints(cpu_t *cpu, addr_t addr, size_t size, int type, uint32_t eip);
