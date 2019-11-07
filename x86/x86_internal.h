/*
 * x86 fuunction prototypes and internal variables
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#pragma once

x86cpu_status cpu_x86_init(cpu_t *cpu);

#define CRO_PE_SHIFT 0
#define CR0_PE_MASK (1 << CRO_PE_SHIFT)

#define R_CR0 cpu->gpr.cr0

#define CPU_PE_MODE (R_CR0 & CR0_PE_MASK)
