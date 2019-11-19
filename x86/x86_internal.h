/*
 * x86 function prototypes and internal variables
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once

#include "x86_decode.h"

void cpu_x86_init(cpu_t *cpu);
lib86cpu_status cpu_exec_tc(cpu_t *cpu);
int disasm_instr(cpu_t *cpu, addr_t pc, x86_instr *instr, char *line, unsigned int max_line);
int decode_instr(cpu_t *cpu, x86_instr *instr, addr_t pc);

extern cpu_t *cpu_copy;
extern const char *mnemo[];

// reg indexes in cpu->regs_layout
#define EAX_idx     0
#define ECX_idx     1
#define EDX_idx     2
#define EBX_idx     3
#define ESP_idx     4
#define EBP_idx     5
#define ESI_idx     6
#define EDI_idx     7
#define ES_idx      8
#define CS_idx      9
#define SS_idx      10
#define DS_idx      11
#define FS_idx      12
#define GS_idx      13
#define CR0_idx     14
#define CR1_idx     15
#define CR2_idx     16
#define CR3_idx     17
#define CR4_idx     18
#define DR0_idx     19
#define DR1_idx     20
#define DR2_idx     21
#define DR3_idx     22
#define DR4_idx     23
#define DR5_idx     24
#define DR6_idx     25
#define DR7_idx     26
#define EFLAGS_idx  27
#define EIP_idx     28

#define SEG_offset  8

#define SEG_SEL_idx     0
#define SEG_HIDDEN_idx  1
#define SEG_BASE_idx    0

#define CRO_PE_SHIFT 0
#define CR0_PE_MASK (1 << CRO_PE_SHIFT)

#define R_CR0 cpu->regs.cr0

#define CPU_PE_MODE (R_CR0 & CR0_PE_MASK)
