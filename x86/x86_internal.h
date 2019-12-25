/*
 * x86 function prototypes and internal variables
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once

#include "x86_decode.h"

void cpu_x86_init(cpu_t *cpu);
lib86cpu_status cpu_exec_tc(cpu_t *cpu);
void tc_protect(void* addr, size_t size, bool ro);
int disasm_instr(cpu_t *cpu, addr_t pc, x86_instr *instr, char *line, unsigned int max_line);
int decode_instr(cpu_t *cpu, x86_instr *instr, addr_t pc);
JIT_EXTERNAL_CALL_C void cpu_raise_exception(uint8_t *cpu2, uint8_t expno, uint32_t eip);

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
#define IDTR_idx    29

#define CF_shift    0
#define PF_shift    2
#define AF_shift    4
#define ZF_shift    6
#define SF_shift    7
#define TF_shift    8
#define IF_shift    9
#define DF_shift    10
#define OF_shift    11
#define IOPL_shift  12
#define NT_shift    14
#define RF_shift    16
#define VM_shift    17
#define AC_shift    18
#define VIF_shift   19
#define VIP_shift   20
#define ID_shift    21
#define TF_MASK     (1 << TF_shift)
#define IF_MASK     (1 << IF_shift)
#define DF_MASK     (1 << DF_shift)
#define RF_MASK     (1 << RF_shift)
#define AC_MASK     (1 << AC_shift)

// exception numbers
#define EXP_DE  0   // divide error
#define EXP_DB  1   // debug
#define EXP_NMI 2   // non-maskable interrupt
#define EXP_BP  3   // breakpoint
#define EXP_OF  4   // overflow
#define EXP_BR  5   // bound range exceeded
#define EXP_UD  6   // invalid opcode
#define EXP_NM  7   // no math coprocessor
#define EXP_DF  8   // double fault
#define EXP_TS  10  // invalid TSS
#define EXP_NP  11  // segment not present
#define EXP_SS  12  // stack segment fault
#define EXP_GP  13  // general protection
#define EXP_PF  14  // page fault
#define EXP_MF  16  // math fault
#define EXP_AC  17  // alignment check
#define EXP_MC  18  // machine check
#define EXP_XF  19  // SIMD floating point exception

#define SEG_offset  8

#define SEG_SEL_idx     0
#define SEG_HIDDEN_idx  1
#define SEG_BASE_idx    0
#define R48_BASE  0
#define R48_LIMIT 1

#define CRO_PE_SHIFT 0
#define CR0_PE_MASK (1 << CRO_PE_SHIFT)

#define R_CR0 cpu->regs.cr0

#define CPU_PE_MODE (R_CR0 & CR0_PE_MASK)
