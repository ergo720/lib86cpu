/*
 * x86 function prototypes and internal variables
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once

#include "x86_decode.h"


void cpu_x86_init(cpu_t *cpu);
lib86cpu_status cpu_exec_tc(cpu_t *cpu);
addr_t mmu_translate_addr(cpu_t *cpu, addr_t addr, uint8_t is_write, uint32_t eip);
size_t disasm_instr(cpu_t *cpu, x86_instr *instr, char *line, unsigned int max_line, disas_ctx_t *disas_ctx);
void decode_instr(cpu_t *cpu, x86_instr *instr, disas_ctx_t *disas_ctx);
 void cpu_raise_exception(cpu_ctx_t *cpu_ctx, uint32_t eip);
JIT_EXTERNAL_CALL_C void cpu_throw_exception [[noreturn]] (cpu_ctx_t *cpu_ctx, uint64_t exp_data, uint32_t eip);

extern const char *mnemo[];

// cpu hidden flags
#define HFLG_CPL        (3 << 0)
#define HFLG_CS32       (1 << 2)
#define HFLG_SS32       (1 << 3)
#define HFLG_PE_MODE    (1 << 4)
#define HFLG_CPL_PRIV   (1 << 5)
#define CS32_SHIFT      2
#define SS32_SHIFT      3
#define CPL_PRIV_SHIFT  5

// disassembly context flags
#define DISAS_FLG_CS32         (1 << 0)
#define DISAS_FLG_PAGE_CROSS   (1 << 1)
#define DISAS_FLG_FETCH_FAULT  DISAS_FLG_PAGE_CROSS

// tc struct flags
#define TC_FLG_NUM_JMP   (3 << 0)
#define TC_FLG_INDIRECT  (1 << 2)
#define TC_FLG_DIRECT    (1 << 3)
#define TC_FLG_NEXT_PC   (1 << 4)

// segment descriptor flags
#define SEG_DESC_TY   (15ULL << 40) // type
#define SEG_DESC_A    (1ULL << 40)  // accessed
#define SEG_DESC_W    (1ULL << 41)  // write
#define SEG_DESC_R    SEG_DESC_W    // read
#define SEG_DESC_BY   SEG_DESC_W    // busy
#define SEG_DESC_C    (1ULL << 42)  // conforming
#define SEG_DESC_DC   (1ULL << 43)  // data/code
#define SEG_DESC_S    (1ULL << 44)  // system
#define SEG_DESC_DPL  (3ULL << 45)  // dpl
#define SEG_DESC_P    (1ULL << 47)  // present
#define SEG_DESC_DB   (1ULL << 54)  // default size
#define SEG_DESC_G    (1ULL << 55)  // granularity
#define SEG_DESC_TSS16AV  1         // system / tss, 16 bit, available
#define SEG_DESC_LDT      2         // system / ldt
#define SEG_DESC_TSS32AV  9         // system / tss, 32 bit, available

// segment hidden flags
#define SEG_HIDDEN_DB      (1 << 22)  // default size
#define SEG_HIDDEN_TSS_TY  (1 << 11)  // 16/32 tss type

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
#define GDTR_idx    30
#define LDTR_idx    31
#define TR_idx      32

#define SEG_offset  ES_idx
#define CR_offset   CR0_idx

#define SEG_SEL_idx     0
#define SEG_HIDDEN_idx  1
#define SEG_BASE_idx    0
#define SEG_LIMIT_idx   1
#define SEG_FLG_idx     2

// eflags macros
#define TF_MASK     (1 << 8)
#define IF_MASK     (1 << 9)
#define DF_MASK     (1 << 10)
#define IOPL_MASK   (3 << 12)
#define NT_MASK     (1 << 14)
#define RF_MASK     (1 << 16)
#define VM_MASK     (1 << 17)
#define AC_MASK     (1 << 18)
#define VIF_MASK    (1 << 19)
#define VIP_MASK    (1 << 20)
#define ID_MASK     (1 << 21)

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

// pte flags
#define PTE_PRESENT   (1 << 0)
#define PTE_WRITE     (1 << 1)
#define PTE_USER      (1 << 2)
#define PTE_ACCESSED  (1 << 5)
#define PTE_DIRTY     (1 << 6)
#define PTE_LARGE     (1 << 7)
#define PTE_ADDR_4K   0xFFFFF000
#define PTE_ADDR_4M   0xFFC00000

// page macros
#define PAGE_SHIFT        12
#define PAGE_SHIFT_LARGE  22
#define PAGE_SIZE         (1 << PAGE_SHIFT)
#define PAGE_SIZE_LARGE   (1 << PAGE_SHIFT_LARGE)
#define PAGE_MASK         (PAGE_SIZE - 1)
#define PAGE_MASK_LARGE   (PAGE_SIZE_LARGE - 1)

// control register flags
#define CR0_PG_MASK (1 << 31)
#define CR0_CD_MASK (1 << 30)
#define CR0_NW_MASK (1 << 29)
#define CR0_AM_MASK (1 << 18)
#define CR0_WP_MASK (1 << 16)
#define CR0_NE_MASK (1 << 5)
#define CR0_ET_MASK (1 << 4)
#define CR0_TS_MASK (1 << 3)
#define CR0_EM_MASK (1 << 2)
#define CR0_MP_MASK (1 << 1)
#define CR0_PE_MASK (1 << 0)
#define CR0_FLG_MASK (CR0_PG_MASK | CR0_CD_MASK | CR0_NW_MASK | CR0_AM_MASK | CR0_WP_MASK | CR0_NE_MASK | CR0_ET_MASK |\
CR0_TS_MASK | CR0_EM_MASK | CR0_MP_MASK | CR0_PE_MASK)
#define CR3_PD_MASK 0xFFFFF000
#define CR3_PCD_MASK (1 << 4)
#define CR3_PWT_MASK (1 << 3)
#define CR3_FLG_MASK (CR3_PD_MASK | CR3_PCD_MASK | CR3_PWT_MASK)
#define CR4_PSE_MASK (1 << 4)

#define X86_MAX_INSTR_LENGTH 15
