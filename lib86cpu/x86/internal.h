/*
 * x86 function prototypes and internal variables
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once

#include "decode.h"
#include "support.h"


using namespace llvm;

void tc_invalidate(cpu_ctx_t *cpu_ctx, translated_code_t *tc, uint32_t addr, uint8_t size, uint32_t eip);
uint8_t cpu_update_crN(cpu_ctx_t *cpu_ctx, uint32_t new_cr, uint8_t idx, uint32_t eip, uint32_t bytes);
void cpu_rdtsc_handler(cpu_ctx_t *cpu_ctx);

// cpu hidden flags
#define EM_SHIFT        0
#define CS32_SHIFT      2
#define SS32_SHIFT      3
#define PE_MODE_SHIFT   4
#define HFLG_CR0_EM     (1 << EM_SHIFT)
#define HFLG_CPL        (3 << 0)
#define HFLG_CS32       (1 << CS32_SHIFT)
#define HFLG_SS32       (1 << SS32_SHIFT)
#define HFLG_PE_MODE    (1 << PE_MODE_SHIFT)

// disassembly context flags
#define DISAS_FLG_CS32         (1 << 0)
#define DISAS_FLG_PAGE_CROSS   (1 << 2)
#define DISAS_FLG_FETCH_FAULT  DISAS_FLG_PAGE_CROSS
#define DISAS_FLG_ONE_INSTR    CPU_DISAS_ONE

// tc struct flags
#define TC_FLG_DST_PC     0
#define TC_FLG_NEXT_PC    1
#define TC_FLG_RET        2
#define TC_FLG_NUM_JMP    (3 << 0)
#define TC_FLG_INDIRECT   (1 << 2)
#define TC_FLG_DIRECT     (1 << 3)
#define TC_FLG_JMP_TAKEN  (3 << 4)
#define TC_FLG_HOOK       (1 << 6)
#define TC_FLG_DST_ONLY   (1 << 7)
#define TC_FLG_LINK_MASK  (TC_FLG_INDIRECT | TC_FLG_DIRECT | TC_FLG_DST_ONLY)

// segment descriptor flags
#define SEG_DESC_TY   (15ULL << 40) // type
#define SEG_DESC_TYC  (3ULL << 42)  // type/conf bits
#define SEG_DESC_DCRW (5ULL << 41)  // data/code read/write
#define SEG_DESC_A    (1ULL << 40)  // accessed
#define SEG_DESC_W    (1ULL << 41)  // write, data desc
#define SEG_DESC_R    SEG_DESC_W    // read, code desc
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
#define EAX_idx     REG_EAX
#define ECX_idx     REG_ECX
#define EDX_idx     REG_EDX
#define EBX_idx     REG_EBX
#define ESP_idx     REG_ESP
#define EBP_idx     REG_EBP
#define ESI_idx     REG_ESI
#define EDI_idx     REG_EDI
#define ES_idx      REG_ES
#define CS_idx      REG_CS
#define SS_idx      REG_SS
#define DS_idx      REG_DS
#define FS_idx      REG_FS
#define GS_idx      REG_GS
#define CR0_idx     REG_CR0
#define CR1_idx     REG_CR1
#define CR2_idx     REG_CR2
#define CR3_idx     REG_CR3
#define CR4_idx     REG_CR4
#define DR0_idx     REG_DR0
#define DR1_idx     REG_DR1
#define DR2_idx     REG_DR2
#define DR3_idx     REG_DR3
#define DR4_idx     REG_DR4
#define DR5_idx     REG_DR5
#define DR6_idx     REG_DR6
#define DR7_idx     REG_DR7
#define EFLAGS_idx  REG_EFLAGS
#define EIP_idx     REG_EIP
#define IDTR_idx    REG_IDTR
#define GDTR_idx    REG_GDTR
#define LDTR_idx    REG_LDTR
#define TR_idx      REG_TR
#define R0_idx      REG_R0
#define R1_idx      REG_R1
#define R2_idx      REG_R2
#define R3_idx      REG_R3
#define R4_idx      REG_R4
#define R5_idx      REG_R5
#define R6_idx      REG_R6
#define R7_idx      REG_R7
#define ST_idx      REG_ST
#define TAG_idx     REG_TAG

#define SEG_offset  ES_idx
#define CR_offset   CR0_idx

#define SEG_SEL_idx     0
#define SEG_HIDDEN_idx  1
#define SEG_BASE_idx    0
#define SEG_LIMIT_idx   1
#define SEG_FLG_idx     2
#define F80_LOW_idx     0
#define F80_HIGH_idx    1

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
#define PTE_GLOBAL    (1 << 8)
#define PTE_ADDR_4K   0xFFFFF000
#define PTE_ADDR_4M   0xFFC00000

// page macros
#define PAGE_SHIFT        12
#define PAGE_SHIFT_LARGE  22
#define PAGE_SIZE         (1 << PAGE_SHIFT)
#define PAGE_SIZE_LARGE   (1 << PAGE_SHIFT_LARGE)
#define PAGE_MASK         (PAGE_SIZE - 1)
#define PAGE_MASK_LARGE   (PAGE_SIZE_LARGE - 1)

// tlb macros
#define TLB_SUP_READ    (1 << 0)
#define TLB_SUP_WRITE   (1 << 1)
#define TLB_USER_READ   (1 << 2)
#define TLB_USER_WRITE  (1 << 3)
#define TLB_CODE        (1 << 4)
#define TLB_RAM         (1 << 5)
#define TLB_GLOBAL      (1 << 8)
#define TLB_DIRTY       (1 << 9)
#define TLB_zero        0
#define TLB_keep_rc     1
#define TLB_no_g        2

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
#define CR4_TSD_MASK (1 << 2)
#define CR4_PSE_MASK (1 << 4)
#define CR4_PAE_MASK (1 << 5)
#define CR4_PGE_MASK (1 << 7)
#define CR4_RES_MASK (0x1FFFFF << 11) // cr4 reserved bits

// fpu register flags
#define ST_ES_MASK  (1 << 7)
#define ST_TOP_MASK (3 << 11)

#define X86_MAX_INSTR_LENGTH 15
