/*
 * x86 function prototypes and internal variables
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once

#include "decode.h"
#include "support.h"
#include "breakpoint.h"


using namespace llvm;

template<bool remove_hook = false>
void tc_invalidate(cpu_ctx_t *cpu_ctx, addr_t addr, [[maybe_unused]] uint8_t size = 0, [[maybe_unused]] uint32_t eip = 0);
extern template void tc_invalidate<true>(cpu_ctx_t *cpu_ctx, addr_t addr, [[maybe_unused]] uint8_t size, [[maybe_unused]] uint32_t eip);
extern template void tc_invalidate<false>(cpu_ctx_t *cpu_ctx, addr_t addr, [[maybe_unused]] uint8_t size, [[maybe_unused]] uint32_t eip);
void tc_cache_clear(cpu_t *cpu);
void tc_cache_purge(cpu_t *cpu);
uint8_t update_crN_helper(cpu_ctx_t *cpu_ctx, uint32_t new_cr, uint8_t idx, uint32_t eip, uint32_t bytes);
void cpu_rdtsc_handler(cpu_ctx_t *cpu_ctx);
void msr_read_helper(cpu_ctx_t *cpu_ctx);
addr_t get_pc(cpu_ctx_t *cpu_ctx);
template<bool is_int = false> translated_code_t *cpu_raise_exception(cpu_ctx_t *cpu_ctx);

// cpu hidden flags (assumed to be constant during exec of a tc, together with a flag subset of eflags)
// HFLG_CPL: cpl of cpu
// HFLG_CS32: 16 or 32 bit code segment
// HFLG_SS32: 16 or 32 bit stack segment
// HFLG_PE_MODE: real or protected mode
// HFLG_CR0_EM: em flag of cr0
// HFLG_TRAMP: used to select the trampoline tc instead of the hook tc
// HFLG_DBG_TRAP: used to suppress data/io watchpoints (not recorded in the tc flags)
#define CPL_SHIFT       0
#define CS32_SHIFT      2
#define SS32_SHIFT      3
#define PE_MODE_SHIFT   4
#define EM_SHIFT        5
#define TRAMP_SHIFT     6
#define DBG_TRAP_SHIFT  7
#define HFLG_CPL        (3 << CPL_SHIFT)
#define HFLG_CS32       (1 << CS32_SHIFT)
#define HFLG_SS32       (1 << SS32_SHIFT)
#define HFLG_PE_MODE    (1 << PE_MODE_SHIFT)
#define HFLG_CR0_EM     (1 << EM_SHIFT)
#define HFLG_TRAMP      (1 << TRAMP_SHIFT)
#define HFLG_DBG_TRAP   (1 << DBG_TRAP_SHIFT)
#define HFLG_CONST      (HFLG_CPL | HFLG_CS32 | HFLG_SS32 | HFLG_PE_MODE | HFLG_CR0_EM | HFLG_TRAMP)

// cpu interrupt flags
#define CPU_NO_INT   0
#define CPU_DBG_INT  1
#define CPU_HW_INT   2

// disassembly context flags
#define DISAS_FLG_CS32         (1 << 0)
#define DISAS_FLG_PAGE_CROSS   (1 << 2)
#define DISAS_FLG_FETCH_FAULT  DISAS_FLG_PAGE_CROSS
#define DISAS_FLG_DBG_FAULT    DISAS_FLG_PAGE_CROSS
#define DISAS_FLG_ONE_INSTR    CPU_DISAS_ONE

// tc struct flags/offsets
#define TC_JMP_DST_PC     0
#define TC_JMP_NEXT_PC    1
#define TC_JMP_RET        2
#define TC_FLG_NUM_JMP         (3 << 0)
#define TC_FLG_INDIRECT        (1 << 2)
#define TC_FLG_DIRECT          (1 << 3)
#define TC_FLG_JMP_TAKEN       (3 << 4)
#define TC_FLG_RET             (1 << 6)
#define TC_FLG_DST_ONLY        (1 << 7)  // jump(dest_pc)
#define TC_FLG_COND_DST_ONLY   (1 << 8)  // if [runtime] (cond) jump(dst_pc)
#define TC_FLG_LINK_MASK  (TC_FLG_INDIRECT | TC_FLG_DIRECT | TC_FLG_RET | TC_FLG_DST_ONLY | TC_FLG_COND_DST_ONLY)
#define TC_JMP_INT_OFFSET 2

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
#define R0_idx      33
#define R1_idx      34
#define R2_idx      35
#define R3_idx      36
#define R4_idx      37
#define R5_idx      38
#define R6_idx      39
#define R7_idx      40
#define ST_idx      41
#define TAG_idx     42

#define SEG_offset  ES_idx
#define CR_offset   CR0_idx
#define DR_offset   DR0_idx

#define SEG_SEL_idx     0
#define SEG_HIDDEN_idx  1
#define SEG_BASE_idx    0
#define SEG_LIMIT_idx   1
#define SEG_FLG_idx     2
#define F80_LOW_idx     0
#define F80_HIGH_idx    1

// eflags macros
#define TF_MASK        (1 << 8)
#define IF_MASK        (1 << 9)
#define DF_MASK        (1 << 10)
#define IOPL_MASK      (3 << 12)
#define NT_MASK        (1 << 14)
#define RF_MASK        (1 << 16)
#define VM_MASK        (1 << 17)
#define AC_MASK        (1 << 18)
#define VIF_MASK       (1 << 19)
#define VIP_MASK       (1 << 20)
#define ID_MASK        (1 << 21)
#define EFLAGS_CONST   (TF_MASK | IOPL_MASK | RF_MASK | AC_MASK)

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
#define EXP_INVALID 0xFFFF

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
#define TLB_ROM         (1 << 6)
#define TLB_MMIO        (1 << 7)
#define TLB_GLOBAL      (1 << 8)
#define TLB_DIRTY       (1 << 9)
#define TLB_WATCH       (1 << 10)
#define TLB_zero        0
#define TLB_keep_cw     1
#define TLB_no_g        2
#define TLB_rom         3
#define TLB_mmio        4

// io macros
#define IO_SHIFT        2
#define IO_SIZE         4
#define IO_MAX_PORT     65536

// iotlb macros
#define IOTLB_VALID    (1 << 0)
#define IOTLB_WATCH    (1 << 1)

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
#define CR4_VME_MASK (1 << 0)
#define CR4_TSD_MASK (1 << 2)
#define CR4_DE_MASK  (1 << 3)
#define CR4_PSE_MASK (1 << 4)
#define CR4_PAE_MASK (1 << 5)
#define CR4_PGE_MASK (1 << 7)
#define CR4_RES_MASK (0x1FFFFF << 11) // cr4 reserved bits

// debug register flags
#define DR6_B0_MASK      (1 << 0)
#define DR6_B1_MASK      (1 << 1)
#define DR6_B2_MASK      (1 << 2)
#define DR6_B3_MASK      (1 << 3)
#define DR6_BD_MASK      (1 << 13)
#define DR6_BS_MASK      (1 << 14)
#define DR6_RES_MASK     0xFFFF0FF0 // dr6 reserved bits
#define DR7_GD_MASK      (1 << 13)
#define DR7_RES_MASK     0x400 // dr7 reserved bits
#define DR7_TYPE_SHIFT   16
#define DR7_LEN_SHIFT    18
#define DR7_TYPE_INSTR   0
#define DR7_TYPE_DATA_W  1
#define DR7_TYPE_IO_RW   2
#define DR7_TYPE_DATA_RW 3

// fpu register flags
#define ST_ES_MASK  (1 << 7)
#define ST_TOP_MASK (3 << 11)

// msr register addresses
#define MTRR_PHYSBASE_base    0x200
#define MTRR_PHYSMASK_base    0x201
#define IA32_APIC_BASE        0x1B
#define IA32_MTRR_PHYSBASE(n) (MTRR_PHYSBASE_base + (n * 2))
#define IA32_MTRR_PHYSMASK(n) (MTRR_PHYSMASK_base + (n * 2))

#define X86_MAX_INSTR_LENGTH 15
#define ROM_MAX_NUM ((1 << 16) - 1)
#define MMIO_MAX_NUM ROM_MAX_NUM
