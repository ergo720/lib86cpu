/*
 * x86 init code
 *
 * ergo720                Copyright (c) 2019
 */

#include "lib86cpu.h"
#include "x86_internal.h"


// These registers must have the same order they have in struct regs_t
static constexpr regs_layout_t regs_layout[CPU_NUM_REGS] = {
	{ 32, EAX_idx,    "eax" },
	{ 32, ECX_idx,	  "ecx" },
	{ 32, EDX_idx,	  "edx" },
	{ 32, EBX_idx,	  "ebx" },
	{ 32, ESP_idx,	  "esp" },
	{ 32, EBP_idx,	  "ebp" },
	{ 32, ESI_idx,	  "esi" },
	{ 32, EDI_idx,	  "edi" },
	{ 0,  ES_idx,	  "es" },
	{ 0,  CS_idx,	  "cs" },
	{ 0,  SS_idx,	  "ss" },
	{ 0,  DS_idx,	  "ds" },
	{ 0,  FS_idx,	  "fs" },
	{ 0,  GS_idx,	  "gs" },
	{ 32, CR0_idx,	  "cr0" },
	{ 32, CR1_idx,	  "cr1" },
	{ 32, CR2_idx,	  "cr2" },
	{ 32, CR3_idx,	  "cr3" },
	{ 32, CR4_idx,	  "cr4" },
	{ 32, DR0_idx,	  "dr0" },
	{ 32, DR1_idx,	  "dr1" },
	{ 32, DR2_idx,	  "dr2" },
	{ 32, DR3_idx,	  "dr3" },
	{ 32, DR4_idx,	  "dr4" },
	{ 32, DR5_idx,	  "dr5" },
	{ 32, DR6_idx,	  "dr6" },
	{ 32, DR7_idx,	  "dr7" },
	{ 32, EFLAGS_idx, "eflags" },
	{ 32, EIP_idx,	  "eip" },
};

static constexpr bool
check_regs_layout_idx(unsigned idx)
{
	if (regs_layout[idx].idx == idx) {
		return true;
	}
	else {
		return false;
	}
}

// ensure that the indexes in regs_layout are actually correct
static_assert(check_regs_layout_idx(0),  "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(1),  "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(2),  "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(3),  "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(4),  "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(5),  "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(6),  "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(7),  "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(8),  "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(9),  "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(10), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(11), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(12), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(13), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(14), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(15), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(16), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(17), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(18), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(19), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(20), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(21), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(22), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(23), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(24), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(25), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(26), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(27), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(28), "wrong index in regs_layout array!");


void
cpu_x86_init(cpu_t *cpu)
{
	cpu->cpu_name = "Intel Pentium III";
	cpu->regs_layout = regs_layout;

	// init regs to their reset state
	cpu->regs.eip = 0x0000FFF0;
	cpu->regs.edx = 0x00000680; // TODO: stepping id
	cpu->regs.cs = 0xF000;
	cpu->regs.cs_hidden.base = 0xFFFF0000;
	cpu->regs.eflags = 0x2;
	cpu->regs.cr0 = 0x60000010;
}
