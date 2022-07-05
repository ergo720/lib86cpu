/*
 * x86 init code
 *
 * ergo720                Copyright (c) 2019
 */

#include "lib86cpu_priv.h"
#include "internal.h"


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
	{ 0, IDTR_idx,	  "idtr" },
	{ 0, GDTR_idx,	  "gdtr" },
	{ 0, LDTR_idx,	  "ldtr" },
	{ 0, TR_idx,      "tr" },
	{ 80, R0_idx,	  "r0" },
	{ 80, R1_idx,	  "r1" },
	{ 80, R2_idx,	  "r2" },
	{ 80, R3_idx,	  "r3" },
	{ 80, R4_idx,	  "r4" },
	{ 80, R5_idx,	  "r5" },
	{ 80, R6_idx,	  "r6" },
	{ 80, R7_idx,	  "r7" },
	{ 16, ST_idx,	  "status" },
	{ 16, TAG_idx,	  "tag" },
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
static_assert(check_regs_layout_idx(29), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(30), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(31), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(32), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(33), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(34), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(35), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(36), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(37), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(38), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(39), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(40), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(41), "wrong index in regs_layout array!");
static_assert(check_regs_layout_idx(42), "wrong index in regs_layout array!");


void
cpu_init(cpu_t *cpu)
{
	cpu->cpu_name = "Intel Pentium III";
	cpu->regs_layout = regs_layout;
	cpu->cpu_ctx.exp_info.old_exp = EXP_INVALID;

	// init regs to their reset state
	cpu->cpu_ctx.regs.eip = 0x0000FFF0;
	cpu->cpu_ctx.regs.edx = 0x00000680; // TODO: stepping id
	cpu->cpu_ctx.regs.cs = 0xF000;
	cpu->cpu_ctx.regs.cs_hidden.base = 0xFFFF0000;
	cpu->cpu_ctx.regs.es_hidden.limit = cpu->cpu_ctx.regs.cs_hidden.limit = cpu->cpu_ctx.regs.ss_hidden.limit =
	cpu->cpu_ctx.regs.ds_hidden.limit = cpu->cpu_ctx.regs.fs_hidden.limit = cpu->cpu_ctx.regs.gs_hidden.limit = 0xFFFF;
	cpu->cpu_ctx.regs.eflags = 0x2;
	cpu->cpu_ctx.regs.cr0 = 0x60000010;
	cpu->cpu_ctx.regs.dr6 = DR6_RES_MASK;
	cpu->cpu_ctx.regs.dr7 = DR7_RES_MASK;
	cpu->cpu_ctx.regs.idtr_hidden.limit = cpu->cpu_ctx.regs.gdtr_hidden.limit = cpu->cpu_ctx.regs.ldtr_hidden.limit =
		cpu->cpu_ctx.regs.tr_hidden.limit = 0xFFFF;
	cpu->cpu_ctx.regs.tag = 0x5555;
}
