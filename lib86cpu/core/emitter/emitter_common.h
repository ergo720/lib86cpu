/*
 * shared definitions among all emitters
 *
 * ergo720                Copyright (c) 2022
 */

#pragma once

#include "instructions.h"
#include "debugger.h"
#include "clock.h"


#define CPU_CTX_REG          offsetof(cpu_ctx_t, regs)
#define CPU_CTX_EFLAGS_RES   offsetof(cpu_ctx_t, lazy_eflags.result)
#define CPU_CTX_EFLAGS_AUX   offsetof(cpu_ctx_t, lazy_eflags.auxbits)
#define CPU_CTX_EFLAGS_PAR   offsetof(cpu_ctx_t, lazy_eflags.parity)
#define CPU_CTX_HFLG         offsetof(cpu_ctx_t, hflags)
#define CPU_CTX_EXP          offsetof(cpu_ctx_t, exp_info)
#define CPU_CTX_INT          offsetof(cpu_ctx_t, int_pending)
#define CPU_CTX_EXIT         offsetof(cpu_ctx_t, exit_requested)
#define CPU_CTX_HALTED       offsetof(cpu_ctx_t, is_halted)

#define CPU_CTX_EAX          offsetof(cpu_ctx_t, regs.eax)
#define CPU_CTX_ECX          offsetof(cpu_ctx_t, regs.ecx)
#define CPU_CTX_EDX          offsetof(cpu_ctx_t, regs.edx)
#define CPU_CTX_EBX          offsetof(cpu_ctx_t, regs.ebx)
#define CPU_CTX_ESP          offsetof(cpu_ctx_t, regs.esp)
#define CPU_CTX_EBP          offsetof(cpu_ctx_t, regs.ebp)
#define CPU_CTX_ESI          offsetof(cpu_ctx_t, regs.esi)
#define CPU_CTX_EDI          offsetof(cpu_ctx_t, regs.edi)
#define CPU_CTX_ES           offsetof(cpu_ctx_t, regs.es)
#define CPU_CTX_ES_BASE      offsetof(cpu_ctx_t, regs.es_hidden.base)
#define CPU_CTX_ES_LIMIT     offsetof(cpu_ctx_t, regs.es_hidden.limit)
#define CPU_CTX_ES_FLAGS     offsetof(cpu_ctx_t, regs.es_hidden.flags)
#define CPU_CTX_CS           offsetof(cpu_ctx_t, regs.cs)
#define CPU_CTX_CS_BASE      offsetof(cpu_ctx_t, regs.cs_hidden.base)
#define CPU_CTX_CS_LIMIT     offsetof(cpu_ctx_t, regs.cs_hidden.limit)
#define CPU_CTX_CS_FLAGS     offsetof(cpu_ctx_t, regs.cs_hidden.flags)
#define CPU_CTX_SS           offsetof(cpu_ctx_t, regs.ss)
#define CPU_CTX_SS_BASE      offsetof(cpu_ctx_t, regs.ss_hidden.base)
#define CPU_CTX_SS_LIMIT     offsetof(cpu_ctx_t, regs.ss_hidden.limit)
#define CPU_CTX_SS_FLAGS     offsetof(cpu_ctx_t, regs.ss_hidden.flags)
#define CPU_CTX_DS           offsetof(cpu_ctx_t, regs.ds)
#define CPU_CTX_DS_BASE      offsetof(cpu_ctx_t, regs.ds_hidden.base)
#define CPU_CTX_DS_LIMIT     offsetof(cpu_ctx_t, regs.ds_hidden.limit)
#define CPU_CTX_DS_FLAGS     offsetof(cpu_ctx_t, regs.ds_hidden.flags)
#define CPU_CTX_FS           offsetof(cpu_ctx_t, regs.fs)
#define CPU_CTX_FS_BASE      offsetof(cpu_ctx_t, regs.fs_hidden.base)
#define CPU_CTX_FS_LIMIT     offsetof(cpu_ctx_t, regs.fs_hidden.limit)
#define CPU_CTX_FS_FLAGS     offsetof(cpu_ctx_t, regs.fs_hidden.flags)
#define CPU_CTX_GS           offsetof(cpu_ctx_t, regs.gs)
#define CPU_CTX_GS_BASE      offsetof(cpu_ctx_t, regs.gs_hidden.base)
#define CPU_CTX_GS_LIMIT     offsetof(cpu_ctx_t, regs.gs_hidden.limit)
#define CPU_CTX_GS_FLAGS     offsetof(cpu_ctx_t, regs.gs_hidden.flags)
#define CPU_CTX_CR0          offsetof(cpu_ctx_t, regs.cr0)
#define CPU_CTX_CR1          offsetof(cpu_ctx_t, regs.cr1)
#define CPU_CTX_CR2          offsetof(cpu_ctx_t, regs.cr2)
#define CPU_CTX_CR3          offsetof(cpu_ctx_t, regs.cr3)
#define CPU_CTX_CR4          offsetof(cpu_ctx_t, regs.cr4)
#define CPU_CTX_DR0          offsetof(cpu_ctx_t, regs.dr[0])
#define CPU_CTX_DR1          offsetof(cpu_ctx_t, regs.dr[1])
#define CPU_CTX_DR2          offsetof(cpu_ctx_t, regs.dr[2])
#define CPU_CTX_DR3          offsetof(cpu_ctx_t, regs.dr[3])
#define CPU_CTX_DR4          offsetof(cpu_ctx_t, regs.dr[4])
#define CPU_CTX_DR5          offsetof(cpu_ctx_t, regs.dr[5])
#define CPU_CTX_DR6          offsetof(cpu_ctx_t, regs.dr[6])
#define CPU_CTX_DR7          offsetof(cpu_ctx_t, regs.dr[7])
#define CPU_CTX_EFLAGS       offsetof(cpu_ctx_t, regs.eflags)
#define CPU_CTX_EIP          offsetof(cpu_ctx_t, regs.eip)
#define CPU_CTX_IDTR         offsetof(cpu_ctx_t, regs.idtr)
#define CPU_CTX_IDTR_BASE    offsetof(cpu_ctx_t, regs.idtr_hidden.base)
#define CPU_CTX_IDTR_LIMIT   offsetof(cpu_ctx_t, regs.idtr_hidden.limit)
#define CPU_CTX_IDTR_FLAGS   offsetof(cpu_ctx_t, regs.idtr_hidden.flags)
#define CPU_CTX_GDTR         offsetof(cpu_ctx_t, regs.gdtr)
#define CPU_CTX_GDTR_BASE    offsetof(cpu_ctx_t, regs.gdtr_hidden.base)
#define CPU_CTX_GDTR_LIMIT   offsetof(cpu_ctx_t, regs.gdtr_hidden.limit)
#define CPU_CTX_GDTR_FLAGS   offsetof(cpu_ctx_t, regs.gdtr_hidden.flags)
#define CPU_CTX_LDTR         offsetof(cpu_ctx_t, regs.ldtr)
#define CPU_CTX_LDTR_BASE    offsetof(cpu_ctx_t, regs.ldtr_hidden.base)
#define CPU_CTX_LDTR_LIMIT   offsetof(cpu_ctx_t, regs.ldtr_hidden.limit)
#define CPU_CTX_LDTR_FLAGS   offsetof(cpu_ctx_t, regs.ldtr_hidden.flags)
#define CPU_CTX_TR           offsetof(cpu_ctx_t, regs.tr)
#define CPU_CTX_TR_BASE      offsetof(cpu_ctx_t, regs.tr_hidden.base)
#define CPU_CTX_TR_LIMIT     offsetof(cpu_ctx_t, regs.tr_hidden.limit)
#define CPU_CTX_TR_FLAGS     offsetof(cpu_ctx_t, regs.tr_hidden.flags)
#define CPU_CTX_R0           offsetof(cpu_ctx_t, regs.fr[0].low)
#define CPU_CTX_R1           offsetof(cpu_ctx_t, regs.fr[1].low)
#define CPU_CTX_R2           offsetof(cpu_ctx_t, regs.fr[2].low)
#define CPU_CTX_R3           offsetof(cpu_ctx_t, regs.fr[3].low)
#define CPU_CTX_R4           offsetof(cpu_ctx_t, regs.fr[4].low)
#define CPU_CTX_R5           offsetof(cpu_ctx_t, regs.fr[5].low)
#define CPU_CTX_R6           offsetof(cpu_ctx_t, regs.fr[6].low)
#define CPU_CTX_R7           offsetof(cpu_ctx_t, regs.fr[7].low)
#define CPU_CTX_FCTRL        offsetof(cpu_ctx_t, regs.fctrl)
#define CPU_CTX_FSTATUS      offsetof(cpu_ctx_t, regs.fstatus)
#define CPU_CTX_FTAGS0       offsetof(cpu_ctx_t, regs.ftags[0])
#define CPU_CTX_FTAGS1       offsetof(cpu_ctx_t, regs.ftags[1])
#define CPU_CTX_FTAGS2       offsetof(cpu_ctx_t, regs.ftags[2])
#define CPU_CTX_FTAGS3       offsetof(cpu_ctx_t, regs.ftags[3])
#define CPU_CTX_FTAGS4       offsetof(cpu_ctx_t, regs.ftags[4])
#define CPU_CTX_FTAGS5       offsetof(cpu_ctx_t, regs.ftags[5])
#define CPU_CTX_FTAGS6       offsetof(cpu_ctx_t, regs.ftags[6])
#define CPU_CTX_FTAGS7       offsetof(cpu_ctx_t, regs.ftags[7])
#define CPU_CTX_FCS          offsetof(cpu_ctx_t, regs.fcs)
#define CPU_CTX_FIP          offsetof(cpu_ctx_t, regs.fip)
#define CPU_CTX_FDS          offsetof(cpu_ctx_t, regs.fds)
#define CPU_CTX_FDP          offsetof(cpu_ctx_t, regs.fdp)
#define CPU_CTX_FOP          offsetof(cpu_ctx_t, regs.fop)
#define CPU_CTX_XMM0         offsetof(cpu_ctx_t, regs.xmm[0].low)
#define CPU_CTX_XMM1         offsetof(cpu_ctx_t, regs.xmm[1].low)
#define CPU_CTX_XMM2         offsetof(cpu_ctx_t, regs.xmm[2].low)
#define CPU_CTX_XMM3         offsetof(cpu_ctx_t, regs.xmm[3].low)
#define CPU_CTX_XMM4         offsetof(cpu_ctx_t, regs.xmm[4].low)
#define CPU_CTX_XMM5         offsetof(cpu_ctx_t, regs.xmm[5].low)
#define CPU_CTX_XMM6         offsetof(cpu_ctx_t, regs.xmm[6].low)
#define CPU_CTX_XMM7         offsetof(cpu_ctx_t, regs.xmm[7].low)

#define FPU_DATA_FTOP        offsetof(cpu_ctx_t, fpu_data.ftop)
#define FPU_DATA_FES         offsetof(cpu_ctx_t, fpu_data.fes)
#define FPU_DATA_FRP         offsetof(cpu_ctx_t, fpu_data.frp)

#define CPU_EXP_ADDR         offsetof(cpu_ctx_t, exp_info.exp_data.fault_addr)
#define CPU_EXP_CODE         offsetof(cpu_ctx_t, exp_info.exp_data.code)
#define CPU_EXP_IDX          offsetof(cpu_ctx_t, exp_info.exp_data.idx)
#define CPU_EXP_EIP          offsetof(cpu_ctx_t, exp_info.exp_data.eip)

#define REG_off(reg) get_reg_offset(reg)
#define REG_idx(reg) get_reg_idx(reg)
#define REG_pair(reg) get_reg_pair(reg)


entry_t JIT_API link_indirect_handler(cpu_ctx_t *cpu_ctx, translated_code_t *tc);
size_t get_reg_offset(ZydisRegister reg);
size_t get_seg_prfx_offset(decoded_instr *instr);
int get_reg_idx(ZydisRegister reg);
const std::pair<int, size_t> get_reg_pair(ZydisRegister reg);
#ifdef LIB86CPU_X64_EMITTER
size_t get_jit_stack_required_runtime();
#endif


inline constexpr size_t seg_base_offset = offsetof(cpu_ctx_t, regs.es_hidden.base) - offsetof(cpu_ctx_t, regs.es);
inline constexpr size_t seg_limit_offset = offsetof(cpu_ctx_t, regs.es_hidden.limit) - offsetof(cpu_ctx_t, regs.es);
inline constexpr size_t seg_flags_offset = offsetof(cpu_ctx_t, regs.es_hidden.flags) - offsetof(cpu_ctx_t, regs.es);

// this should hold all the functions that can be called at runtime by the jit
inline constexpr auto all_callable_funcs = std::make_tuple(
	cpu_raise_exception<0, true>,
	cpu_raise_exception<1, true>,
	cpu_raise_exception<2, true>,
	cpu_raise_exception<3, true>,
	cpu_raise_exception<0, false>,
	cpu_raise_exception<1, false>,
	cpu_raise_exception<2, false>,
	cpu_raise_exception<3, false>,
	cpu_timer_helper,
	cpu_do_int,
	link_indirect_handler,
	mem_read_helper<uint32_t>,
	mem_read_helper<uint16_t>,
	mem_read_helper<uint8_t>,
	mem_write_helper<uint32_t>,
	mem_write_helper<uint16_t>,
	mem_write_helper<uint8_t>,
	io_read_helper<uint32_t>,
	io_read_helper<uint16_t>,
	io_read_helper<uint8_t>,
	io_write_helper<uint32_t>,
	io_write_helper<uint16_t>,
	io_write_helper<uint8_t>,
	ljmp_pe_helper,
	lcall_pe_helper,
	lret_pe_helper<true>,
	lret_pe_helper<false>,
	iret_real_helper,
	lldt_helper,
	ltr_helper,
	verrw_helper<true>,
	verrw_helper<false>,
	update_crN_helper<0>,
	update_crN_helper<1>,
	update_crN_helper<2>,
	update_drN_helper,
	mov_sel_pe_helper<SS_idx>,
	mov_sel_pe_helper<DS_idx>,
	mov_sel_pe_helper<ES_idx>,
	mov_sel_pe_helper<FS_idx>,
	mov_sel_pe_helper<GS_idx>,
	cpu_rdtsc_helper,
	msr_read_helper,
	msr_write_helper,
	divd_helper,
	divw_helper,
	divb_helper,
	idivd_helper,
	idivw_helper,
	idivb_helper,
	cpuid_helper,
	hlt_helper,
	fxsave_helper,
	fxrstor_helper,
	fpu_update_tag,
	cpu_runtime_abort,
	dbg_update_exp_hook,
	tlb_invalidate_,
	fpu_stack_check<true, fpu_instr_t::integer8>,
	fpu_stack_check<false, fpu_instr_t::integer8>,
	fpu_stack_check<true, fpu_instr_t::integer16>,
	fpu_stack_check<false, fpu_instr_t::integer16>,
	fpu_stack_check<true, fpu_instr_t::integer32>,
	fpu_stack_check<false, fpu_instr_t::integer32>,
	fpu_stack_check<true, fpu_instr_t::integer64>,
	fpu_stack_check<false, fpu_instr_t::integer64>,
	fpu_stack_check<true, fpu_instr_t::float_>,
	fpu_stack_check<false, fpu_instr_t::float_>,
	fpu_stack_check<true, fpu_instr_t::bcd>,
	fpu_stack_check<false, fpu_instr_t::bcd>
);
