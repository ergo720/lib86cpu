/*
 * ergo720                Copyright (c) 2022
 */

#pragma once

#include "helpers.h"


template<bool is_iret> uint32_t JIT_API lret_pe_helper(cpu_ctx_t *cpu_ctx, uint8_t size_mode, uint32_t eip);
void JIT_API iret_real_helper(cpu_ctx_t *cpu_ctx, uint8_t size_mode, uint32_t eip);
uint32_t JIT_API ljmp_pe_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint8_t size_mode, uint32_t jmp_eip, uint32_t eip);
uint32_t JIT_API lcall_pe_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint32_t call_eip, uint8_t size_mode, uint32_t ret_eip, uint32_t eip);
template<bool is_verr> void JIT_API verrw_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint32_t eip);
template<unsigned reg> uint32_t JIT_API mov_sel_pe_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint32_t eip);
uint32_t JIT_API ltr_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint32_t eip);
uint32_t JIT_API lldt_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint32_t eip);
uint32_t JIT_API update_crN_helper(cpu_ctx_t *cpu_ctx, uint32_t new_cr, uint8_t idx);
void JIT_API update_drN_helper(cpu_ctx_t *cpu_ctx, uint8_t dr_idx, uint32_t new_dr);
uint32_t JIT_API divd_helper(cpu_ctx_t *cpu_ctx, uint32_t d, uint32_t eip);
uint32_t JIT_API divw_helper(cpu_ctx_t *cpu_ctx, uint16_t d, uint32_t eip);
uint32_t JIT_API divb_helper(cpu_ctx_t *cpu_ctx, uint8_t d, uint32_t eip);
uint32_t JIT_API idivd_helper(cpu_ctx_t *cpu_ctx, uint32_t d, uint32_t eip);
uint32_t JIT_API idivw_helper(cpu_ctx_t *cpu_ctx, uint16_t d, uint32_t eip);
uint32_t JIT_API idivb_helper(cpu_ctx_t *cpu_ctx, uint8_t d, uint32_t eip);
void JIT_API cpuid_helper(cpu_ctx_t *cpu_ctx);
void JIT_API cpu_rdtsc_helper(cpu_ctx_t *cpu_ctx);
uint32_t JIT_API msr_read_helper(cpu_ctx_t *cpu_ctx);
uint32_t JIT_API msr_write_helper(cpu_ctx_t *cpu_ctx);
uint32_t JIT_API hlt_helper(cpu_ctx_t *cpu_ctx);
void JIT_API fxsave_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip);
uint32_t JIT_API fxrstor_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip);
