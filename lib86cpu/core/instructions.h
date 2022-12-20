/*
 * ergo720                Copyright (c) 2022
 */

#pragma once

#include "helpers.h"


template<bool is_iret> uint32_t lret_pe_helper(cpu_ctx_t *cpu_ctx, uint8_t size_mode, uint32_t eip);
void iret_real_helper(cpu_ctx_t *cpu_ctx, uint8_t size_mode, uint32_t eip);
uint32_t ljmp_pe_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint8_t size_mode, uint32_t jmp_eip, uint32_t eip);
uint32_t lcall_pe_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint32_t call_eip, uint8_t size_mode, uint32_t ret_eip, uint32_t eip);
template<bool is_verr> void verrw_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint32_t eip);
template<unsigned reg> uint32_t mov_sel_pe_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint32_t eip);
uint32_t ltr_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint32_t eip);
uint32_t lldt_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint32_t eip);
uint32_t update_crN_helper(cpu_ctx_t *cpu_ctx, uint32_t new_cr, uint8_t idx, uint32_t eip, uint32_t bytes);
void update_drN_helper(cpu_ctx_t *cpu_ctx, uint8_t dr_idx, uint32_t new_dr);
uint32_t divd_helper(cpu_ctx_t *cpu_ctx, uint32_t d, uint32_t eip);
uint32_t divw_helper(cpu_ctx_t *cpu_ctx, uint16_t d, uint32_t eip);
uint32_t divb_helper(cpu_ctx_t *cpu_ctx, uint8_t d, uint32_t eip);
uint32_t idivd_helper(cpu_ctx_t *cpu_ctx, uint32_t d, uint32_t eip);
uint32_t idivw_helper(cpu_ctx_t *cpu_ctx, uint16_t d, uint32_t eip);
uint32_t idivb_helper(cpu_ctx_t *cpu_ctx, uint8_t d, uint32_t eip);
void cpuid_helper(cpu_ctx_t *cpu_ctx);
void cpu_rdtsc_helper(cpu_ctx_t *cpu_ctx);
uint32_t msr_read_helper(cpu_ctx_t *cpu_ctx);
uint32_t msr_write_helper(cpu_ctx_t *cpu_ctx);
uint32_t hlt_helper(cpu_ctx_t *cpu_ctx);
