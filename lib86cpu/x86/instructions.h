/*
 * ergo720                Copyright (c) 2022
 */

#pragma once

#include "helpers.h"


template<bool is_iret> uint8_t lret_pe_helper(cpu_ctx_t *cpu_ctx, uint8_t size_mode, uint32_t eip);
void iret_real_helper(cpu_ctx_t *cpu_ctx, uint8_t size_mode, uint32_t eip);
uint8_t ljmp_pe_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint8_t size_mode, uint32_t jmp_eip, uint32_t eip);
uint8_t lcall_pe_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint32_t call_eip, uint8_t size_mode, uint32_t ret_eip, uint32_t eip);
template<bool is_verr> void verrw_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint32_t eip);
template<unsigned reg> uint8_t mov_sel_pe_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint32_t eip);
uint8_t ltr_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint32_t eip);
uint8_t lldt_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint32_t eip);
