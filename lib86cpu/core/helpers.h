/*
 * ergo720                Copyright (c) 2022
 */

#pragma once

#include "memory_management.h"


uint32_t stack_pop_helper(cpu_t *cpu, uint32_t size_mode, uint32_t &addr, uint32_t eip);
void stack_push_helper(cpu_t *cpu, const uint32_t val, uint32_t size_mode, uint32_t &addr, uint32_t eip);
uint8_t raise_exp_helper(cpu_t *cpu, uint16_t code, uint16_t idx, uint32_t eip);
template<bool is_tss = false> uint8_t read_seg_desc_helper(cpu_t *cpu, uint16_t sel, addr_t &desc_addr, uint64_t &desc, uint32_t eip);
void set_access_flg_seg_desc_helper(cpu_t *cpu, uint64_t desc, addr_t desc_addr, uint32_t eip);
uint32_t read_seg_desc_base_helper(cpu_t *cpu, uint64_t desc);
uint32_t read_seg_desc_flags_helper(cpu_t *cpu, uint64_t desc);
uint32_t read_seg_desc_limit_helper(cpu_t *cpu, uint64_t desc);
uint8_t check_ss_desc_priv_helper(cpu_t *cpu, uint16_t sel, uint16_t *cs, addr_t &desc_addr, uint64_t &desc, uint32_t eip);
uint8_t check_seg_desc_priv_helper(cpu_t *cpu, uint16_t sel, addr_t &desc_addr, uint64_t &desc, uint32_t eip);
void write_eflags_helper(cpu_t *cpu, uint32_t eflags, uint32_t mask);
uint8_t read_stack_ptr_from_tss_helper(cpu_t *cpu, uint32_t dpl, uint32_t &esp, uint16_t &ss, uint32_t eip);
