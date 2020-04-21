/*
 * instruction decoding
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#pragma once


// the instructions opcode
typedef enum arch_x86_opcode {
	X86_OPC_ILLEGAL = 0,
#define DECLARE_OPC(name,str) name,
#include "instr.h"
#undef DECLARE_OPC
} arch_x86_opcode_t;

const char *get_instr_name(unsigned num);
