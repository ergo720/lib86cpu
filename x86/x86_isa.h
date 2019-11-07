/*
 * instruction decoding (shared by disassembler and translator)
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#ifndef X86_ISA_H
#define X86_ISA_H

#define CF_SHIFT    0
#define PF_SHIFT    2
#define AF_SHIFT    4
#define ZF_SHIFT    6
#define SF_SHIFT    7
#define TF_SHIFT    8
#define IF_SHIFT    9
#define DF_SHIFT    10
#define OF_SHIFT    11
#define IOPLL_SHIFT 12
#define IOPLH_SHIFT 13
#define NT_SHIFT    14
#define RF_SHIFT    16
#define VM_SHIFT    17
#define AC_SHIFT    18
#define VIF_SHIFT   19
#define VIP_SHIFT   20
#define ID_SHIFT    21

// the instructions opcode
typedef enum arch_x86_opcode {
	X86_OPC_ILLEGAL = 0,
#define DECLARE_OPC(name,str) name,
#include "x86_instr.h"
#undef DECLARE_OPC
} arch_x86_opcode_t;

#endif /* X86_ISA_H */
