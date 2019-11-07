/*
 * disassembler
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#include "x86cpu.h"

const char *mnemo[] = {
	"illegal",
#define DECLARE_OPC(name,str) str,
#include "x86_instr.h"
#undef DECLARE_OPC
};

extern int disasm_instr_att(cpu_t *cpu, addr_t pc, char *line, unsigned int max_line);
extern int disasm_instr_intel(cpu_t *cpu, addr_t pc, char *line, unsigned int max_line);

typedef int(*fp_disasm_instr)(cpu_t *cpu, addr_t pc, char *line, unsigned int max_line);
fp_disasm_instr disasm_func[] = {
	disasm_instr_att,
	disasm_instr_intel,
};

int
disasm_instr(cpu_t *cpu, addr_t pc, char *line, unsigned int max_line)
{
	return (*disasm_func[(cpu->flags & CPU_INTEL_SYNTAX) >> CPU_INTEL_SYNTAX_SHIFT])(cpu, pc, line, max_line);
}
