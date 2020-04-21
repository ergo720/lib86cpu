/*
 * disassembler
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#include "decode.h"

const char *mnemo[] = {
	"illegal",
#define DECLARE_OPC(name,str) str,
#include "instr.h"
#undef DECLARE_OPC
};

using fp_disasm_instr = size_t(*)(cpu_t *, x86_instr *, char *, unsigned int, disas_ctx_t *);
fp_disasm_instr disasm_func[] = {
	disasm_instr_att,
	disasm_instr_intel,
};

size_t
disasm_instr(cpu_t *cpu, x86_instr *instr, char *line, unsigned int max_line, disas_ctx_t *disas_ctx)
{
	return (*disasm_func[(cpu->cpu_flags & CPU_INTEL_SYNTAX) >> CPU_INTEL_SYNTAX_SHIFT])(cpu, instr, line, max_line, disas_ctx);
}
