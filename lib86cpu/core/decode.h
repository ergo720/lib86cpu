/*
 * instruction decoding
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once

#include "lib86cpu_priv.h"
#include "Zydis/Zydis.h"
#include <stdint.h>

#define SIZE32 2
#define SIZE16 1
#define SIZE8  0
#define ADDR32 0
#define ADDR16 1


// Operand numbers
// NOTE for OPNUM_SINGLE: intel docs are not consistent for instr with a single op. Sometimes it's considered a src but in others
// it's considered a dst, so adding the src/dst prefix would be incorrect for some of those.
enum {
	OPNUM_DST = 0,
	OPNUM_SRC,
	OPNUM_THIRD,
	OPNUM_SINGLE = 0
};

void set_instr_format(cpu_t *cpu);
std::string log_instr(addr_t addr, ZydisDecodedInstruction *instr);
std::string discard_instr_log(addr_t addr, ZydisDecodedInstruction *instr);
void init_instr_decoder(disas_ctx_t *disas_ctx, ZydisDecoder *decoder);
ZyanStatus decode_instr(cpu_t *cpu, disas_ctx_t *disas_ctx, ZydisDecoder *decoder, ZydisDecodedInstruction *instr);

using instr_logfn_t = std::string(*)(addr_t, ZydisDecodedInstruction *);
inline instr_logfn_t instr_logfn = &discard_instr_log;
