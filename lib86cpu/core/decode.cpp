/*
 * instruction decoder
 *
 * ergo720                Copyright (c) 2019
 */

#include "decode.h"
#include "internal.h"
#include "memory.h"
#include "support.h"


static ZydisFormatter formatter;

static const ZydisFormatterStyle to_zydis_instr_style[] = {
	ZYDIS_FORMATTER_STYLE_ATT,
	ZYDIS_FORMATTER_STYLE_INTEL
};

static const ZydisMachineMode to_zydis_cpu_mode[] = {
	ZYDIS_MACHINE_MODE_REAL_16,
	ZYDIS_MACHINE_MODE_REAL_16,
	ZYDIS_MACHINE_MODE_LEGACY_16,
	ZYDIS_MACHINE_MODE_LEGACY_32
};

static const ZydisAddressWidth to_zydis_addr_mode[] = {
	ZYDIS_ADDRESS_WIDTH_16,
	ZYDIS_ADDRESS_WIDTH_16,
	ZYDIS_ADDRESS_WIDTH_16,
	ZYDIS_ADDRESS_WIDTH_32
};

void
set_instr_format(cpu_t *cpu)
{
	[[maybe_unused]] auto status = ZydisFormatterInit(&formatter, to_zydis_instr_style[(cpu->cpu_flags & CPU_INTEL_SYNTAX) >> 1]);
	assert(ZYAN_SUCCESS(status));
	status = ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
	assert(ZYAN_SUCCESS(status));
	status = ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
	assert(ZYAN_SUCCESS(status));
}

std::string
log_instr(addr_t addr, ZydisDecodedInstruction *instr)
{
	char buffer[256];
	ZydisFormatterFormatInstruction(&formatter, instr, buffer, sizeof(buffer), addr);
	return buffer;
}

std::string
discard_instr_log(addr_t addr, ZydisDecodedInstruction *instr) { return std::string(); }

void
init_instr_decoder(disas_ctx_t *disas_ctx, ZydisDecoder *decoder)
{
	[[maybe_unused]] auto status = ZydisDecoderInit(decoder, to_zydis_cpu_mode[disas_ctx->flags & 3], to_zydis_addr_mode[disas_ctx->flags & 3]);
	assert(ZYAN_SUCCESS(status));
}

ZyanStatus
decode_instr(cpu_t *cpu, disas_ctx_t *disas_ctx, ZydisDecoder *decoder, ZydisDecodedInstruction *instr)
{
	uint8_t instr_buffer[X86_MAX_INSTR_LENGTH];
	disas_ctx->instr_buff_size = sizeof(instr_buffer);
	ram_fetch(cpu, disas_ctx, instr_buffer);

	return ZydisDecoderDecodeBuffer(decoder, instr_buffer, disas_ctx->instr_buff_size, instr);
}
