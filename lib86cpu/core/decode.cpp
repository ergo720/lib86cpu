/*
 * instruction decoder
 *
 * ergo720                Copyright (c) 2019
 */

#include "decode.h"
#include "internal.h"
#include "memory_management.h"
#include "support.h"


static ZydisFormatter formatter;

static constexpr ZydisFormatterStyle to_zydis_instr_style[] = {
	ZYDIS_FORMATTER_STYLE_ATT,
	ZYDIS_FORMATTER_STYLE_INTEL_MASM,
	ZYDIS_FORMATTER_STYLE_INTEL,
	ZYDIS_FORMATTER_STYLE_INTEL, // default to intel with anything above max supported index
	ZYDIS_FORMATTER_STYLE_INTEL,
	ZYDIS_FORMATTER_STYLE_INTEL,
	ZYDIS_FORMATTER_STYLE_INTEL,
	ZYDIS_FORMATTER_STYLE_INTEL
};

static constexpr ZydisMachineMode to_zydis_cpu_mode[] = {
	ZYDIS_MACHINE_MODE_REAL_16,
	ZYDIS_MACHINE_MODE_REAL_16,
	ZYDIS_MACHINE_MODE_LEGACY_16,
	ZYDIS_MACHINE_MODE_LEGACY_32
};

static constexpr ZydisStackWidth to_zydis_stack_mode[] = {
	ZYDIS_STACK_WIDTH_16,
	ZYDIS_STACK_WIDTH_32,
	ZYDIS_STACK_WIDTH_32
};

void
set_instr_format(cpu_t *cpu)
{
	[[maybe_unused]] auto status = ZydisFormatterInit(&formatter, to_zydis_instr_style[cpu->cpu_flags & CPU_SYNTAX_MASK]);
	assert(ZYAN_SUCCESS(status));
	status = ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
	assert(ZYAN_SUCCESS(status));
	status = ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
	assert(ZYAN_SUCCESS(status));
}

std::string
log_instr(addr_t addr, decoded_instr *instr)
{
	char buffer[256];
	ZydisFormatterFormatInstruction(&formatter, &instr->i, instr->o, ZYDIS_MAX_OPERAND_COUNT, buffer, sizeof(buffer), addr, nullptr);
	return buffer;
}

std::string
discard_instr_log(addr_t addr, decoded_instr *instr) { return std::string(); }

void
init_instr_decoder(disas_ctx_t *disas_ctx, ZydisDecoder *decoder)
{
	[[maybe_unused]] auto status = ZydisDecoderInit(decoder, to_zydis_cpu_mode[(disas_ctx->flags & DISAS_FLG_CS32) | ((disas_ctx->flags & DISAS_FLG_PE) >> 3)],
		to_zydis_stack_mode[disas_ctx->flags & DISAS_FLG_SS32]);
	assert(ZYAN_SUCCESS(status));
}

ZyanStatus
decode_instr(cpu_t *cpu, disas_ctx_t *disas_ctx, ZydisDecoder *decoder, decoded_instr *instr)
{
	uint8_t instr_buffer[X86_MAX_INSTR_LENGTH];
	disas_ctx->instr_buff_size = sizeof(instr_buffer);
	ram_fetch(cpu, disas_ctx, instr_buffer);

	return ZydisDecoderDecodeFull(decoder, instr_buffer, disas_ctx->instr_buff_size, &instr->i, instr->o);
}
