/*
 * instruction decoding
 *
 * ergo720                Copyright (c) 2019
 * PatrickvL              Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#include "lib86cpu.h"
#include "isa.h"
#include "internal.h"
#include "decode.h"
#include "memory.h"


// Macro's to select either side of a tuple expressed as (left:right)
#define TUPLE_LEFT(L_R) (true?L_R)
#define TUPLE_RIGHT(L_R) (false?L_R)

// Bitfield extraction macro's
#define GET_SHIFT(TUPLE) TUPLE_LEFT(TUPLE)
#define GET_SIZE(TUPLE) TUPLE_RIGHT(TUPLE)
#define GET_MASK(TUPLE) ((1 << GET_SIZE(TUPLE)) - 1)
#define GET_FIELD(v, TUPLE) ((v >> GET_SHIFT(TUPLE)) & GET_MASK(TUPLE))
#define SET_FIELD(TUPLE, VALUE) (((uint64_t)VALUE) << GET_SHIFT(TUPLE)) // No need to mask when all uses stay within bounds (assert this?)

// Offset:Size tuples for bitfields :
#define X86_OPCODE 0:8 // [0-7] // Note : When opcode count surpasses 8 bits, update this mask AND x86_instr_flags!
#define X86_DECODE_CLASS 61:3 // [61-63] - classes defined below (X86_DECODE_CLASS_*)
#define X86_PREFIX_INDEX 58:3 // [58-60] - indexes in prefix_values[]
#define X86_PREFIX_VALUE 55:3 // [55-57] - writes to prefix_values[]
#define X86_DECODE_GROUP 57:4 // [57-60] - indexes in decode_tables[]
#define X86_DIFF_SYNTAX 56:5 // [56-60] - indexes in diff_syntax_opcodes[]
#define X86_FIXED_SIZE 52:4 // [52-55] - indexes in fixed_size_opcodes[]

#define X86_DECODE_CLASS_INVALID 0
#define X86_DECODE_CLASS_PREFIX 1 // prefix bytes, fetched in arch_x86_decode_instr()
#define X86_DECODE_CLASS_GROUP 2
#define X86_DECODE_CLASS_DIFF_SYNTAX 3 // instr has different syntax between Intel and AT&T
#define X86_DECODE_FIXED_SIZE 4 // instr ignores op size override prefix

#define X86_FIELD_DECODE_CLASS(VALUE) SET_FIELD(X86_DECODE_CLASS, VALUE)
#define X86_FIELD_PREFIX_INDEX(VALUE) SET_FIELD(X86_PREFIX_INDEX, VALUE)
#define X86_FIELD_PREFIX_VALUE(VALUE) SET_FIELD(X86_PREFIX_VALUE, VALUE)
#define X86_FIELD_DECODE_GROUP(VALUE) SET_FIELD(X86_DECODE_GROUP, VALUE)
#define X86_FIELD_DIFF_SYNTAX(VALUE) SET_FIELD(X86_DIFF_SYNTAX, VALUE)
#define X86_FIELD_FIXED_SIZE(VALUE) SET_FIELD(X86_FIXED_SIZE, VALUE)

/* Decoding markers checked in arch_x86_decode_instr() */
#define X86_OPC_UNDEFINED X86_FIELD_DECODE_CLASS(X86_DECODE_CLASS_INVALID) | X86_OPC_ILLEGAL // == 0, non-existent instruction - NO flags allowed!
#define X86_OPC_PREFIX(INDEX, VALUE) X86_FIELD_DECODE_CLASS(X86_DECODE_CLASS_PREFIX) | X86_FIELD_PREFIX_INDEX(INDEX) | X86_FIELD_PREFIX_VALUE(VALUE)
#define X86_OPC_GROUP(GROUP) X86_FIELD_DECODE_CLASS(X86_DECODE_CLASS_GROUP) | X86_FIELD_DECODE_GROUP(GROUP + 1) // Groups must be moved 1 step aside, since decode_tables[2] = grp1_decode_table, etc.
#define X86_OPC_DIFF_SYNTAX(INDEX) X86_FIELD_DECODE_CLASS(X86_DECODE_CLASS_DIFF_SYNTAX) | X86_FIELD_DIFF_SYNTAX(INDEX)
#define X86_OPC_FIXED_SIZE(INDEX) X86_FIELD_DECODE_CLASS(X86_DECODE_FIXED_SIZE) | X86_FIELD_FIXED_SIZE(INDEX)

/* Shorthand for common conditional instruction flags */
#define Jb (ADDRMOD_REL | WIDTH_BYTE)
#define Jv (ADDRMOD_REL | WIDTH_WORD)
#define Cv (ADDRMOD_RM_REG | WIDTH_WORD)
#define Sb (ADDRMOD_RM | WIDTH_BYTE)

static const uint64_t decode_table_one[256] = {
	/*[0x00]*/	X86_OPC_ADD | ADDRMOD_REG_RM | WIDTH_BYTE,
	/*[0x01]*/	X86_OPC_ADD | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0x02]*/	X86_OPC_ADD | ADDRMOD_RM_REG | WIDTH_BYTE,
	/*[0x03]*/	X86_OPC_ADD | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0x04]*/	X86_OPC_ADD | ADDRMOD_IMM_ACC | WIDTH_BYTE,
	/*[0x05]*/	X86_OPC_ADD | ADDRMOD_IMM_ACC | WIDTH_WORD,
	/*[0x06]*/	X86_OPC_PUSH | ADDRMOD_SEG2_REG /* ES */ | WIDTH_WORD,
	/*[0x07]*/	X86_OPC_POP | ADDRMOD_SEG2_REG /* ES */ | WIDTH_WORD,
	/*[0x08]*/	X86_OPC_OR | ADDRMOD_REG_RM | WIDTH_BYTE,
	/*[0x09]*/	X86_OPC_OR | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0x0A]*/	X86_OPC_OR | ADDRMOD_RM_REG | WIDTH_BYTE,
	/*[0x0B]*/	X86_OPC_OR | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0x0C]*/	X86_OPC_OR | ADDRMOD_IMM_ACC | WIDTH_BYTE,
	/*[0x0D]*/	X86_OPC_OR | ADDRMOD_IMM_ACC | WIDTH_WORD,
	/*[0x0E]*/	X86_OPC_PUSH | ADDRMOD_SEG2_REG /* CS */ | WIDTH_WORD,
	/*[0x0F]*/	X86_OPC_PREFIX(IS_TWO_BYTE_INSTR, 1),
	/*[0x10]*/	X86_OPC_ADC | ADDRMOD_REG_RM | WIDTH_BYTE,
	/*[0x11]*/	X86_OPC_ADC | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0x12]*/	X86_OPC_ADC | ADDRMOD_RM_REG | WIDTH_BYTE,
	/*[0x13]*/	X86_OPC_ADC | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0x14]*/	X86_OPC_ADC | ADDRMOD_IMM_ACC | WIDTH_BYTE,
	/*[0x15]*/	X86_OPC_ADC | ADDRMOD_IMM_ACC | WIDTH_WORD,
	/*[0x16]*/	X86_OPC_PUSH | ADDRMOD_SEG2_REG /* SS */ | WIDTH_WORD,
	/*[0x17]*/	X86_OPC_POP | ADDRMOD_SEG2_REG /* SS */ | WIDTH_WORD,
	/*[0x18]*/	X86_OPC_SBB | ADDRMOD_REG_RM | WIDTH_BYTE,
	/*[0x19]*/	X86_OPC_SBB | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0x1A]*/	X86_OPC_SBB | ADDRMOD_RM_REG | WIDTH_BYTE,
	/*[0x1B]*/	X86_OPC_SBB | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0x1C]*/	X86_OPC_SBB | ADDRMOD_IMM_ACC | WIDTH_BYTE,
	/*[0x1D]*/	X86_OPC_SBB | ADDRMOD_IMM_ACC | WIDTH_WORD,
	/*[0x1E]*/	X86_OPC_PUSH | ADDRMOD_SEG2_REG /* DS */ | WIDTH_WORD,
	/*[0x1F]*/	X86_OPC_POP | ADDRMOD_SEG2_REG /* DS */ | WIDTH_WORD,
	/*[0x20]*/	X86_OPC_AND | ADDRMOD_REG_RM | WIDTH_BYTE,
	/*[0x21]*/	X86_OPC_AND | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0x22]*/	X86_OPC_AND | ADDRMOD_RM_REG | WIDTH_BYTE,
	/*[0x23]*/	X86_OPC_AND | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0x24]*/	X86_OPC_AND | ADDRMOD_IMM_ACC | WIDTH_BYTE,
	/*[0x25]*/	X86_OPC_AND | ADDRMOD_IMM_ACC | WIDTH_WORD,
	/*[0x26]*/	X86_OPC_PREFIX(SEG_OVERRIDE, ES),
	/*[0x27]*/	X86_OPC_DAA | ADDRMOD_IMPLIED,
	/*[0x28]*/	X86_OPC_SUB | ADDRMOD_REG_RM | WIDTH_BYTE,
	/*[0x29]*/	X86_OPC_SUB | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0x2A]*/	X86_OPC_SUB | ADDRMOD_RM_REG | WIDTH_BYTE,
	/*[0x2B]*/	X86_OPC_SUB | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0x2C]*/	X86_OPC_SUB | ADDRMOD_IMM_ACC | WIDTH_BYTE,
	/*[0x2D]*/	X86_OPC_SUB | ADDRMOD_IMM_ACC | WIDTH_WORD,
	/*[0x2E]*/	X86_OPC_PREFIX(SEG_OVERRIDE, CS),
	/*[0x2F]*/	X86_OPC_DAS | ADDRMOD_IMPLIED,
	/*[0x30]*/	X86_OPC_XOR | ADDRMOD_REG_RM | WIDTH_BYTE,
	/*[0x31]*/	X86_OPC_XOR | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0x32]*/	X86_OPC_XOR | ADDRMOD_RM_REG | WIDTH_BYTE,
	/*[0x33]*/	X86_OPC_XOR | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0x34]*/	X86_OPC_XOR | ADDRMOD_IMM_ACC | WIDTH_BYTE,
	/*[0x35]*/	X86_OPC_XOR | ADDRMOD_IMM_ACC | WIDTH_WORD,
	/*[0x36]*/	X86_OPC_PREFIX(SEG_OVERRIDE, SS),
	/*[0x37]*/	X86_OPC_AAA | ADDRMOD_IMPLIED,
	/*[0x38]*/	X86_OPC_CMP | ADDRMOD_REG_RM | WIDTH_BYTE,
	/*[0x39]*/	X86_OPC_CMP | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0x3A]*/	X86_OPC_CMP | ADDRMOD_RM_REG | WIDTH_BYTE,
	/*[0x3B]*/	X86_OPC_CMP | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0x3C]*/	X86_OPC_CMP | ADDRMOD_IMM_ACC | WIDTH_BYTE,
	/*[0x3D]*/	X86_OPC_CMP | ADDRMOD_IMM_ACC | WIDTH_WORD,
	/*[0x3E]*/	X86_OPC_PREFIX(SEG_OVERRIDE, DS),
	/*[0x3F]*/	X86_OPC_AAS | ADDRMOD_IMPLIED,
	/*[0x40]*/	X86_OPC_INC | ADDRMOD_REG | WIDTH_WORD,
	/*[0x41]*/	X86_OPC_INC | ADDRMOD_REG | WIDTH_WORD,
	/*[0x42]*/	X86_OPC_INC | ADDRMOD_REG | WIDTH_WORD,
	/*[0x43]*/	X86_OPC_INC | ADDRMOD_REG | WIDTH_WORD,
	/*[0x44]*/	X86_OPC_INC | ADDRMOD_REG | WIDTH_WORD,
	/*[0x45]*/	X86_OPC_INC | ADDRMOD_REG | WIDTH_WORD,
	/*[0x46]*/	X86_OPC_INC | ADDRMOD_REG | WIDTH_WORD,
	/*[0x47]*/	X86_OPC_INC | ADDRMOD_REG | WIDTH_WORD,
	/*[0x48]*/	X86_OPC_DEC | ADDRMOD_REG | WIDTH_WORD,
	/*[0x49]*/	X86_OPC_DEC | ADDRMOD_REG | WIDTH_WORD,
	/*[0x4A]*/	X86_OPC_DEC | ADDRMOD_REG | WIDTH_WORD,
	/*[0x4B]*/	X86_OPC_DEC | ADDRMOD_REG | WIDTH_WORD,
	/*[0x4C]*/	X86_OPC_DEC | ADDRMOD_REG | WIDTH_WORD,
	/*[0x4D]*/	X86_OPC_DEC | ADDRMOD_REG | WIDTH_WORD,
	/*[0x4E]*/	X86_OPC_DEC | ADDRMOD_REG | WIDTH_WORD,
	/*[0x4F]*/	X86_OPC_DEC | ADDRMOD_REG | WIDTH_WORD,
	/*[0x50]*/	X86_OPC_PUSH | ADDRMOD_REG /* AX */ | WIDTH_WORD,
	/*[0x51]*/	X86_OPC_PUSH | ADDRMOD_REG /* CX */ | WIDTH_WORD,
	/*[0x52]*/	X86_OPC_PUSH | ADDRMOD_REG /* DX */ | WIDTH_WORD,
	/*[0x53]*/	X86_OPC_PUSH | ADDRMOD_REG /* BX */ | WIDTH_WORD,
	/*[0x54]*/	X86_OPC_PUSH | ADDRMOD_REG /* SP */ | WIDTH_WORD,
	/*[0x55]*/	X86_OPC_PUSH | ADDRMOD_REG /* BP */ | WIDTH_WORD,
	/*[0x56]*/	X86_OPC_PUSH | ADDRMOD_REG /* SI */ | WIDTH_WORD,
	/*[0x57]*/	X86_OPC_PUSH | ADDRMOD_REG /* DI */ | WIDTH_WORD,
	/*[0x58]*/	X86_OPC_POP | ADDRMOD_REG /* AX */  | WIDTH_WORD,
	/*[0x59]*/	X86_OPC_POP | ADDRMOD_REG /* CX */  | WIDTH_WORD,
	/*[0x5A]*/	X86_OPC_POP | ADDRMOD_REG /* DX */  | WIDTH_WORD,
	/*[0x5B]*/	X86_OPC_POP | ADDRMOD_REG /* BX */  | WIDTH_WORD,
	/*[0x5C]*/	X86_OPC_POP | ADDRMOD_REG /* SP */  | WIDTH_WORD,
	/*[0x5D]*/	X86_OPC_POP | ADDRMOD_REG /* BP */  | WIDTH_WORD,
	/*[0x5E]*/	X86_OPC_POP | ADDRMOD_REG /* SI */  | WIDTH_WORD,
	/*[0x5F]*/	X86_OPC_POP | ADDRMOD_REG /* DI */  | WIDTH_WORD,
	/*[0x60]*/	X86_OPC_PUSHA | ADDRMOD_IMPLIED | WIDTH_WORD,
	/*[0x61]*/	X86_OPC_POPA | ADDRMOD_IMPLIED | WIDTH_WORD,
	/*[0x62]*/	X86_OPC_DIFF_SYNTAX(0) | ADDRMOD_RM_REG,
	/*[0x63]*/	X86_OPC_FIXED_SIZE(0) | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0x64]*/	X86_OPC_PREFIX(SEG_OVERRIDE, FS),
	/*[0x65]*/	X86_OPC_PREFIX(SEG_OVERRIDE, GS),
	/*[0x66]*/	X86_OPC_PREFIX(OPERAND_SIZE_OVERRIDE, 1),
	/*[0x67]*/	X86_OPC_PREFIX(ADDRESS_SIZE_OVERRIDE, 1),
	/*[0x68]*/	X86_OPC_PUSH | ADDRMOD_IMM | WIDTH_WORD,
	/*[0x69]*/	X86_OPC_IMUL | ADDRMOD_RM_IMM_REG | WIDTH_WORD,
	/*[0x6A]*/	X86_OPC_PUSH | ADDRMOD_IMM | WIDTH_BYTE,
	/*[0x6B]*/	X86_OPC_IMUL | ADDRMOD_RM_IMM8_REG | WIDTH_WORD,
	/*[0x6C]*/	X86_OPC_INS | ADDRMOD_IMPLIED | WIDTH_BYTE,
	/*[0x6D]*/	X86_OPC_INS | ADDRMOD_IMPLIED | WIDTH_WORD,
	/*[0x6E]*/	X86_OPC_OUTS | ADDRMOD_IMPLIED | WIDTH_BYTE,
	/*[0x6F]*/	X86_OPC_OUTS | ADDRMOD_IMPLIED | WIDTH_WORD,
	/*[0x70]*/	X86_OPC_JO  | Jb,
	/*[0x71]*/	X86_OPC_JNO | Jb,
	/*[0x72]*/	X86_OPC_JC  | Jb,
	/*[0x73]*/	X86_OPC_JNC | Jb,
	/*[0x74]*/	X86_OPC_JZ  | Jb,
	/*[0x75]*/	X86_OPC_JNZ | Jb,
	/*[0x76]*/	X86_OPC_JBE | Jb,
	/*[0x77]*/	X86_OPC_JNBE  | Jb,
	/*[0x78]*/	X86_OPC_JS  | Jb,
	/*[0x79]*/	X86_OPC_JNS | Jb,
	/*[0x7A]*/	X86_OPC_JP | Jb,
	/*[0x7B]*/	X86_OPC_JNP | Jb,
	/*[0x7C]*/	X86_OPC_JL  | Jb,
	/*[0x7D]*/	X86_OPC_JNL | Jb,
	/*[0x7E]*/	X86_OPC_JLE | Jb,
	/*[0x7F]*/	X86_OPC_JNLE  | Jb,
	/*[0x80]*/	X86_OPC_GROUP(1) | ADDRMOD_IMM8_RM | WIDTH_BYTE,
	/*[0x81]*/	X86_OPC_GROUP(1) | ADDRMOD_IMM_RM | WIDTH_WORD,
	/*[0x82]*/	X86_OPC_GROUP(1) | ADDRMOD_IMM8_RM | WIDTH_BYTE,
	/*[0x83]*/	X86_OPC_GROUP(1) | ADDRMOD_IMM8_RM | WIDTH_WORD,
	/*[0x84]*/	X86_OPC_TEST | ADDRMOD_REG_RM | WIDTH_BYTE,
	/*[0x85]*/	X86_OPC_TEST | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0x86]*/	X86_OPC_XCHG | ADDRMOD_REG_RM | WIDTH_BYTE,
	/*[0x87]*/	X86_OPC_XCHG | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0x88]*/	X86_OPC_MOV | ADDRMOD_REG_RM | WIDTH_BYTE,
	/*[0x89]*/	X86_OPC_MOV | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0x8A]*/	X86_OPC_MOV | ADDRMOD_RM_REG | WIDTH_BYTE,
	/*[0x8B]*/	X86_OPC_MOV | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0x8C]*/	X86_OPC_FIXED_SIZE(1) | ADDRMOD_SEG3_REG_RM | WIDTH_WORD,
	/*[0x8D]*/	X86_OPC_LEA | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0x8E]*/	X86_OPC_FIXED_SIZE(1) | ADDRMOD_RM_SEG3_REG | WIDTH_WORD,
	/*[0x8F]*/	X86_OPC_POP | ADDRMOD_RM | WIDTH_WORD,
	/*[0x90]*/	X86_OPC_NOP | ADDRMOD_IMPLIED,	/* xchg eax, eax */
	/*[0x91]*/	X86_OPC_XCHG | ADDRMOD_ACC_REG | WIDTH_WORD,
	/*[0x92]*/	X86_OPC_XCHG | ADDRMOD_ACC_REG | WIDTH_WORD,
	/*[0x93]*/	X86_OPC_XCHG | ADDRMOD_ACC_REG | WIDTH_WORD,
	/*[0x94]*/	X86_OPC_XCHG | ADDRMOD_ACC_REG | WIDTH_WORD,
	/*[0x95]*/	X86_OPC_XCHG | ADDRMOD_ACC_REG | WIDTH_WORD,
	/*[0x96]*/	X86_OPC_XCHG | ADDRMOD_ACC_REG | WIDTH_WORD,
	/*[0x97]*/	X86_OPC_XCHG | ADDRMOD_ACC_REG | WIDTH_WORD,
	/*[0x98]*/	X86_OPC_DIFF_SYNTAX(1) | ADDRMOD_IMPLIED,
	/*[0x99]*/	X86_OPC_DIFF_SYNTAX(2) | ADDRMOD_IMPLIED,
	/*[0x9A]*/	X86_OPC_DIFF_SYNTAX(3) | ADDRMOD_FAR_PTR | WIDTH_WORD,
	/*[0x9B]*/	X86_OPC_UNDEFINED, // fpu
	/*[0x9C]*/	X86_OPC_PUSHF | ADDRMOD_IMPLIED,
	/*[0x9D]*/	X86_OPC_POPF | ADDRMOD_IMPLIED,
	/*[0x9E]*/	X86_OPC_SAHF | ADDRMOD_IMPLIED,
	/*[0x9F]*/	X86_OPC_LAHF | ADDRMOD_IMPLIED,
	/*[0xA0]*/	X86_OPC_MOV | ADDRMOD_MOFFSET_ACC | WIDTH_BYTE, /* load */
	/*[0xA1]*/	X86_OPC_MOV | ADDRMOD_MOFFSET_ACC | WIDTH_WORD, /* load */
	/*[0xA2]*/	X86_OPC_MOV | ADDRMOD_ACC_MOFFSET | WIDTH_BYTE, /* store */
	/*[0xA3]*/	X86_OPC_MOV | ADDRMOD_ACC_MOFFSET | WIDTH_WORD, /* store */
	/*[0xA4]*/	X86_OPC_MOVS | ADDRMOD_IMPLIED | WIDTH_BYTE,
	/*[0xA5]*/	X86_OPC_MOVS | ADDRMOD_IMPLIED | WIDTH_WORD,
	/*[0xA6]*/	X86_OPC_CMPS | ADDRMOD_IMPLIED | WIDTH_BYTE,
	/*[0xA7]*/	X86_OPC_CMPS | ADDRMOD_IMPLIED | WIDTH_WORD,
	/*[0xA8]*/	X86_OPC_TEST | ADDRMOD_IMM_ACC | WIDTH_BYTE,
	/*[0xA9]*/	X86_OPC_TEST | ADDRMOD_IMM_ACC | WIDTH_WORD,
	/*[0xAA]*/	X86_OPC_STOS | ADDRMOD_IMPLIED | WIDTH_BYTE,
	/*[0xAB]*/	X86_OPC_STOS | ADDRMOD_IMPLIED | WIDTH_WORD,
	/*[0xAC]*/	X86_OPC_LODS | ADDRMOD_IMPLIED | WIDTH_BYTE,
	/*[0xAD]*/	X86_OPC_LODS | ADDRMOD_IMPLIED | WIDTH_WORD,
	/*[0xAE]*/	X86_OPC_SCAS | ADDRMOD_IMPLIED | WIDTH_BYTE,
	/*[0xAF]*/	X86_OPC_SCAS | ADDRMOD_IMPLIED | WIDTH_WORD,
	/*[0xB0]*/	X86_OPC_MOV | ADDRMOD_IMM_REG | WIDTH_BYTE,
	/*[0xB1]*/	X86_OPC_MOV | ADDRMOD_IMM_REG | WIDTH_BYTE,
	/*[0xB2]*/	X86_OPC_MOV | ADDRMOD_IMM_REG | WIDTH_BYTE,
	/*[0xB3]*/	X86_OPC_MOV | ADDRMOD_IMM_REG | WIDTH_BYTE,
	/*[0xB4]*/	X86_OPC_MOV | ADDRMOD_IMM_REG | WIDTH_BYTE,
	/*[0xB5]*/	X86_OPC_MOV | ADDRMOD_IMM_REG | WIDTH_BYTE,
	/*[0xB6]*/	X86_OPC_MOV | ADDRMOD_IMM_REG | WIDTH_BYTE,
	/*[0xB7]*/	X86_OPC_MOV | ADDRMOD_IMM_REG | WIDTH_BYTE,
	/*[0xB8]*/	X86_OPC_MOV | ADDRMOD_IMM_REG | WIDTH_WORD,
	/*[0xB9]*/	X86_OPC_MOV | ADDRMOD_IMM_REG | WIDTH_WORD,
	/*[0xBA]*/	X86_OPC_MOV | ADDRMOD_IMM_REG | WIDTH_WORD,
	/*[0xBB]*/	X86_OPC_MOV | ADDRMOD_IMM_REG | WIDTH_WORD,
	/*[0xBC]*/	X86_OPC_MOV | ADDRMOD_IMM_REG | WIDTH_WORD,
	/*[0xBD]*/	X86_OPC_MOV | ADDRMOD_IMM_REG | WIDTH_WORD,
	/*[0xBE]*/	X86_OPC_MOV | ADDRMOD_IMM_REG | WIDTH_WORD,
	/*[0xBF]*/	X86_OPC_MOV | ADDRMOD_IMM_REG | WIDTH_WORD,
	/*[0xC0]*/	X86_OPC_GROUP(2) | ADDRMOD_IMM8_RM | WIDTH_BYTE,
	/*[0xC1]*/	X86_OPC_GROUP(2) | ADDRMOD_IMM8_RM | WIDTH_WORD,
	/*[0xC2]*/	X86_OPC_FIXED_SIZE(2) | ADDRMOD_IMM | WIDTH_WORD,
	/*[0xC3]*/	X86_OPC_RET | ADDRMOD_IMPLIED,
	/*[0xC4]*/	X86_OPC_LES | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0xC5]*/	X86_OPC_LDS | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0xC6]*/	X86_OPC_MOV | ADDRMOD_IMM8_RM | WIDTH_BYTE,
	/*[0xC7]*/	X86_OPC_MOV | ADDRMOD_IMM_RM | WIDTH_WORD,
	/*[0xC8]*/	X86_OPC_FIXED_SIZE(3) | ADDRMOD_IMM8_IMM16 | WIDTH_WORD,
	/*[0xC9]*/	X86_OPC_LEAVE | ADDRMOD_IMPLIED,
	/*[0xCA]*/	X86_OPC_DIFF_SYNTAX(4) | ADDRMOD_IMM | WIDTH_WORD,
	/*[0xCB]*/	X86_OPC_DIFF_SYNTAX(5) | ADDRMOD_IMPLIED,
	/*[0xCC]*/	X86_OPC_INT3 | ADDRMOD_IMPLIED,
	/*[0xCD]*/	X86_OPC_INT | ADDRMOD_IMM | WIDTH_BYTE,
	/*[0xCE]*/	X86_OPC_INTO | ADDRMOD_IMPLIED,
	/*[0xCF]*/	X86_OPC_IRET | ADDRMOD_IMPLIED,
	/*[0xD0]*/	X86_OPC_GROUP(2) | ADDRMOD_RM | WIDTH_BYTE,
	/*[0xD1]*/	X86_OPC_GROUP(2) | ADDRMOD_RM | WIDTH_WORD,
	/*[0xD2]*/	X86_OPC_GROUP(2) | ADDRMOD_RM | WIDTH_BYTE,
	/*[0xD3]*/	X86_OPC_GROUP(2) | ADDRMOD_RM | WIDTH_WORD,
	/*[0xD4]*/	X86_OPC_AAM | ADDRMOD_IMM | WIDTH_BYTE,
	/*[0xD5]*/	X86_OPC_AAD | ADDRMOD_IMM | WIDTH_BYTE,
	/*[0xD6]*/	X86_OPC_UNDEFINED, // SALC undocumented instr, should add this?
	/*[0xD7]*/	X86_OPC_XLATB | ADDRMOD_IMPLIED,
	/*[0xD8]*/	X86_OPC_UNDEFINED, // fpu
	/*[0xD9]*/	X86_OPC_UNDEFINED, // fpu
	/*[0xDA]*/	X86_OPC_UNDEFINED, // fpu
	/*[0xDB]*/	X86_OPC_UNDEFINED, // fpu
	/*[0xDC]*/	X86_OPC_UNDEFINED, // fpu
	/*[0xDD]*/	X86_OPC_UNDEFINED, // fpu
	/*[0xDE]*/	X86_OPC_UNDEFINED, // fpu
	/*[0xDF]*/	X86_OPC_UNDEFINED, // fpu
	/*[0xE0]*/	X86_OPC_LOOPNE | ADDRMOD_REL | WIDTH_BYTE,
	/*[0xE1]*/	X86_OPC_LOOPE | ADDRMOD_REL | WIDTH_BYTE,
	/*[0xE2]*/	X86_OPC_LOOP | ADDRMOD_REL | WIDTH_BYTE,
	/*[0xE3]*/	X86_OPC_JECXZ | Jb,
	/*[0xE4]*/	X86_OPC_IN | ADDRMOD_IMM | WIDTH_BYTE,
	/*[0xE5]*/	X86_OPC_IN | ADDRMOD_IMM8 | WIDTH_WORD,
	/*[0xE6]*/	X86_OPC_OUT | ADDRMOD_IMM | WIDTH_BYTE,
	/*[0xE7]*/	X86_OPC_OUT | ADDRMOD_IMM8 | WIDTH_WORD,
	/*[0xE8]*/	X86_OPC_CALL | Jv,
	/*[0xE9]*/	X86_OPC_JMP  | Jv,
	/*[0xEA]*/	X86_OPC_DIFF_SYNTAX(6) | ADDRMOD_FAR_PTR | WIDTH_WORD,
	/*[0xEB]*/	X86_OPC_JMP  | Jb,
	/*[0xEC]*/	X86_OPC_IN | ADDRMOD_IMPLIED | WIDTH_BYTE,
	/*[0xED]*/	X86_OPC_IN | ADDRMOD_IMPLIED | WIDTH_WORD,
	/*[0xEE]*/	X86_OPC_OUT | ADDRMOD_IMPLIED | WIDTH_BYTE,
	/*[0xEF]*/	X86_OPC_OUT | ADDRMOD_IMPLIED | WIDTH_WORD,
	/*[0xF0]*/	X86_OPC_PREFIX(LOCK_PREFIX, 1),
	/*[0xF1]*/	X86_OPC_UNDEFINED, // INT1 undocumented instr, should add this?
	/*[0xF2]*/	X86_OPC_PREFIX(REP_OVERRIDE, REPNZ_PREFIX), /* REPNE/REPNZ */
	/*[0xF3]*/	X86_OPC_PREFIX(REP_OVERRIDE, REPZ_PREFIX), /* REP/REPE/REPZ */
	/*[0xF4]*/	X86_OPC_HLT | ADDRMOD_IMPLIED,
	/*[0xF5]*/	X86_OPC_CMC | ADDRMOD_IMPLIED,
	/*[0xF6]*/	X86_OPC_GROUP(3) | ADDRMOD_RM | WIDTH_BYTE,
	/*[0xF7]*/	X86_OPC_GROUP(3) | ADDRMOD_RM | WIDTH_WORD,
	/*[0xF8]*/	X86_OPC_CLC | ADDRMOD_IMPLIED,
	/*[0xF9]*/	X86_OPC_STC | ADDRMOD_IMPLIED,
	/*[0xFA]*/	X86_OPC_CLI | ADDRMOD_IMPLIED,
	/*[0xFB]*/	X86_OPC_STI | ADDRMOD_IMPLIED,
	/*[0xFC]*/	X86_OPC_CLD | ADDRMOD_IMPLIED,
	/*[0xFD]*/	X86_OPC_STD | ADDRMOD_IMPLIED,
	/*[0xFE]*/	X86_OPC_GROUP(4) | ADDRMOD_RM | WIDTH_BYTE,
	/*[0xFF]*/	X86_OPC_GROUP(5) | ADDRMOD_RM | WIDTH_WORD,
};

static const uint64_t decode_table_two[256] = {
	/*[0x00]*/	X86_OPC_GROUP(6) | ADDRMOD_RM | WIDTH_WORD,
	/*[0x01]*/	X86_OPC_GROUP(7) | ADDRMOD_RM | WIDTH_WORD,
	/*[0x02]*/	X86_OPC_LAR | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0x03]*/	X86_OPC_LSL | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0x04]*/	X86_OPC_UNDEFINED,
	/*[0x05]*/	X86_OPC_UNDEFINED,
	/*[0x06]*/	X86_OPC_CLTS | ADDRMOD_IMPLIED,
	/*[0x07]*/	X86_OPC_UNDEFINED,
	/*[0x08]*/	X86_OPC_INVD | ADDRMOD_IMPLIED,
	/*[0x09]*/	X86_OPC_WBINVD | ADDRMOD_IMPLIED,
	/*[0x0A]*/	X86_OPC_UNDEFINED,
	/*[0x0B]*/	X86_OPC_UD2 | ADDRMOD_IMPLIED,
	/*[0x0C]*/	X86_OPC_UNDEFINED,
	/*[0x0D]*/	X86_OPC_UNDEFINED,
	/*[0x0E]*/	X86_OPC_UNDEFINED,
	/*[0x0F]*/	X86_OPC_UNDEFINED,
	/*[0x10]*/	X86_OPC_UNDEFINED, // sse
	/*[0x11]*/	X86_OPC_UNDEFINED, // sse
	/*[0x12]*/	X86_OPC_UNDEFINED, // sse
	/*[0x13]*/	X86_OPC_UNDEFINED, // sse
	/*[0x14]*/	X86_OPC_UNDEFINED, // sse
	/*[0x15]*/	X86_OPC_UNDEFINED, // sse
	/*[0x16]*/	X86_OPC_UNDEFINED, // sse
	/*[0x17]*/	X86_OPC_UNDEFINED, // sse
	/*[0x18]*/	X86_OPC_UNDEFINED, // sse
	/*[0x19]*/	X86_OPC_UNDEFINED,
	/*[0x1A]*/	X86_OPC_UNDEFINED,
	/*[0x1B]*/	X86_OPC_UNDEFINED,
	/*[0x1C]*/	X86_OPC_UNDEFINED,
	/*[0x1D]*/	X86_OPC_UNDEFINED,
	/*[0x1E]*/	X86_OPC_UNDEFINED,
	/*[0x1F]*/	X86_OPC_UNDEFINED,
	/*[0x20]*/	X86_OPC_FIXED_SIZE(1) | ADDRMOD_CR_RM | WIDTH_DWORD,
	/*[0x21]*/	X86_OPC_FIXED_SIZE(1) | ADDRMOD_DBG_RM | WIDTH_DWORD,
	/*[0x22]*/	X86_OPC_FIXED_SIZE(1) | ADDRMOD_RM_CR | WIDTH_DWORD,
	/*[0x23]*/	X86_OPC_FIXED_SIZE(1) | ADDRMOD_RM_DBG | WIDTH_DWORD,
	/*[0x24]*/	X86_OPC_UNDEFINED,
	/*[0x25]*/	X86_OPC_UNDEFINED,
	/*[0x26]*/	X86_OPC_UNDEFINED,
	/*[0x27]*/	X86_OPC_UNDEFINED,
	/*[0x28]*/	X86_OPC_UNDEFINED, // sse
	/*[0x29]*/	X86_OPC_UNDEFINED, // sse
	/*[0x2A]*/	X86_OPC_UNDEFINED, // sse
	/*[0x2B]*/	X86_OPC_UNDEFINED, // sse
	/*[0x2C]*/	X86_OPC_UNDEFINED, // sse
	/*[0x2D]*/	X86_OPC_UNDEFINED, // sse
	/*[0x2E]*/	X86_OPC_UNDEFINED, // sse
	/*[0x2F]*/	X86_OPC_UNDEFINED, // sse
	/*[0x30]*/	X86_OPC_WRMSR | ADDRMOD_IMPLIED,
	/*[0x31]*/	X86_OPC_RDTSC | ADDRMOD_IMPLIED,
	/*[0x32]*/	X86_OPC_RDMSR | ADDRMOD_IMPLIED,
	/*[0x33]*/	X86_OPC_RDPMC | ADDRMOD_IMPLIED,
	/*[0x34]*/	X86_OPC_SYSENTER | ADDRMOD_IMPLIED,
	/*[0x35]*/	X86_OPC_SYSEXIT | ADDRMOD_IMPLIED,
	/*[0x36]*/	X86_OPC_UNDEFINED,
	/*[0x37]*/	X86_OPC_UNDEFINED,
	/*[0x38]*/	X86_OPC_UNDEFINED,
	/*[0x39]*/	X86_OPC_UNDEFINED,
	/*[0x3A]*/	X86_OPC_UNDEFINED,
	/*[0x3B]*/	X86_OPC_UNDEFINED,
	/*[0x3C]*/	X86_OPC_UNDEFINED,
	/*[0x3D]*/	X86_OPC_UNDEFINED,
	/*[0x3E]*/	X86_OPC_UNDEFINED,
	/*[0x3F]*/	X86_OPC_UNDEFINED,
	/*[0x40]*/	X86_OPC_CMOVO  | Cv,
	/*[0x41]*/	X86_OPC_CMOVNO | Cv,
	/*[0x42]*/	X86_OPC_CMOVB  | Cv,
	/*[0x43]*/	X86_OPC_CMOVNB | Cv,
	/*[0x44]*/	X86_OPC_CMOVZ  | Cv,
	/*[0x45]*/	X86_OPC_CMOVNE | Cv,
	/*[0x46]*/	X86_OPC_CMOVBE | Cv,
	/*[0x47]*/	X86_OPC_CMOVA  | Cv,
	/*[0x48]*/	X86_OPC_CMOVS  | Cv,
	/*[0x49]*/	X86_OPC_CMOVNS | Cv,
	/*[0x4A]*/	X86_OPC_CMOVPE | Cv,
	/*[0x4B]*/	X86_OPC_CMOVPO | Cv,
	/*[0x4C]*/	X86_OPC_CMOVL  | Cv,
	/*[0x4D]*/	X86_OPC_CMOVGE | Cv,
	/*[0x4E]*/	X86_OPC_CMOVLE | Cv,
	/*[0x4F]*/	X86_OPC_CMOVG  | Cv,
	/*[0x50]*/	X86_OPC_UNDEFINED, // sse
	/*[0x51]*/	X86_OPC_UNDEFINED, // sse
	/*[0x52]*/	X86_OPC_UNDEFINED, // sse
	/*[0x53]*/	X86_OPC_UNDEFINED, // sse
	/*[0x54]*/	X86_OPC_UNDEFINED, // sse
	/*[0x55]*/	X86_OPC_UNDEFINED, // sse
	/*[0x56]*/	X86_OPC_UNDEFINED, // sse
	/*[0x57]*/	X86_OPC_UNDEFINED, // sse
	/*[0x58]*/	X86_OPC_UNDEFINED, // sse
	/*[0x59]*/	X86_OPC_UNDEFINED, // sse
	/*[0x5A]*/	X86_OPC_UNDEFINED,
	/*[0x5B]*/	X86_OPC_UNDEFINED,
	/*[0x5C]*/	X86_OPC_UNDEFINED, // sse
	/*[0x5D]*/	X86_OPC_UNDEFINED, // sse
	/*[0x5E]*/	X86_OPC_UNDEFINED, // sse
	/*[0x5F]*/	X86_OPC_UNDEFINED, // sse
	/*[0x60]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x61]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x62]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x63]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x64]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x65]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x66]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x67]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x68]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x69]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x6A]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x6B]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x6C]*/	X86_OPC_UNDEFINED,
	/*[0x6D]*/	X86_OPC_UNDEFINED,
	/*[0x6E]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x6F]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x70]*/	X86_OPC_UNDEFINED, // sse
	/*[0x71]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x72]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x73]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x74]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x75]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x76]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x77]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x78]*/	X86_OPC_UNDEFINED,
	/*[0x79]*/	X86_OPC_UNDEFINED,
	/*[0x7A]*/	X86_OPC_UNDEFINED,
	/*[0x7B]*/	X86_OPC_UNDEFINED,
	/*[0x7C]*/	X86_OPC_UNDEFINED,
	/*[0x7D]*/	X86_OPC_UNDEFINED,
	/*[0x7E]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x7F]*/	X86_OPC_UNDEFINED, // mmx
	/*[0x80]*/	X86_OPC_JO  | Jv,
	/*[0x81]*/	X86_OPC_JNO | Jv,
	/*[0x82]*/	X86_OPC_JC  | Jv,
	/*[0x83]*/	X86_OPC_JNC | Jv,
	/*[0x84]*/	X86_OPC_JZ  | Jv,
	/*[0x85]*/	X86_OPC_JNZ | Jv,
	/*[0x86]*/	X86_OPC_JBE | Jv,
	/*[0x87]*/	X86_OPC_JNBE | Jv,
	/*[0x88]*/	X86_OPC_JS  | Jv,
	/*[0x89]*/	X86_OPC_JNS | Jv,
	/*[0x8A]*/	X86_OPC_JP | Jv,
	/*[0x8B]*/	X86_OPC_JNP | Jv,
	/*[0x8C]*/	X86_OPC_JL  | Jv,
	/*[0x8D]*/	X86_OPC_JNL | Jv,
	/*[0x8E]*/	X86_OPC_JLE | Jv,
	/*[0x8F]*/	X86_OPC_JNLE | Jv,
	/*[0x90]*/	X86_OPC_SETO  | Sb,
	/*[0x91]*/	X86_OPC_SETNO | Sb,
	/*[0x92]*/	X86_OPC_SETB  | Sb,
	/*[0x93]*/	X86_OPC_SETNB | Sb,
	/*[0x94]*/	X86_OPC_SETZ  | Sb,
	/*[0x95]*/	X86_OPC_SETNE | Sb,
	/*[0x96]*/	X86_OPC_SETBE | Sb,
	/*[0x97]*/	X86_OPC_SETA  | Sb,
	/*[0x98]*/	X86_OPC_SETS  | Sb,
	/*[0x99]*/	X86_OPC_SETNS | Sb,
	/*[0x9A]*/	X86_OPC_SETPE | Sb,
	/*[0x9B]*/	X86_OPC_SETPO | Sb,
	/*[0x9C]*/	X86_OPC_SETL  | Sb,
	/*[0x9D]*/	X86_OPC_SETGE | Sb,
	/*[0x9E]*/	X86_OPC_SETLE | Sb,
	/*[0x9F]*/	X86_OPC_SETG  | Sb,
	/*[0xA0]*/	X86_OPC_PUSH | ADDRMOD_SEG3_REG /* FS */ | WIDTH_WORD,
	/*[0xA1]*/	X86_OPC_POP | ADDRMOD_SEG3_REG /* FS */ | WIDTH_WORD,
	/*[0xA2]*/	X86_OPC_CPUID | ADDRMOD_IMPLIED,
	/*[0xA3]*/	X86_OPC_BT | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0xA4]*/	X86_OPC_SHLD | ADDRMOD_REG_IMM8_RM | WIDTH_WORD,
	/*[0xA5]*/	X86_OPC_SHLD | ADDRMOD_REG_CL_RM | WIDTH_WORD,
	/*[0xA6]*/	X86_OPC_UNDEFINED,
	/*[0xA7]*/	X86_OPC_UNDEFINED,
	/*[0xA8]*/	X86_OPC_PUSH | ADDRMOD_SEG3_REG /* GS */ | WIDTH_WORD,
	/*[0xA9]*/	X86_OPC_POP | ADDRMOD_SEG3_REG /* GS */ | WIDTH_WORD,
	/*[0xAA]*/	X86_OPC_RSM | ADDRMOD_IMPLIED,
	/*[0xAB]*/	X86_OPC_BTS | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0xAC]*/	X86_OPC_SHRD | ADDRMOD_REG_IMM8_RM | WIDTH_WORD,
	/*[0xAD]*/	X86_OPC_SHRD | ADDRMOD_REG_CL_RM | WIDTH_WORD,
	/*[0xAE]*/	X86_OPC_UNDEFINED, // fpu, sse
	/*[0xAF]*/	X86_OPC_IMUL | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0xB0]*/	X86_OPC_CMPXCHG | ADDRMOD_REG_RM | WIDTH_BYTE,
	/*[0xB1]*/	X86_OPC_CMPXCHG | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0xB2]*/	X86_OPC_LSS | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0xB3]*/	X86_OPC_BTR | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0xB4]*/	X86_OPC_LFS | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0xB5]*/	X86_OPC_LGS | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0xB6]*/	X86_OPC_DIFF_SYNTAX(7) | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0xB7]*/	X86_OPC_DIFF_SYNTAX(8) | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0xB8]*/	X86_OPC_UNDEFINED,
	/*[0xB9]*/	X86_OPC_UD1 | ADDRMOD_IMPLIED,
	/*[0xBA]*/	X86_OPC_GROUP(8) | ADDRMOD_IMM8_RM | WIDTH_WORD,
	/*[0xBB]*/	X86_OPC_BTC | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0xBC]*/	X86_OPC_BSF | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0xBD]*/	X86_OPC_BSR | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0xBE]*/	X86_OPC_DIFF_SYNTAX(9) | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0xBF]*/	X86_OPC_DIFF_SYNTAX(10) | ADDRMOD_RM_REG | WIDTH_WORD,
	/*[0xC0]*/	X86_OPC_XADD | ADDRMOD_REG_RM | WIDTH_BYTE,
	/*[0xC1]*/	X86_OPC_XADD | ADDRMOD_REG_RM | WIDTH_WORD,
	/*[0xC2]*/	X86_OPC_UNDEFINED, // sse
	/*[0xC3]*/	X86_OPC_UNDEFINED,
	/*[0xC4]*/	X86_OPC_UNDEFINED, // sse
	/*[0xC5]*/	X86_OPC_UNDEFINED, // sse
	/*[0xC6]*/	X86_OPC_UNDEFINED, // sse
	/*[0xC7]*/	X86_OPC_GROUP(9) | ADDRMOD_RM,
	/*[0xC8]*/	X86_OPC_BSWAP | ADDRMOD_REG | WIDTH_WORD,
	/*[0xC9]*/	X86_OPC_BSWAP | ADDRMOD_REG | WIDTH_WORD,
	/*[0xCA]*/	X86_OPC_BSWAP | ADDRMOD_REG | WIDTH_WORD,
	/*[0xCB]*/	X86_OPC_BSWAP | ADDRMOD_REG | WIDTH_WORD,
	/*[0xCC]*/	X86_OPC_BSWAP | ADDRMOD_REG | WIDTH_WORD,
	/*[0xCD]*/	X86_OPC_BSWAP | ADDRMOD_REG | WIDTH_WORD,
	/*[0xCE]*/	X86_OPC_BSWAP | ADDRMOD_REG | WIDTH_WORD,
	/*[0xCF]*/	X86_OPC_BSWAP | ADDRMOD_REG | WIDTH_WORD,
	/*[0xD0]*/	X86_OPC_UNDEFINED,
	/*[0xD1]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xD2]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xD3]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xD4]*/	X86_OPC_UNDEFINED,
	/*[0xD5]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xD6]*/	X86_OPC_UNDEFINED,
	/*[0xD7]*/	X86_OPC_UNDEFINED, // sse
	/*[0xD8]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xD9]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xDA]*/	X86_OPC_UNDEFINED, // sse
	/*[0xDB]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xDC]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xDD]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xDE]*/	X86_OPC_UNDEFINED, // sse
	/*[0xDF]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xE0]*/	X86_OPC_UNDEFINED, // sse
	/*[0xE1]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xE2]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xE3]*/	X86_OPC_UNDEFINED, // sse
	/*[0xE4]*/	X86_OPC_UNDEFINED, // sse
	/*[0xE5]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xE6]*/	X86_OPC_UNDEFINED,
	/*[0xE7]*/	X86_OPC_UNDEFINED, // sse
	/*[0xE8]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xE9]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xEA]*/	X86_OPC_UNDEFINED, // sse
	/*[0xEB]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xEC]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xED]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xEE]*/	X86_OPC_UNDEFINED, // sse
	/*[0xEF]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xF0]*/	X86_OPC_UNDEFINED,
	/*[0xF1]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xF2]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xF3]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xF4]*/	X86_OPC_UNDEFINED,
	/*[0xF5]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xF6]*/	X86_OPC_UNDEFINED, // sse
	/*[0xF7]*/	X86_OPC_UNDEFINED, // sse
	/*[0xF8]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xF9]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xFA]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xFB]*/	X86_OPC_UNDEFINED,
	/*[0xFC]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xFD]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xFE]*/	X86_OPC_UNDEFINED, // mmx
	/*[0xFF]*/	X86_OPC_UNDEFINED,
};

static const uint64_t grp1_decode_table[8] = { // X86_OPC_GROUP(1)
	/*[0x00]*/	X86_OPC_ADD,
	/*[0x01]*/	X86_OPC_OR,
	/*[0x02]*/	X86_OPC_ADC,
	/*[0x03]*/	X86_OPC_SBB,
	/*[0x04]*/	X86_OPC_AND,
	/*[0x05]*/	X86_OPC_SUB,
	/*[0x06]*/	X86_OPC_XOR,
	/*[0x07]*/	X86_OPC_CMP,
};

static const uint64_t grp2_decode_table[8] = { // X86_OPC_GROUP(2)
	/*[0x00]*/	X86_OPC_ROL,
	/*[0x01]*/	X86_OPC_ROR,
	/*[0x02]*/	X86_OPC_RCL,
	/*[0x03]*/	X86_OPC_RCR,
	/*[0x04]*/	X86_OPC_SHL,
	/*[0x05]*/	X86_OPC_SHR,
	/*[0x06]*/	X86_OPC_UNDEFINED,
	/*[0x07]*/	X86_OPC_SAR,
};

static const uint64_t grp3_decode_table[8] = { // X86_OPC_GROUP(3)
	/*[0x00]*/	X86_OPC_TEST | ADDRMOD_IMM_RM,
	/*[0x01]*/	X86_OPC_UNDEFINED,
	/*[0x02]*/	X86_OPC_NOT,
	/*[0x03]*/	X86_OPC_NEG,
	/*[0x04]*/	X86_OPC_MUL,
	/*[0x05]*/	X86_OPC_IMUL,
	/*[0x06]*/	X86_OPC_DIV,
	/*[0x07]*/	X86_OPC_IDIV,
};

static const uint64_t grp4_decode_table[8] = { // X86_OPC_GROUP(4)
	/*[0x00]*/	X86_OPC_INC,
	/*[0x01]*/	X86_OPC_DEC,
	/*[0x02]*/	X86_OPC_UNDEFINED,
	/*[0x03]*/	X86_OPC_UNDEFINED,
	/*[0x04]*/	X86_OPC_UNDEFINED,
	/*[0x05]*/	X86_OPC_UNDEFINED,
	/*[0x06]*/	X86_OPC_UNDEFINED,
	/*[0x07]*/	X86_OPC_UNDEFINED,
};

static const uint64_t grp5_decode_table[8] = { // X86_OPC_GROUP(5)
	/*[0x00]*/	X86_OPC_INC,
	/*[0x01]*/	X86_OPC_DEC,
	/*[0x02]*/	X86_OPC_CALL,
	/*[0x03]*/	X86_OPC_DIFF_SYNTAX(11),
	/*[0x04]*/	X86_OPC_JMP,
	/*[0x05]*/	X86_OPC_DIFF_SYNTAX(12),
	/*[0x06]*/	X86_OPC_PUSH,
	/*[0x07]*/	X86_OPC_UNDEFINED,
};

static const uint64_t grp6_decode_table[8] = { // X86_OPC_GROUP(6)
	/*[0x00]*/	X86_OPC_FIXED_SIZE(4),
	/*[0x01]*/	X86_OPC_FIXED_SIZE(5),
	/*[0x02]*/	X86_OPC_FIXED_SIZE(6),
	/*[0x03]*/	X86_OPC_FIXED_SIZE(7),
	/*[0x04]*/	X86_OPC_FIXED_SIZE(8),
	/*[0x05]*/	X86_OPC_FIXED_SIZE(9),
	/*[0x06]*/	X86_OPC_UNDEFINED,
	/*[0x07]*/	X86_OPC_UNDEFINED,
};

static const uint64_t grp7_decode_table[8] = { // X86_OPC_GROUP(7)
	/*[0x00]*/	X86_OPC_DIFF_SYNTAX(13),
	/*[0x01]*/	X86_OPC_DIFF_SYNTAX(14),
	/*[0x02]*/	X86_OPC_DIFF_SYNTAX(15),
	/*[0x03]*/	X86_OPC_DIFF_SYNTAX(16),
	/*[0x04]*/	X86_OPC_FIXED_SIZE(10),
	/*[0x05]*/	X86_OPC_UNDEFINED,
	/*[0x06]*/	X86_OPC_FIXED_SIZE(11),
	/*[0x07]*/	X86_OPC_INVLPG | WIDTH_BYTE,
};

static const uint64_t grp8_decode_table[8] = { // X86_OPC_GROUP(8)
	/*[0x00]*/	X86_OPC_UNDEFINED,
	/*[0x01]*/	X86_OPC_UNDEFINED,
	/*[0x02]*/	X86_OPC_UNDEFINED,
	/*[0x03]*/	X86_OPC_UNDEFINED,
	/*[0x04]*/	X86_OPC_BT,
	/*[0x05]*/	X86_OPC_BTS,
	/*[0x06]*/	X86_OPC_BTR,
	/*[0x07]*/	X86_OPC_BTC,
};

static const uint64_t grp9_decode_table[8] = { // X86_OPC_GROUP(9)
	/*[0x00]*/	X86_OPC_UNDEFINED,
	/*[0x01]*/	X86_OPC_CMPXCHG8B,
	/*[0x02]*/	X86_OPC_UNDEFINED,
	/*[0x03]*/	X86_OPC_UNDEFINED,
	/*[0x04]*/	X86_OPC_UNDEFINED,
	/*[0x05]*/	X86_OPC_UNDEFINED,
	/*[0x06]*/	X86_OPC_UNDEFINED,
	/*[0x07]*/	X86_OPC_UNDEFINED,
};

static const uint64_t *decode_tables[11] = {
	decode_table_one,
	decode_table_two,
	grp1_decode_table,
	grp2_decode_table,
	grp3_decode_table,
	grp4_decode_table,
	grp5_decode_table,
	grp6_decode_table,
	grp7_decode_table,
	grp8_decode_table,
	grp9_decode_table,
};

// offset 0 = AT&T 16 bit, 1 = AT&T sintax 32 bit, 2 = Intel syntax 16 bit , 3 = Intel syntax 32 bit
static const uint64_t diff_syntax_flags_0x62[4] = { WIDTH_WORD, WIDTH_DWORD, WIDTH_DWORD, WIDTH_QWORD };

static const arch_x86_opcode diff_syntax_opcodes[17][4] = { // Opcodes for all elements marked with X86_OPC_DIFF_SYNTAX
	// decode_table_one :
	/*[ 0=0x62]*/	{ X86_OPC_BOUND, X86_OPC_BOUND, X86_OPC_BOUND, X86_OPC_BOUND }, // marked X86_OPC_DIFF_SYNTAX for diff_syntax_flags_0x62 (all use X86_OPC_BOUND)
	/*[ 1=0x98]*/	{ X86_OPC_CBTV, X86_OPC_CWTL, X86_OPC_CBW, X86_OPC_CWDE },
	/*[ 2=0x99]*/	{ X86_OPC_CWTD, X86_OPC_CLTD, X86_OPC_CWD, X86_OPC_CDQ  },
	/*[ 3=0x9A]*/	{ X86_OPC_LCALL, X86_OPC_LCALL, X86_OPC_CALL, X86_OPC_CALL }, // Identical to 0x03
	/*[ 4=0xCA]*/	{ X86_OPC_LRET, X86_OPC_LRET, X86_OPC_RETF, X86_OPC_RETF }, // Identical to 0xCB \_
	/*[ 5=0xCB]*/	{ X86_OPC_LRET, X86_OPC_LRET, X86_OPC_RETF, X86_OPC_RETF }, // Identical to 0xCA /
	/*[ 6=0xEA]*/	{ X86_OPC_LJMP, X86_OPC_LJMP, X86_OPC_JMP, X86_OPC_JMP }, // Identical to 0x05
	// decode_table_two :
	/*[ 7=0xB6]*/	{ X86_OPC_MOVZXB, X86_OPC_MOVZXB, X86_OPC_MOVZX, X86_OPC_MOVZX }, // Identical to 0xB7 \_
	/*[ 8=0xB7]*/	{ X86_OPC_MOVZXW, X86_OPC_MOVZXW, X86_OPC_MOVZX, X86_OPC_MOVZX }, // Identical to 0xB6 /
	/*[ 9=0xBE]*/	{ X86_OPC_MOVSXB, X86_OPC_MOVSXB, X86_OPC_MOVSX, X86_OPC_MOVSX }, // Identical to 0xBF \_
	/*[10=0xBF]*/	{ X86_OPC_MOVSXW, X86_OPC_MOVSXW, X86_OPC_MOVSX, X86_OPC_MOVSX }, // Identical to 0xBE /
	// grp5_decode_table :
	/*[11=0x03]*/	{ X86_OPC_LCALL, X86_OPC_LCALL, X86_OPC_CALL, X86_OPC_CALL }, // Identical to 0x9A
	/*[12=0x05]*/	{ X86_OPC_LJMP, X86_OPC_LJMP, X86_OPC_JMP, X86_OPC_JMP }, // Identical to 0xEA
	// grp7_decode_table :
	/*[13=0x00]*/	{ X86_OPC_SGDTW, X86_OPC_SGDTL, X86_OPC_SGDTW, X86_OPC_SGDTD },
	/*[14=0x01]*/	{ X86_OPC_SIDTW, X86_OPC_SIDTL, X86_OPC_SIDTW, X86_OPC_SIDTD },
	/*[15=0x02]*/	{ X86_OPC_LGDTW, X86_OPC_LGDTL, X86_OPC_LGDTW, X86_OPC_LGDTD },
	/*[16=0x03]*/	{ X86_OPC_LIDTW, X86_OPC_LIDTL, X86_OPC_LIDTW, X86_OPC_LIDTD },
};

static const arch_x86_opcode fixed_size_opcodes[12] = {
	/*[0=0x63]*/             X86_OPC_ARPL,
	/*[0=0x8C/8E/0F20-23]*/  X86_OPC_MOV,
	/*[0=0xC2]*/             X86_OPC_RET,
	/*[0=0xC8]*/             X86_OPC_ENTER,
	/*[0=0x0000]*/           X86_OPC_SLDT,
	/*[0=0x0008]*/           X86_OPC_STR,
	/*[0=0x0010]*/           X86_OPC_LLDT,
	/*[0=0x0018]*/           X86_OPC_LTR,
	/*[0=0x0020]*/           X86_OPC_VERR,
	/*[0=0x0028]*/           X86_OPC_VERW,
	/*[0=0x0120]*/           X86_OPC_SMSW,
	/*[0=0x0130]*/           X86_OPC_LMSW,
};

static void
decode_third_operand(struct x86_instr *instr)
{
	struct x86_operand *operand = &instr->operand[OPNUM_THIRD];

	switch (instr->flags & OP3_MASK) {
	case OP3_NONE:
		break;
	case OP3_IMM:
	case OP3_IMM8:
		operand->type	= OPTYPE_IMM;
		operand->imm	= instr->imm_data[0];
		break;
	case OP3_CL:
		operand->type	= OPTYPE_REG8;
		operand->reg	= 1; /* CL */
		break;
	default:
		break;
	}
}

static uint8_t
decode_dst_reg(struct x86_instr *instr)
{
	if (!(instr->flags & MOD_RM))
		return instr->opcode_byte & 0x07;

	if (instr->flags & DIR_REVERSED)
		return instr->rm;

	return instr->reg_opc;
}

static uint8_t
decode_dst_mem(struct x86_instr *instr)
{
	if (instr->flags & DIR_REVERSED)
		return instr->rm;

	return instr->reg_opc;
}

static void
decode_dst_operand(struct x86_instr *instr)
{
	struct x86_operand *operand = &instr->operand[OPNUM_DST];

	switch (instr->flags & DST_MASK) {
	case DST_NONE:
		break;
	case DST_IMM16:
		operand->type	= OPTYPE_IMM;
		operand->imm	= instr->imm_data[1];
		break;
	case DST_REG:
		operand->type	= OPTYPE_REG;
		operand->reg	= decode_dst_reg(instr);
		break;
	case DST_SEG3_REG:
		operand->type	= OPTYPE_SEG_REG;
		operand->reg	= instr->reg_opc;
		break;
	case DST_CR_REG:
		operand->type	= OPTYPE_CR_REG;
		operand->reg	= instr->reg_opc;
		break;
	case DST_DBG_REG:
		operand->type	= OPTYPE_DBG_REG;
		operand->reg	= instr->reg_opc;
		break;
	case DST_ACC:
		operand->type	= OPTYPE_REG;
		operand->reg	= 0; /* AL/AX/EAX */
		break;
	case DST_MOFFSET:
		operand->type	= OPTYPE_MOFFSET;
		operand->disp	= instr->disp;
		break;
	case DST_MEM:
		if (instr->flags & SIB) {
			operand->type = OPTYPE_SIB_MEM;
		}
		else {
			operand->type = OPTYPE_MEM;
			operand->reg = decode_dst_mem(instr);
		}
		break;
	case DST_MEM_DISP_BYTE:
	case DST_MEM_DISP_WORD:
	case DST_MEM_DISP_DWORD:
		if (instr->flags & SIB) {
			operand->type = OPTYPE_SIB_DISP;
			operand->disp = instr->disp;
		}
		else {
			operand->type = OPTYPE_MEM_DISP;
			operand->reg = instr->rm;
			operand->disp = instr->disp;
		}
		break;
	default:
		break;
	}
}

static uint8_t
decode_src_reg(struct x86_instr *instr)
{
	if (!(instr->flags & MOD_RM))
		return instr->opcode_byte & 0x07;

	if (instr->flags & DIR_REVERSED)
		return instr->reg_opc;

	return instr->rm;
}

static uint8_t
decode_src_mem(struct x86_instr* instr)
{
	if (instr->flags & DIR_REVERSED)
		return instr->reg_opc;

	return instr->rm;
}

static void
decode_src_operand(struct x86_instr *instr)
{
	struct x86_operand *operand = &instr->operand[OPNUM_SRC];

	switch (instr->flags & SRC_MASK) {
	case SRC_NONE:
		break;
	case SRC_REL:
		operand->type	= OPTYPE_REL;
		operand->rel	= instr->rel_data[0];
		break;
	case SRC_IMM:
	case SRC_IMM8:
		operand->type	= OPTYPE_IMM;
		operand->imm	= instr->imm_data[0];
		break;
	case SRC_IMM48:
		operand->type	= OPTYPE_FAR_PTR;
		operand->imm	= instr->imm_data[0];
		operand->seg_sel = instr->imm_data[1];
		break;
	case SRC_REG:
		operand->type	= OPTYPE_REG;
		operand->reg	= decode_src_reg(instr);
		break;
	case SRC_SEG2_REG:
		operand->type	= OPTYPE_SEG_REG;
		operand->reg	= instr->opcode_byte >> 3;
		break;
	case SRC_SEG3_REG:
		operand->type	= OPTYPE_SEG_REG;
		if (instr->flags & MOD_RM) {
			operand->reg = instr->reg_opc;
		}
		else {
			operand->reg = (instr->opcode_byte & 0x38) >> 3;
		}
		break;
	case SRC_CR_REG:
		operand->type	= OPTYPE_CR_REG;
		operand->reg	= instr->reg_opc;
		break;
	case SRC_DBG_REG:
		operand->type	= OPTYPE_DBG_REG;
		operand->reg	= instr->reg_opc;
		break;
	case SRC_ACC:
		operand->type	= OPTYPE_REG;
		operand->reg	= 0; /* AL/AX/EAX */
		break;
	case SRC_MOFFSET:
		operand->type	= OPTYPE_MOFFSET;
		operand->disp	= instr->disp;
		break;
	case SRC_MEM:
		if (instr->flags & SIB) {
			operand->type = OPTYPE_SIB_MEM;
		}
		else {
			operand->type = OPTYPE_MEM;
			operand->reg = decode_src_mem(instr);
		}
		break;
	case SRC_MEM_DISP_BYTE:
	case SRC_MEM_DISP_WORD:
	case SRC_MEM_DISP_DWORD:
		if (instr->flags & SIB) {
			operand->type = OPTYPE_SIB_DISP;
			operand->disp = instr->disp;
		}
		else {
			operand->type = OPTYPE_MEM_DISP;
			operand->reg = instr->rm;
			operand->disp = instr->disp;
		}
		break;
	default:
		break;
	}
}

static void
decode_imm(cpu_t *cpu, struct x86_instr *instr, disas_ctx_t *disas_ctx, uint8_t page_cross)
{
	switch (instr->flags & (SRC_IMM8 | SRC_IMM48 | OP3_IMM_MASK | DST_IMM16)) {
	case SRC_IMM8:
		instr->imm_data[0] = ram_fetch<uint8_t>(cpu, disas_ctx, page_cross);
		return;
	case SRC_IMM48: // far JMP and far CALL instr
		if (instr->flags & WIDTH_DWORD) {
			instr->imm_data[0] = ram_fetch<uint32_t>(cpu, disas_ctx, page_cross);
		}
		else {
			instr->imm_data[0] = ram_fetch<uint16_t>(cpu, disas_ctx, page_cross);
		}
		instr->imm_data[1] = ram_fetch<uint16_t>(cpu, disas_ctx, page_cross);
		return;
	case SRC_IMM8|DST_IMM16: // ENTER instr
		instr->imm_data[1] = ram_fetch<uint16_t>(cpu, disas_ctx, page_cross);
		instr->imm_data[0] = ram_fetch<uint8_t>(cpu, disas_ctx, page_cross);
		return;
	case OP3_IMM8:
		instr->imm_data[0] = ram_fetch<uint8_t>(cpu, disas_ctx, page_cross);
		return;
	case OP3_IMM:
		if (instr->flags & WIDTH_DWORD) {
			instr->imm_data[0] = ram_fetch<uint32_t>(cpu, disas_ctx, page_cross);
		}
		else {
			instr->imm_data[0] = ram_fetch<uint16_t>(cpu, disas_ctx, page_cross);
		}
		return;
	default:
		break;
	}

	switch (instr->flags & WIDTH_MASK) {
	// TODO case WIDTH_QWORD:
	case WIDTH_DWORD:
		instr->imm_data[0] = ram_fetch<uint32_t>(cpu, disas_ctx, page_cross);
		break;
	case WIDTH_WORD:
		instr->imm_data[0] = ram_fetch<uint16_t>(cpu, disas_ctx, page_cross);
		break;
	case WIDTH_BYTE:
		instr->imm_data[0] = ram_fetch<uint8_t>(cpu, disas_ctx, page_cross);
		break;
	default:
		break;
	}
}

static void
decode_rel(cpu_t *cpu, struct x86_instr *instr, disas_ctx_t *disas_ctx, uint8_t page_cross)
{
	switch (instr->flags & WIDTH_MASK) {
	// TODO case WIDTH_QWORD:
	case WIDTH_DWORD:
		instr->rel_data[0] = static_cast<int32_t>(ram_fetch<uint32_t>(cpu, disas_ctx, page_cross));
		break;
	case WIDTH_WORD:
		instr->rel_data[0] = static_cast<int16_t>(ram_fetch<uint16_t>(cpu, disas_ctx, page_cross));
		break;
	case WIDTH_BYTE:
		instr->rel_data[0] = static_cast<int8_t>(ram_fetch<uint8_t>(cpu, disas_ctx, page_cross));
		break;
	default:
		break;
	}
}

static void
decode_moffset(cpu_t *cpu, struct x86_instr *instr, disas_ctx_t *disas_ctx, uint8_t page_cross)
{
	if (instr->addr_size_override ^ (disas_ctx->flags & DISAS_FLG_CS32)) {
		instr->disp = ram_fetch<uint32_t>(cpu, disas_ctx, page_cross);
	}
	else {
		instr->disp = ram_fetch<uint16_t>(cpu, disas_ctx, page_cross);
	}
}

static void
decode_disp(cpu_t *cpu, struct x86_instr *instr, disas_ctx_t *disas_ctx, uint8_t page_cross)
{
	switch (instr->flags & MEM_DISP_MASK) {
	case SRC_MEM_DISP_DWORD:
	case DST_MEM_DISP_DWORD:
		instr->disp = static_cast<int32_t>(ram_fetch<uint32_t>(cpu, disas_ctx, page_cross));
		break;
	case SRC_MEM_DISP_WORD:
	case DST_MEM_DISP_WORD:
		instr->disp	= static_cast<int16_t>(ram_fetch<uint16_t>(cpu, disas_ctx, page_cross));
		break;
	case SRC_MEM_DISP_BYTE:
	case DST_MEM_DISP_BYTE:
		instr->disp	= static_cast<int8_t>(ram_fetch<uint8_t>(cpu, disas_ctx, page_cross));
		break;
	}
}

static const uint64_t sib_dst_decode[] = {
	/*[0x00]*/	DST_MEM_DISP_DWORD,
	/*[0x01]*/	DST_MEM_DISP_BYTE,
	/*[0x02]*/	DST_MEM_DISP_DWORD,
};

static const uint64_t sib_src_decode[] = {
	/*[0x00]*/	SRC_MEM_DISP_DWORD,
	/*[0x01]*/	SRC_MEM_DISP_BYTE,
	/*[0x02]*/	SRC_MEM_DISP_DWORD,
};

static void
decode_sib_byte(struct x86_instr *instr, uint8_t sib)
{
	instr->scale = (sib & 0xc0) >> 6;
	instr->idx = (sib & 0x38) >> 3;
	instr->base = (sib & 0x07);

	if (instr->base == 5) {
		if (instr->flags & DIR_REVERSED) {
			instr->flags &= ~DST_MEM;
			instr->flags |= sib_dst_decode[instr->mod];
		}
		else {
			instr->flags &= ~SRC_MEM;
			instr->flags |= sib_src_decode[instr->mod];
		}
	}
}

static const uint64_t mod_dst_decode[] = {
	/*[0x00]*/	DST_MEM,
	/*[0x01]*/	DST_MEM_DISP_BYTE,
	/*[0x02]*/	0,
	/*[0x03]*/	DST_REG,
};

static const uint64_t mod_src_decode[] = {
	/*[0x00]*/	SRC_MEM,
	/*[0x01]*/	SRC_MEM_DISP_BYTE,
	/*[0x02]*/	0,
	/*[0x03]*/	SRC_REG,
};

static void
decode_modrm_fields(struct x86_instr *instr, uint8_t modrm)
{
	instr->mod = (modrm & 0xc0) >> 6;
	instr->reg_opc = (modrm & 0x38) >> 3;
	instr->rm = (modrm & 0x07);
}

#define RM_SIZE_SHIFT 16
#define RM_SIZE (1 << RM_SIZE_SHIFT)

#define RM_MOD_SHIFT 8
#define RM_MOD_0 (0 << RM_MOD_SHIFT) // TODO : Rename
#define RM_MOD_1 (1 << RM_MOD_SHIFT) // TODO : Rename
#define RM_MOD_2 (2 << RM_MOD_SHIFT) // TODO : Rename

static void
decode_modrm_addr_modes(struct x86_instr *instr, uint8_t prot)
{
	if (instr->flags & DIR_REVERSED) {
		instr->flags |= mod_dst_decode[instr->mod];
		switch (((instr->addr_size_override ^ prot) << RM_SIZE_SHIFT) | (instr->mod << RM_MOD_SHIFT) | instr->rm) {
		case 0 | RM_MOD_2 | RM_SIZE: // fallthrough
		case 1 | RM_MOD_2 | RM_SIZE: // fallthrough
		case 2 | RM_MOD_2 | RM_SIZE: // fallthrough
		case 3 | RM_MOD_2 | RM_SIZE: // fallthrough
		case 5 | RM_MOD_2 | RM_SIZE: // fallthrough
		case 6 | RM_MOD_2 | RM_SIZE: // fallthrough
		case 7 | RM_MOD_2 | RM_SIZE:
			instr->flags |= DST_MEM_DISP_DWORD;
			break;
		case 0 | RM_MOD_2: // fallthrough
		case 1 | RM_MOD_2: // fallthrough
		case 2 | RM_MOD_2: // fallthrough
		case 3 | RM_MOD_2: // fallthrough
		case 4 | RM_MOD_2: // fallthrough
		case 5 | RM_MOD_2: // fallthrough
		case 6 | RM_MOD_2: // fallthrough
		case 7 | RM_MOD_2:
			instr->flags |= DST_MEM_DISP_WORD;
			break;
		case 4 | RM_MOD_0 | RM_SIZE: // fallthrough
		case 4 | RM_MOD_1 | RM_SIZE:
			instr->flags |= SIB;
			break;
		case 4 | RM_MOD_2 | RM_SIZE:
			instr->flags |= (DST_MEM_DISP_DWORD | SIB);
			break;
		case 5 | RM_MOD_0 | RM_SIZE:
			instr->flags &= ~DST_MEM;
			instr->flags |= DST_MEM_DISP_DWORD;
			break;
		case 6 | RM_MOD_0:
			instr->flags &= ~DST_MEM;
			instr->flags |= DST_MEM_DISP_WORD;
			break;
		default:
			break;
		}
	}
	else {
		instr->flags |= mod_src_decode[instr->mod];
		switch (((instr->addr_size_override ^ prot) << RM_SIZE_SHIFT) | (instr->mod << RM_MOD_SHIFT) | instr->rm) {
		case 0 | RM_MOD_2 | RM_SIZE: // fallthrough
		case 1 | RM_MOD_2 | RM_SIZE: // fallthrough
		case 2 | RM_MOD_2 | RM_SIZE: // fallthrough
		case 3 | RM_MOD_2 | RM_SIZE: // fallthrough
		case 5 | RM_MOD_2 | RM_SIZE: // fallthrough
		case 6 | RM_MOD_2 | RM_SIZE: // fallthrough
		case 7 | RM_MOD_2 | RM_SIZE:
			instr->flags |= SRC_MEM_DISP_DWORD;
			break;
		case 0 | RM_MOD_2: // fallthrough
		case 1 | RM_MOD_2: // fallthrough
		case 2 | RM_MOD_2: // fallthrough
		case 3 | RM_MOD_2: // fallthrough
		case 4 | RM_MOD_2: // fallthrough
		case 5 | RM_MOD_2: // fallthrough
		case 6 | RM_MOD_2: // fallthrough
		case 7 | RM_MOD_2:
			instr->flags |= SRC_MEM_DISP_WORD;
			break;
		case 4 | RM_MOD_0 | RM_SIZE: // fallthrough
		case 4 | RM_MOD_1 | RM_SIZE:
			instr->flags |= SIB;
			break;
		case 4 | RM_MOD_2 | RM_SIZE:
			instr->flags |= (SRC_MEM_DISP_DWORD | SIB);
			break;
		case 5 | RM_MOD_0 | RM_SIZE:
			instr->flags &= ~SRC_MEM;
			instr->flags |= SRC_MEM_DISP_DWORD;
			break;
		case 6 | RM_MOD_0:
			instr->flags &= ~SRC_MEM;
			instr->flags |= SRC_MEM_DISP_WORD;
			break;
		default:
			break;
		}
	}
}

static void
set_instr_seg(x86_instr *instr, uint8_t pe)
{
	uint8_t seg = DS;

	if (instr->seg_override != DEFAULT) {
		instr->seg = instr->seg_override;
		return;
	}
	else if (instr->mod == 3) {
		instr->seg = seg;
		return;
	}

	switch (instr->addr_size_override ^ pe)
	{
	case 0: { // 16 addr mode
		switch (instr->rm)
		{
		case 2:
		case 3:
			seg = SS;
			break;

		case 6:
			if (instr->mod != 0) {
				seg = SS;
			}
			break;
		}
	}
	break;

	case 1: { // 32 addr mode
		switch (instr->rm)
		{
		case 4:
			if (instr->base == 4 || instr->base == 5) {
				seg = SS;
			}
			break;

		case 5:
			if (instr->mod != 0) {
				seg = SS;
			}
			break;
		}
	}
	break;

	}

	instr->seg = seg;
}

void
decode_instr(cpu_t *cpu, x86_instr *instr, disas_ctx_t *disas_ctx)
{
	unsigned decode_group;
	uint8_t instr_byte, no_fixed_size;
	uint64_t decode;
	arch_x86_opcode opcode;
	uint8_t bits, page_cross;
	char use_intel;

	// Start decoding here, initially using decode_table_one :
	disas_ctx->start_pc = disas_ctx->virt_pc;
	page_cross = (disas_ctx->virt_pc & ~PAGE_MASK) != ((disas_ctx->virt_pc + X86_MAX_INSTR_LENGTH - 1) & ~PAGE_MASK);
#if DEBUG_LOG
	disas_ctx->byte_idx = 0;
#endif
	decode_group = 0;
	no_fixed_size = 1;
	use_intel = (cpu->cpu_flags & CPU_INTEL_SYNTAX) >> CPU_INTEL_SYNTAX_SHIFT;
	instr->seg_override = DEFAULT;
	instr_byte = ram_fetch<uint8_t>(cpu, disas_ctx, page_cross);
	while(true) {
		decode = decode_tables[decode_group][instr_byte];
		opcode = (arch_x86_opcode)GET_FIELD(decode, X86_OPCODE);
		if (opcode == 0) {
			switch (GET_FIELD(decode, X86_DECODE_CLASS)) {
			case X86_DECODE_CLASS_INVALID:
				// This handles all occurences of X86_OPC_UNDEFINED :
				// TODO: actually this should raise an UD exception for illegal opcodes
				LIB86CPU_ABORT_msg("Illegal or not implemented opcode 0x%x\n", instr_byte);
			case X86_DECODE_CLASS_PREFIX: // TODO : Honor maximum number of prefix bytes per prefix group
				// All prefix bytes set an instruction variable to some value and will fetch and decode another byte :
				bits = GET_FIELD(decode, X86_PREFIX_INDEX);
				instr->prefix_values[bits] = GET_FIELD(decode, X86_PREFIX_VALUE);
				// Recognize prefix byte 0x0F; Run the next byte through decode_table_two :
				if (instr_byte == 0x0F) // Equivalent to: if (bits == IS_TWO_BYTE_INSTR)
					decode_group = 1; // Use decode_table_two (instr->is_two_byte_instr is already set above via prefix_values[])
				instr_byte = ram_fetch<uint8_t>(cpu, disas_ctx, page_cross);
				continue; // repeat loop
			case X86_DECODE_CLASS_GROUP:
				// Do an extension group side-step, by repeating the decodeing using the indicated group and index :
				instr->opcode_byte = instr_byte;
				instr->flags = decode; // Initially, use the flags mentioned together with the group reference (group entries may have deviations)
				decode_modrm_fields(instr, ram_fetch<uint8_t>(cpu, disas_ctx, page_cross));
				decode_group = GET_FIELD(decode, X86_DECODE_GROUP);
				instr_byte = instr->reg_opc;
				continue; // repeat loop
			case X86_DECODE_CLASS_DIFF_SYNTAX:
				// Calculate diff_syntax_* last dimension index : 0 = AT&T 16 bit, 1 = AT&T sintax 32 bit, 2 = Intel syntax 16 bit , 3 = Intel syntax 32 bit
				bits = (instr->op_size_override ^ (disas_ctx->flags & DISAS_FLG_CS32)) | (use_intel << 1);
				opcode = diff_syntax_opcodes[GET_FIELD(decode, X86_DIFF_SYNTAX)][bits];
				if (instr_byte == 0x62)
					instr->flags |= diff_syntax_flags_0x62[bits];
				else if (instr_byte == 0xCA)
					no_fixed_size = 0;
				break;
			case X86_DECODE_FIXED_SIZE:
				no_fixed_size = 0;
				opcode = fixed_size_opcodes[GET_FIELD(decode, X86_FIXED_SIZE)];
				break;
			// No default
			}
		}
		break; // leave loop
	}

	instr->opcode = opcode;
	if (decode_group <= 1) { // Did we read from decode_table_one or decode_table_two?
		instr->opcode_byte = instr_byte;
		instr->flags |= decode & ~GET_MASK(X86_OPCODE);
		if (instr->flags & MOD_RM) {
			decode_modrm_fields(instr, ram_fetch<uint8_t>(cpu, disas_ctx, page_cross));
			decode_modrm_addr_modes(instr, disas_ctx->flags & DISAS_FLG_CS32);
		}
	} else { // Read from grp*_decode_table
		// Mask away (initially set) width flags, if the group entry also has a width flag :
		if (decode & WIDTH_MASK)
			instr->flags &= ~WIDTH_MASK;
		// Mask away (initially set) addressing mode flags, if the group entry also has address mode flags :
		if (decode & ADDRMOD_MASK)
			instr->flags &= ~ADDRMOD_MASK;
		instr->flags |= decode & ~GET_MASK(X86_OPCODE);
		decode_modrm_addr_modes(instr, disas_ctx->flags & DISAS_FLG_CS32);
	}

	if (no_fixed_size && (instr->op_size_override ^ (disas_ctx->flags & DISAS_FLG_CS32))) {
		if (instr->flags & WIDTH_WORD) {
			instr->flags &= ~WIDTH_WORD;
			instr->flags |= WIDTH_DWORD;
		}
	}

	if (instr->flags & SIB)
		decode_sib_byte(instr, ram_fetch<uint8_t>(cpu, disas_ctx, page_cross));

	if (instr->flags & MEM_DISP_MASK)
		decode_disp(cpu, instr, disas_ctx, page_cross);

	if (instr->flags & MOFFSET_MASK)
		decode_moffset(cpu, instr, disas_ctx, page_cross);

	if (instr->flags & IMM_MASK)
		decode_imm(cpu, instr, disas_ctx, page_cross);

	if (instr->flags & REL_MASK)
		decode_rel(cpu, instr, disas_ctx, page_cross);

	set_instr_seg(instr, disas_ctx->flags & DISAS_FLG_CS32);

	decode_src_operand(instr);

	decode_dst_operand(instr);

	decode_third_operand(instr);

	instr->nr_bytes = static_cast<unsigned long>(disas_ctx->virt_pc - disas_ctx->start_pc);
	disas_ctx->flags |= (disas_ctx->instr_page_addr != ((disas_ctx->start_pc + instr->nr_bytes - 1) & ~PAGE_MASK)) << 1;
	disas_ctx->instr_page_addr = disas_ctx->start_pc & ~PAGE_MASK;
}

int
get_instr_length(struct x86_instr *instr)
{
	return instr->nr_bytes;
}
