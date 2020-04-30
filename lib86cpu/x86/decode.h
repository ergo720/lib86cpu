/*
 * instruction decoding
 *
 * ergo720                Copyright (c) 2019
 * PatrickvL              Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#pragma once

#include "lib86cpu.h"
#include <stdint.h>

#define SIZE32 0
#define SIZE16 1
#define SIZE8  2
#define ADDR32 0
#define ADDR16 1


enum x86_operand_type {
	OPTYPE_IMM,
	OPTYPE_MEM,
	OPTYPE_MOFFSET,
	OPTYPE_MEM_DISP,
	OPTYPE_REG,
	OPTYPE_REG8,
	OPTYPE_SEG_REG,
	OPTYPE_CR_REG,
	OPTYPE_DBG_REG,
	OPTYPE_REL,
	OPTYPE_FAR_PTR,
	OPTYPE_SIB_MEM,
	OPTYPE_SIB_DISP,
};

// must have the same order used by cpu->regs_layout
enum x86_segment : uint8_t {
	ES,
	CS,
	SS,
	DS,
	FS,
	GS,
	DEFAULT,
};

enum x86_rep_prefix {
	NO_PREFIX,
	REPNZ_PREFIX,
	REPZ_PREFIX,
};

struct x86_operand {
	x86_operand_type type;
	uint8_t       reg;
	uint16_t      seg_sel;
	int32_t	      disp; /* address displacement can be negative */
	union {
		uint32_t  imm;
		int32_t   rel;
	};
};

enum x86_instr_flags : uint64_t {
    MOD_RM              = (1ULL << 8),
    SIB                 = (1ULL << 9),
	DIR_REVERSED        = (1ULL << 10),

	/* Operand sizes */
	WIDTH_BYTE          = (1ULL << 11), /* 8 bits */
	WIDTH_WORD          = (1ULL << 12), /* 16 bits */
	WIDTH_DWORD         = (1ULL << 13), /* 32 bits */
	WIDTH_QWORD         = (1ULL << 14), /* 64 bits */
	WIDTH_MASK          = WIDTH_BYTE|WIDTH_WORD|WIDTH_DWORD, // TODO : |WIDTH_QWORD

	/* Source operand */
	SRC_NONE            = (1ULL << 15),

	SRC_IMM             = (1ULL << 16),
	SRC_IMM8            = (1ULL << 17),
	SRC_IMM48           = (1ULL << 18),
	SRC_IMM_MASK        = SRC_IMM|SRC_IMM8|SRC_IMM48,

	SRC_REL             = (1ULL << 19),
	SRC_REG             = (1ULL << 20),
	SRC_SEG2_REG        = (1ULL << 21),
	SRC_SEG3_REG        = (1ULL << 22),
	SRC_ACC             = (1ULL << 23),
	SRC_MEM             = (1ULL << 24),
	SRC_MOFFSET         = (1ULL << 25),

	SRC_MEM_DISP_BYTE   = (1ULL << 26), /* 8 bits */
	SRC_MEM_DISP_WORD   = (1ULL << 27), /* 16 bits */
	SRC_MEM_DISP_DWORD  = (1ULL << 28), /* 32 bits */
	SRC_MEM_DISP_MASK   = SRC_MEM_DISP_BYTE|SRC_MEM_DISP_WORD|SRC_MEM_DISP_DWORD,

	SRC_CR_REG          = (1ULL << 29),
	SRC_DBG_REG         = (1ULL << 30),
	SRC_MASK            = SRC_NONE|SRC_IMM_MASK|SRC_REL|SRC_REG|SRC_SEG2_REG|SRC_SEG3_REG|SRC_ACC|SRC_MEM|SRC_MOFFSET|SRC_MEM_DISP_MASK|SRC_CR_REG|SRC_DBG_REG,

	/* Destination operand */
	DST_NONE            = (1ULL << 31),

	DST_IMM16           = (1ULL << 32),
	DST_REG             = (1ULL << 33),
	DST_ACC             = (1ULL << 34), /* AL/AX/EAX */
	DST_MEM             = (1ULL << 35),
	DST_MOFFSET         = (1ULL << 36),

	DST_MEM_DISP_BYTE   = (1ULL << 37), /* 8 bits */
	DST_MEM_DISP_WORD   = (1ULL << 38), /* 16 bits */
	DST_MEM_DISP_DWORD  = (1ULL << 39), /* 32 bits */
	DST_MEM_DISP_MASK   = DST_MEM_DISP_BYTE|DST_MEM_DISP_WORD|DST_MEM_DISP_DWORD,

	DST_SEG3_REG        = (1ULL << 40),
	DST_CR_REG          = (1ULL << 41),
	DST_DBG_REG         = (1ULL << 42),
	DST_MASK            = DST_NONE|DST_IMM16|DST_REG|DST_ACC|DST_MEM|DST_MOFFSET|DST_MEM_DISP_MASK|DST_SEG3_REG|DST_CR_REG|DST_DBG_REG,

	/* Third operand */
	OP3_NONE            = (1ULL << 43),

	OP3_IMM             = (1ULL << 44),
	OP3_IMM8            = (1ULL << 45),
	OP3_CL              = (1ULL << 46),
	OP3_IMM_MASK        = OP3_IMM|OP3_IMM8,

	OP3_MASK            = OP3_NONE|OP3_IMM_MASK|OP3_CL,

	/* Adressing masks */
	MEM_DISP_MASK       = SRC_MEM_DISP_MASK|DST_MEM_DISP_MASK,

	MOFFSET_MASK        = SRC_MOFFSET|DST_MOFFSET,

	IMM_MASK            = SRC_IMM_MASK|OP3_IMM_MASK,

	REL_MASK            = SRC_REL,

	ADDRMOD_MASK        = MOD_RM|DIR_REVERSED|SRC_MASK|DST_MASK|OP3_MASK, // All flags except SIB and all WIDTH_* flags
};

/*
 *	Addressing modes.
 */
enum x86_addrmod : uint64_t {
	ADDRMOD_ACC_MOFFSET = SRC_ACC|DST_MOFFSET|OP3_NONE,              /* AL/AX/EAX -> moffset */
	ADDRMOD_ACC_REG     = SRC_ACC|DST_REG|OP3_NONE,                  /* AL/AX/EAX -> reg */
	ADDRMOD_IMM         = SRC_IMM|DST_NONE|OP3_NONE,                 /* immediate operand */
	ADDRMOD_IMM8        = SRC_IMM8|DST_NONE|OP3_NONE,                /* immediate8 operand */
	ADDRMOD_IMM8_RM     = SRC_IMM8|MOD_RM|DIR_REVERSED|OP3_NONE,     /* immediate8 -> register/memory */
	ADDRMOD_IMM_RM      = SRC_IMM|MOD_RM|DIR_REVERSED|OP3_NONE,      /* immediate -> register/memory */
	ADDRMOD_IMM_ACC     = SRC_IMM|DST_ACC|OP3_NONE,                  /* immediate -> AL/AX/EAX */
	ADDRMOD_IMM_REG     = SRC_IMM|DST_REG|OP3_NONE,                  /* immediate -> register */
	ADDRMOD_IMPLIED     = SRC_NONE|DST_NONE|OP3_NONE,                /* no operands */
	ADDRMOD_MOFFSET_ACC = SRC_MOFFSET|DST_ACC|OP3_NONE,              /* moffset -> AL/AX/EAX */
	ADDRMOD_REG         = SRC_REG|DST_NONE|OP3_NONE,                 /* register */
	ADDRMOD_SEG2_REG    = SRC_SEG2_REG|DST_NONE|OP3_NONE,            /* segment register (CS/DS/ES/SS) */
	ADDRMOD_SEG3_REG    = SRC_SEG3_REG|DST_NONE|OP3_NONE,            /* segment register (FS/GS) */
	ADDRMOD_SEG3_REG_RM = SRC_SEG3_REG|MOD_RM|DIR_REVERSED|OP3_NONE, /* segment register -> register/memory */
	ADDRMOD_RM_SEG3_REG = DST_SEG3_REG|MOD_RM|OP3_NONE,              /* register/memory -> segment register */
	ADDRMOD_REG_RM      = SRC_REG|MOD_RM|DIR_REVERSED|OP3_NONE,      /* register -> register/memory */
	ADDRMOD_REL         = SRC_REL|DST_NONE|OP3_NONE,                 /* relative */
	ADDRMOD_RM_REG      = DST_REG|MOD_RM|OP3_NONE,                   /* register/memory -> register */
	ADDRMOD_RM          = DST_NONE|MOD_RM|OP3_NONE,                  /* register/memory */
	ADDRMOD_RM_IMM_REG  = DST_REG|MOD_RM|OP3_IMM,                    /* register/memory, immediate -> register */
	ADDRMOD_RM_IMM8_REG = DST_REG|MOD_RM|OP3_IMM8,                   /* register/memory, immediate8 -> register */
	ADDRMOD_REG_IMM8_RM = SRC_REG|MOD_RM|DIR_REVERSED|OP3_IMM8,      /* register, immediate8 -> register/memory */
	ADDRMOD_REG_CL_RM   = SRC_REG|MOD_RM|DIR_REVERSED|OP3_CL,        /* register, CL -> register/memory */
	ADDRMOD_FAR_PTR     = DST_NONE|SRC_IMM48|OP3_NONE,               /* far pointer */
	ADDRMOD_IMM8_IMM16  = SRC_IMM8|DST_IMM16|OP3_NONE,               /* immediate8, immediate16 */
	ADDRMOD_CR_RM       = SRC_CR_REG|MOD_RM|DIR_REVERSED|OP3_NONE,   /* control register -> register */
	ADDRMOD_DBG_RM      = SRC_DBG_REG|MOD_RM|DIR_REVERSED|OP3_NONE,  /* debug register -> register */
	ADDRMOD_RM_CR       = DST_CR_REG|MOD_RM|OP3_NONE,                /* register -> control register */
	ADDRMOD_RM_DBG      = DST_DBG_REG|MOD_RM|OP3_NONE,               /* register -> debug register */
};

// Operand numbers
enum {
	OPNUM_SRC = 0,
	OPNUM_DST,
	OPNUM_THIRD,
	OPNUM_COUNT
};

struct x86_instr { /* Instances of x86_instr are populated in arch_x86_decode_instr() */
	unsigned long		nr_bytes;

	uint8_t         opcode_byte; /* Opcode byte */
	uint8_t         mod;         /* Mod */
	uint8_t         rm;          /* R/M */
	uint8_t         reg_opc;     /* Reg/Opcode */
	uint8_t         base;        /* SIB base */
	uint8_t         idx;         /* SIB index */
	uint8_t         scale;       /* SIB scale */
	uint8_t         seg;         /* Segment used by the instr */
	uint32_t        disp;        /* Address displacement */
	union {
		uint32_t    imm_data[2]; /* Immediate data; src/op3 (0), dst/seg sel (1) */
		int32_t     rel_data[2]; /* Relative address data */
	};

	unsigned opcode; /* See enum arch_x86_opcode */
	uint64_t flags;  /* See enum x86_instr_flags */
	union {
		struct {
#define SEG_OVERRIDE 0
			uint8_t seg_override; /* See enum x86_segment */
#define REP_OVERRIDE 1
			uint8_t rep_prefix; /* See enum x86_rep_prefix */
#define LOCK_PREFIX 2
			uint8_t lock_prefix;
#define ADDRESS_SIZE_OVERRIDE 3
			uint8_t addr_size_override;
#define OPERAND_SIZE_OVERRIDE 4
			uint8_t op_size_override;
#define IS_TWO_BYTE_INSTR 5
			uint8_t is_two_byte_instr; /* Only read in arch_x86_disasm_*.cpp */
		};
		uint8_t prefix_values[6];
	};

	struct x86_operand	operand[OPNUM_COUNT];
};

int get_instr_length(struct x86_instr *instr);
size_t disasm_instr_att(cpu_t *cpu, x86_instr *instr, char *line, unsigned int max_line, disas_ctx_t *disas_ctx);
size_t disasm_instr_intel(cpu_t *cpu, x86_instr *instr, char *line, unsigned int max_line, disas_ctx_t *disas_ctx);
