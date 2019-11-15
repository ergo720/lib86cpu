/*
 * the register file
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */


#define DEFINE_REG32(_reg)			\
	struct {				\
		uint32_t		_reg;	\
	}

#define DEFINE_SEG_REG(_reg)			\
	struct {				\
		uint16_t		_reg;	\
		struct { \
			uint32_t base; \
		} _reg ## _hidden; \
	}

// These registers must have the same order they have in cpu->regs_layout
struct regs_t {
	/* General registers */
	DEFINE_REG32(eax);
	DEFINE_REG32(ecx);
	DEFINE_REG32(edx);
	DEFINE_REG32(ebx);
	/* Pointer registers */
	DEFINE_REG32(esp);
	DEFINE_REG32(ebp);
	/* Index registers */
	DEFINE_REG32(esi);
	DEFINE_REG32(edi);

	/* Segment registers */
	DEFINE_SEG_REG(es);
	DEFINE_SEG_REG(cs);
	DEFINE_SEG_REG(ss);
	DEFINE_SEG_REG(ds);
	DEFINE_SEG_REG(fs);
	DEFINE_SEG_REG(gs);

	/* Control registers */
	DEFINE_REG32(cr0);
	DEFINE_REG32(cr1);
	DEFINE_REG32(cr2);
	DEFINE_REG32(cr3);
	DEFINE_REG32(cr4);

	/* Debug registers */
	DEFINE_REG32(dr0);
	DEFINE_REG32(dr1);
	DEFINE_REG32(dr2);
	DEFINE_REG32(dr3);
	DEFINE_REG32(dr4);
	DEFINE_REG32(dr5);
	DEFINE_REG32(dr6);
	DEFINE_REG32(dr7);

	DEFINE_REG32(eflags);
	DEFINE_REG32(eip);
};
