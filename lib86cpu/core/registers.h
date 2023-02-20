/*
 * the register file
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once

#include "config.h"
#include "platform.h"

#define DEFINE_REG32(_reg) \
		uint32_t		_reg

#define DEFINE_REG16(_reg) \
		uint16_t		_reg

#define DEFINE_SEG_REG(_reg) \
		uint16_t		_reg; \
		struct { \
			uint32_t base; \
			uint32_t limit; \
			uint32_t flags; \
		} _reg ## _hidden;

PACKED(struct alignas(16) uint128_t {
	uint64_t low;
	uint64_t high;
	uint128_t();
	uint128_t(uint64_t val);
	uint128_t &operator|=(const uint128_t &rhs);
	uint128_t operator>>(int shift);
	uint128_t operator<<(int shift);
	explicit operator uint8_t ();
});

PACKED(struct uint80_t {
	uint64_t low;
	uint16_t high;
	uint80_t();
	uint80_t(uint64_t val);
	uint80_t &operator|=(const uint80_t &rhs);
	uint80_t operator>>(int shift);
	uint80_t operator<<(int shift);
	explicit operator uint8_t ();
	operator uint128_t ();
});

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
	uint32_t dr[8];

	DEFINE_REG32(eflags);
	DEFINE_REG32(eip);

	/* Memory management registers */
	DEFINE_SEG_REG(idtr); // selector and flags unused
	DEFINE_SEG_REG(gdtr); // selector and flags unused
	DEFINE_SEG_REG(ldtr);
	DEFINE_SEG_REG(tr);

	/* Fpu registers */
	uint80_t fr[8];
	DEFINE_REG16(fctrl);
	DEFINE_REG16(fstatus);
	uint8_t ftags[8]; // two tag bits of tag reg splitted in their own reg
	DEFINE_REG16(fcs);
	DEFINE_REG32(fip);
	DEFINE_REG16(fds);
	DEFINE_REG32(fdp);
	DEFINE_REG16(fop);

	/* Sse registers */
	uint128_t xmm[8];
	DEFINE_REG32(mxcsr);
};

struct msr_t {
	struct {
		struct {
			uint64_t base;
			uint64_t mask;
		} phys_var[8];
		uint64_t phys_fixed[11];
		uint64_t def_type;
	} mtrr;
	uint64_t bios_sign_id;
	uint64_t pat;
	uint64_t sys_cs;
	uint64_t sys_esp;
	uint64_t sys_eip;
};

static_assert(sizeof(uint80_t) == 10);
static_assert(sizeof(uint128_t) == 16);
static_assert(alignof(decltype(regs_t::xmm)) == 16);
