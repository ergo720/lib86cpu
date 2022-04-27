/*
 * lib86cpu x86 debug test generator
 *
 * ergo720                Copyright (c) 2021
 */

#include "run.h"

#define DBG_POST_PORT 0x123

#if _MSC_VER
#define CDECL __cdecl
#else
#error Don't know how to specify calling conventions with this compiler
#endif


// memory map
// 00000-000FF IDT
// 00100-00117 GDT
// 01000-01FFF code
// FB000-FBFFF no access page
// FC000-FCFFF stack
// FD000-FDFFF no access page
// FE000-FEFFF page table
// FF000-FFFFF page directory

static uint8_t dbg_binary[] = {
	0xB8, 0x00, 0x20, 0x00, 0x00, 0xC7, 0x00, 0x44, 0x33, 0x22, 0x11, 0x83,
	0xC0, 0x04, 0xC7, 0x00, 0x88, 0x77, 0x66, 0x55, 0xB8, 0x43, 0x10, 0x00,
	0x00, 0x0F, 0x23, 0xC0, 0xB8, 0x02, 0x20, 0x00, 0x00, 0x0F, 0x23, 0xC8,
	0xB8, 0xFF, 0xFF, 0x00, 0x00, 0x0F, 0x23, 0xD0, 0xB8, 0x04, 0x20, 0x00,
	0x00, 0x0F, 0x23, 0xD8, 0xB8, 0x4A, 0x00, 0x50, 0xF2, 0x0F, 0x23, 0xF8,
	0xB0, 0x00, 0x66, 0xBA, 0x23, 0x01, 0xEE, 0xB8, 0x00, 0x20, 0x00, 0x00,
	0xC7, 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0xB8, 0x02, 0x20, 0x00, 0x00, 0x66,
	0xC7, 0x00, 0x00, 0x00, 0xB8, 0x01, 0x20, 0x00, 0x00, 0xC7, 0x00, 0x00,
	0x00, 0x00, 0x00, 0xB8, 0x04, 0x20, 0x00, 0x00, 0x8B, 0x00, 0xB8, 0x04,
	0x20, 0x00, 0x00, 0xC7, 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0xB8, 0x4A, 0x20,
	0x50, 0xF2, 0x0F, 0x23, 0xF8, 0x0F, 0x21, 0xC0, 0xB8, 0x4A, 0x20, 0x50,
	0xF2, 0x0F, 0x23, 0xF8, 0x0F, 0x23, 0xD0, 0x0F, 0x23, 0xE0, 0xB0, 0x01,
	0x66, 0xBA, 0x23, 0x01, 0xEE, 0xB8, 0x9E, 0x10, 0x00, 0x00, 0x0F, 0x23,
	0xC0, 0x33, 0xC0, 0xB8, 0x00, 0x20, 0x00, 0x00, 0x66, 0xC7, 0x00, 0x00,
	0x00, 0x83, 0xC0, 0x02, 0x66, 0x8B, 0x00, 0x0F, 0x20, 0xE0, 0x83, 0xE0,
	0xF7, 0x0F, 0x22, 0xE0, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x23, 0xE0,
	0xB0, 0x02, 0x66, 0xBA, 0x23, 0x01, 0xEE, 0xE9, 0x41, 0x00, 0x00, 0x00,
	0x0F, 0x21, 0xF0, 0x83, 0xE0, 0x01, 0x83, 0xF8, 0x01, 0x0F, 0x85, 0x0E,
	0x00, 0x00, 0x00, 0x8B, 0x5C, 0x24, 0x08, 0x81, 0xCB, 0x00, 0x00, 0x01,
	0x00, 0x89, 0x5C, 0x24, 0x08, 0x8B, 0x1C, 0x24, 0x53, 0xE8, 0x1A, 0x00,
	0x00, 0x00, 0x33, 0xC0, 0x0F, 0x23, 0xF0, 0x83, 0xC4, 0x04, 0xCF, 0x8B,
	0x1C, 0x24, 0x53, 0xE8, 0x08, 0x00, 0x00, 0x00, 0x5B, 0x83, 0xC3, 0x03,
	0x89, 0x1C, 0x24, 0xCF, 0xC3, 0xFA, 0xF4
};


static void
dbg_write_handler(addr_t addr, size_t size, const uint64_t value, void *opaque)
{
	switch (addr)
	{
	case DBG_POST_PORT: {
		if (size == 1) {
			std::printf("Test number is 0x%X\n", static_cast<const uint8_t>(value));
		}
		else {
			std::printf("Unhandled i/o port size at port %d\n", DBG_POST_PORT);
		}
	}
	break;

	default:
		std::printf("Unhandled i/o write at port %d\n", addr);
	}
}

static void
CDECL int_handler_printer(uint32_t eip)
{
	uint32_t val;

	switch (eip)
	{
	case 0x1043:
		mem_read_block(cpu, 0x2000, 4, reinterpret_cast<uint8_t *>(&val));
		std::printf("instr breakpoint at 0x%X: mem at 0x2000 should be 0x11223344, it actually was 0x%08X\n", eip, val);
		break;

	case 0x104E:
		mem_read_block(cpu, 0x2000, 4, reinterpret_cast<uint8_t *>(&val));
		std::printf("data w breakpoint of 2 bytes at 0x%X: mem at 0x2000 should be 0xDEADBEEF, it actually was 0x%08X\n", eip, val);
		break;

	case 0x1058:
		mem_read_block(cpu, 0x2000, 4, reinterpret_cast<uint8_t *>(&val));
		std::printf("data w breakpoint of 2 bytes at 0x%X: mem at 0x2000 should be 0x0000BEEF, it actually was 0x%08X\n", eip, val);
		break;

	case 0x1063:
		mem_read_block(cpu, 0x2000, 4, reinterpret_cast<uint8_t *>(&val));
		std::printf("data w breakpoint of 2 bytes at 0x%X: mem at 0x2000 should be 0x000000EF, it actually was 0x%08X\n", eip, val);
		break;

	case 0x106A:
		mem_read_block(cpu, 0x2004, 4, reinterpret_cast<uint8_t *>(&val));
		std::printf("data r breakpoint of 4 bytes at 0x%X: mem at 0x2004 should be 0x55667700, it actually was 0x%08X\n", eip, val);
		break;

	case 0x1075:
		mem_read_block(cpu, 0x2004, 4, reinterpret_cast<uint8_t *>(&val));
		std::printf("data w breakpoint of 4 bytes at 0x%X: mem at 0x2004 should be 0xDEADBEEF, it actually was 0x%08X\n", eip, val);
		break;

	case 0x107D:
		read_gpr(cpu, &val, REG_DR6);
		std::printf("general detect read at 0x%X: dr6 should have bd flag set, it actually was %d\n", eip, (val >> 13) & 1);
		break;

	case 0x1088:
		read_gpr(cpu, &val, REG_DR6);
		std::printf("general detect write at 0x%X: dr6 should have bd flag set, it actually was %d\n", eip, (val >> 13) & 1);
		break;

	case 0x108B:
		mem_read_block(cpu, 0x108B, 4, reinterpret_cast<uint8_t *>(&val));
		std::printf("undefined opcode exception at 0x%X: bytes of the faulting opcode should be 0xB0E0230F, it actually was 0x%X\n", eip, val);
		break;

	case 0x109D:
	case 0x109E:
		std::printf("spurious instr breakpoint at 0x%X\n", eip);
		break;

	case 0x10A9:
		std::printf("spurious data w breakpoint at 0x%X\n", eip);
		break;

	case 0x10AF:
		std::printf("spurious data r breakpoint at 0x%X\n", eip);
		break;

	case 0x10BD:
		std::printf("spurious undefined opcode exception at 0x%X\n", eip);
		break;

	default:
		std::printf("got unexpected eip with value 0x%X", eip);
	}
}

bool
gen_dbg_test()
{
	size_t ramsize = 1024 * 1024;

	if (!LIB86CPU_CHECK_SUCCESS(cpu_new(ramsize, cpu))) {
		printf("Failed to initialize lib86cpu!\n");
		return false;
	}

	uint8_t *ram = get_ram_ptr(cpu);
	std::memcpy(ram + 0x1000, dbg_binary, sizeof(dbg_binary));

	if (!LIB86CPU_CHECK_SUCCESS(mem_init_region_ram(cpu, 0, ramsize, 1))) {
		std::printf("Failed to initialize ram memory!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(mem_init_region_io(cpu, DBG_POST_PORT, 0x1, true, nullptr, dbg_write_handler, nullptr, 1))) {
		std::printf("Failed to initialize post i/o port for debug test!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(hook_add(cpu, 0x110C, std::unique_ptr<hook>(new hook({ call_conv::x86_cdecl, call_conv::x86_cdecl,
		{ std::vector<arg_types> { arg_types::void_, arg_types::i32 }, "int_handler_printer", int_handler_printer } }))))) {
		printf("Failed to install hook!\n");
		return false;
	}

	mem_fill_block(cpu, 0xFE000, 0x2000, 0);
	uint32_t pde = 0xFE007, pte = 0x7;
	mem_write_block(cpu, 0xFF000, 4, &pde);
	for (int i = 0; i < 256; ++i) {
		mem_write_block(cpu, 0xFE000 + (i * 4), 4, &pte); // this identity maps all physical memory
		pte += 0x1000;
	}

	// create the no access pages for the stack
	pte = 0;
	mem_write_block(cpu, 0xFE3EC, 4, &pte);
	mem_write_block(cpu, 0xFE3F4, 4, &pte);

	// create the IDT
	// point all unhandled exp handlers to the hlt instr
	uint64_t desc = 0x8F00000810C7;
	for (int i = 0; i < 32; ++i) {
		mem_write_block(cpu, i * 8, 8, &desc);
	}

	// point DB and UD exp handlers to their corresponding handlers in the code
	desc = 0x8F00000810CC;
	mem_write_block(cpu, 1 * 8, 8, &desc); // DB
	desc = 0x8F00000810FB;
	mem_write_block(cpu, 6 * 8, 8, &desc); // UD

	// create the GDT
	desc = 0;
	mem_write_block(cpu, 0x100, 8, &desc); // first entry is always a null segment descriptor
	desc = 0xCF9F000000FFFF;
	mem_write_block(cpu, 0x108, 8, &desc); // 32bit code segment, conforming, rx, present
	desc = 0xCF97000000FFFF;
	mem_write_block(cpu, 0x110, 8, &desc); // 32bit data segment, expand-down, rw, present

	write_gpr(cpu, 0x8, REG_CS, SEG_SEL);
	write_gpr(cpu, 0x10, REG_ES, SEG_SEL);
	write_gpr(cpu, 0x10, REG_DS, SEG_SEL);
	write_gpr(cpu, 0x10, REG_SS, SEG_SEL);
	write_gpr(cpu, 0x10, REG_FS, SEG_SEL);
	write_gpr(cpu, 0x10, REG_GS, SEG_SEL);

	write_gpr(cpu, 0x0, REG_CS, SEG_BASE);
	write_gpr(cpu, 0x0, REG_ES, SEG_BASE);
	write_gpr(cpu, 0x0, REG_DS, SEG_BASE);
	write_gpr(cpu, 0x0, REG_SS, SEG_BASE);
	write_gpr(cpu, 0x0, REG_FS, SEG_BASE);
	write_gpr(cpu, 0x0, REG_GS, SEG_BASE);

	write_gpr(cpu, 0xFFFFFFFF, REG_CS, SEG_LIMIT);
	write_gpr(cpu, 0xFFFFFFFF, REG_ES, SEG_LIMIT);
	write_gpr(cpu, 0xFFFFFFFF, REG_DS, SEG_LIMIT);
	write_gpr(cpu, 0xFFFFFFFF, REG_SS, SEG_LIMIT);
	write_gpr(cpu, 0xFFFFFFFF, REG_FS, SEG_LIMIT);
	write_gpr(cpu, 0xFFFFFFFF, REG_GS, SEG_LIMIT);

	write_gpr(cpu, 0xCF9F00, REG_CS, SEG_FLG);
	write_gpr(cpu, 0xCF9700, REG_ES, SEG_FLG);
	write_gpr(cpu, 0xCF9700, REG_DS, SEG_FLG);
	write_gpr(cpu, 0xCF9700, REG_SS, SEG_FLG);
	write_gpr(cpu, 0xCF9700, REG_FS, SEG_FLG);
	write_gpr(cpu, 0xCF9700, REG_GS, SEG_FLG);

	write_gpr(cpu, 0x1000, REG_EIP);
	write_gpr(cpu, 0xFD000, REG_ESP);
	write_gpr(cpu, 0xFD000, REG_EBP);

	write_gpr(cpu, 0x0, REG_IDTR, SEG_BASE);
	write_gpr(cpu, 0x100, REG_GDTR, SEG_BASE);
	write_gpr(cpu, 0xFF, REG_IDTR, SEG_LIMIT);
	write_gpr(cpu, 0x117, REG_GDTR, SEG_LIMIT);

	write_gpr(cpu, 0x80000001, REG_CR0); // protected, paging
	write_gpr(cpu, 0x000FF000, REG_CR3);
	write_gpr(cpu, 0x8, REG_CR4); // debug extensions

	return true;
}
