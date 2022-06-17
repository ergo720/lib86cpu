/*
 * lib86cpu x86 debug test generator
 *
 * ergo720                Copyright (c) 2021
 */

#include "run.h"

#define DBG_POST_PORT 0x123


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

static regs_t *regs = nullptr;


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
int_handler_printer()
{
	uint32_t val, eip, ret_eip;
	uint8_t args[8];
	mem_read_block(cpu, regs->esp, sizeof(args), args);
	std::memcpy(&ret_eip, &args[0], 4);
	std::memcpy(&eip, &args[4], 4);

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
		val = regs->dr6;
		std::printf("general detect read at 0x%X: dr6 should have bd flag set, it actually was %d\n", eip, (val >> 13) & 1);
		break;

	case 0x1088:
		val = regs->dr6;
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

	regs->eip = ret_eip;
	regs->esp += 4;
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

	if (!LIB86CPU_CHECK_SUCCESS(mem_init_region_io(cpu, DBG_POST_PORT - 3, 4, true, nullptr, dbg_write_handler, nullptr, 1))) {
		std::printf("Failed to initialize post i/o port for debug test!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(hook_add(cpu, 0x110C, std::unique_ptr<hook>(new hook({ {}, {}, "int_handler_printer", int_handler_printer }))))) {
		std::printf("Failed to install hook!\n");
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

	regs = get_regs_ptr(cpu);
	regs->cs = 0x8;
	regs->es = 0x10;
	regs->ds = 0x10;
	regs->ss = 0x10;
	regs->fs = 0x10;
	regs->gs = 0x10;

	regs->cs_hidden.base = 0x0;
	regs->es_hidden.base = 0x0;
	regs->ds_hidden.base = 0x0;
	regs->ss_hidden.base = 0x0;
	regs->fs_hidden.base = 0x0;
	regs->gs_hidden.base = 0x0;

	regs->cs_hidden.limit = 0xFFFFFFFF;
	regs->es_hidden.limit = 0xFFFFFFFF;
	regs->ds_hidden.limit = 0xFFFFFFFF;
	regs->ss_hidden.limit = 0xFFFFFFFF;
	regs->fs_hidden.limit = 0xFFFFFFFF;
	regs->gs_hidden.limit = 0xFFFFFFFF;

	regs->cs_hidden.flags = 0xCF9F00;
	regs->es_hidden.flags = 0xCF9700;
	regs->ds_hidden.flags = 0xCF9700;
	regs->ss_hidden.flags = 0xCF9700;
	regs->fs_hidden.flags = 0xCF9700;
	regs->gs_hidden.flags = 0xCF9700;

	regs->eip = 0x1000;
	regs->esp = 0xFD000;
	regs->ebp = 0xFD000;

	regs->idtr_hidden.base = 0x0;
	regs->gdtr_hidden.base = 0x100;
	regs->idtr_hidden.limit = 0xFF;
	regs->gdtr_hidden.limit = 0x117;

	regs->cr0 = 0x80000001; // protected, paging
	regs->cr3 = 0x000FF000;
	regs->cr4 = 0x8; // debug extensions

	return true;
}
