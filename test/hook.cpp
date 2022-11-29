/*
 * lib86cpu hook api test generator
 *
 * ergo720                Copyright (c) 2021
 */

#include "run.h"


regs_t *regs = nullptr;

static uint8_t hook_binary[] = {
	0x6A, 0x07, 0x6A, 0x00, 0x6A, 0x02, 0xB2, 0x03, 0xB9, 0x04, 0x00, 0x00,
	0x00, 0xE8, 0x05, 0x00, 0x00, 0x00, 0xE9, 0x20, 0x00, 0x00, 0x00, 0x55,
	0x8B, 0xEC, 0x83, 0xEC, 0x48, 0x53, 0x56, 0x57, 0x88, 0x55, 0xF8, 0x66,
	0x89, 0x4D, 0xFC, 0xB8, 0x09, 0x00, 0x00, 0x00, 0x33, 0xD2, 0x5F, 0x5E,
	0x5B, 0x8B, 0xE5, 0x5D, 0xC2, 0x0C, 0x00, 0x50, 0x6A, 0x03, 0x6A, 0x04,
	0x6A, 0x00, 0x6A, 0x02, 0xE8, 0x05, 0x00, 0x00, 0x00, 0xE9, 0x19, 0x00,
	0x00, 0x00, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x40, 0x53, 0x56, 0x57, 0xB8,
	0x06, 0x00, 0x00, 0x00, 0x33, 0xD2, 0x5F, 0x5E, 0x5B, 0x8B, 0xE5, 0x5D,
	0xC2, 0x14, 0x00, 0x6A, 0x00, 0x6A, 0x04, 0x6A, 0x03, 0x6A, 0x02, 0x6A,
	0x01, 0xE8, 0x08, 0x00, 0x00, 0x00, 0x83, 0xC4, 0x14, 0xE9, 0x0B, 0x00,
	0x00, 0x00, 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x14, 0x8B, 0x55, 0x18, 0x5D,
	0xC3, 0x6A, 0x00, 0x6A, 0x00, 0xE8, 0x08, 0x00, 0x00, 0x00, 0x83, 0xC4,
	0x08, 0xE9, 0x05, 0x00, 0x00, 0x00, 0x55, 0x8B, 0xEC, 0x5D, 0xC3, 0xFA,
	0xF4, 0xE9, 0x96, 0xFF, 0xFF, 0xFF
};


static void
test_fastcall()
{
	// guest: uint64_t fastcall (*)(uint64_t a, uint16_t b, uint8_t c, uint32_t d)
	// push 0x7
	// push 0x0
	// push 0x2
	// mov dl,0x3
	// mov ecx,0x4
	// call 0x17

	uint64_t a;
	uint32_t a_h, a_l;
	uint16_t b = regs->ecx;
	uint8_t c = regs->edx & 0xFFFF;
	uint32_t d;
	uint32_t ret_eip, eflags;
	uint32_t esp = regs->esp;
	uint32_t ebp = regs->ebp;
	uint32_t eax = regs->eax;
	uint32_t edx = regs->edx;
	uint32_t ecx = b;
	uint8_t args[16];
	mem_read_block(cpu, esp, sizeof(args), args);
	std::memcpy(&ret_eip, &args[0], 4);
	std::memcpy(&a_l, &args[4], 4);
	std::memcpy(&a_h, &args[8], 4);
	std::memcpy(&d, &args[12], 4);
	a = (static_cast<uint64_t>(a_h) << 32) | a_l;
	eflags = read_eflags(cpu);
	std::printf("test_fastcall called with args: %llu, %hu, %u, %u\n", a, b, c, d);

	std::vector<uint8_t> vec(0x3800, 0xAA);
	mem_write_block(cpu, 0x2800, 0x2000, vec.data());
	mem_read_block(cpu, 0, 0x3800, vec.data());
	// should print 0x6A, uninitialzed value, 0xAA
	std::printf("vec[0x0] = 0x%X, vec[0x27FF] = 0x%X, vec[0x2800] = 0x%X\n", vec[0x0], vec[0x27FF], vec[0x2800]);

	trampoline_call(cpu, ret_eip);
	std::printf("Trampoline at address 0x17 returned %llu\n", (static_cast<uint64_t>(regs->edx) << 32) | regs->eax);

	// to call the trampoline again, we must restore the previous cpu state
	// restore stack arguments and return eip
	mem_write_block(cpu, esp, 16, args);
	// restore gpr (esi, edi and ebx are not touched by fastcall functions)
	regs->eax = eax;
	regs->ecx = ecx;
	regs->edx = edx;
	regs->esp = esp;
	regs->ebp = ebp;
	regs->eip = 0x17;
	write_eflags(cpu, eflags);

	trampoline_call(cpu, ret_eip);
	std::printf("Trampoline at address 0x17 returned %llu\n", (static_cast<uint64_t>(regs->edx) << 32) | regs->eax);

	// set the return value
	regs->eax = 0;
	regs->edx = 0;
}

static void
test_stdcall()
{
	// guest: uint64_t stdcall (*)(uint64_t a, uint16_t b, uint8_t c, uint32_t d)
    // push eax
    // push 0x3
    // push 0x4
    // push 0x0
    // push 0x2
    // call 0x4a

	uint64_t a;
	uint32_t a_h, a_l;
	uint16_t b;
	uint8_t c;
	uint32_t d;
	uint32_t ret_eip, temp;
	uint8_t args[24];
	mem_read_block(cpu, regs->esp, sizeof(args), args);
	std::memcpy(&ret_eip, &args[0], 4);
	std::memcpy(&a_l, &args[4], 4);
	std::memcpy(&a_h, &args[8], 4);
	std::memcpy(&temp, &args[12], 4);
	b = temp;
	std::memcpy(&temp, &args[16], 4);
	c = temp;
	std::memcpy(&d, &args[20], 4);
	a = (static_cast<uint64_t>(a_h) << 32) | a_l;
	std::printf("test_stdcall called with args: %llu, %hu, %u, %u\n", a, b, c, d);

	// clean up the stack and set the eip
	regs->esp += 24;
	regs->eip = ret_eip;

	// set the return value
	regs->eax = 6;
	regs->edx = 0;
}

static void
test_cdecl()
{
	// guest: uint64_t cdecl (*)(uint8_t a, uint16_t b, uint32_t c, uint64_t d)
	// push 0x0
	// push 0x4
	// push 0x3
	// push 0x2
	// push 0x1
	// call 0x7a

	uint8_t a;
	uint16_t b;
	uint32_t c;
	uint64_t d;
	uint32_t d_h, d_l;
	uint32_t ret_eip, temp;
	uint8_t args[24];
	mem_read_block(cpu, regs->esp, sizeof(args), args);
	std::memcpy(&ret_eip, &args[0], 4);
	std::memcpy(&temp, &args[4], 4);
	a = temp;
	std::memcpy(&temp, &args[8], 4);
	b = temp;
	std::memcpy(&c, &args[12], 4);
	std::memcpy(&d_l, &args[16], 4);
	std::memcpy(&d_h, &args[20], 4);
	d = (static_cast<uint64_t>(d_h) << 32) | d_l;
	std::printf("test_cdecl called with args: %u, %hu, %u, %llu\n", a, b, c, d);

	trampoline_call(cpu, ret_eip);
	std::printf("Trampoline at address 0x7a returned %llu\n", (static_cast<uint64_t>(regs->edx) << 32) | regs->eax);

	// set the return value
	regs->eax = d_l;
	regs->edx = d_h;
}

static void
test_double_ptr()
{
	// guest: void cdecl (*)(int **a, int *b)
	// push 0x0
	// push 0x0
	// call 0x96

	uint32_t a, b, ret_eip;
	uint8_t args[12];
	mem_read_block(cpu, regs->esp, sizeof(args), args);
	std::memcpy(&ret_eip, &args[0], 4);
	std::memcpy(&a, &args[4], 4);
	std::memcpy(&b, &args[8], 4);
	std::printf("test_double_ptr called with args: %u, %u\n", a, b);

	trampoline_call(cpu, ret_eip);
}

bool
gen_hook_test()
{
	size_t ramsize = 5 * 4096;

	if (!LC86_SUCCESS(cpu_new(ramsize, cpu))) {
		std::printf("Failed to initialize lib86cpu!\n");
		return false;
	}

	cpu_set_a20(cpu, true);
	uint8_t *ram = get_ram_ptr(cpu);
	std::memcpy(ram, hook_binary, sizeof(hook_binary));

	if (!LC86_SUCCESS(mem_init_region_ram(cpu, 0, ramsize))) {
		std::printf("Failed to initialize ram memory for hook test!\n");
		return false;
	}

	if (!LC86_SUCCESS(hook_add(cpu, 0x17, &test_fastcall))) {
		std::printf("Failed to install test_fastcall hook!\n");
		return false;
	}

	if (!LC86_SUCCESS(hook_add(cpu, 0x4a, &test_stdcall))) {
		std::printf("Failed to install test_stdcall hook!\n");
		return false;
	}

	if (!LC86_SUCCESS(hook_add(cpu, 0x7a, &test_cdecl))) {
		std::printf("Failed to install test_cdecl hook!\n");
		return false;
	}

	if (!LC86_SUCCESS(hook_add(cpu, 0x96, &test_double_ptr))) {
		std::printf("Failed to install test_double_ptr hook!\n");
		return false;
	}

	regs = get_regs_ptr(cpu);
	regs->cr0 |= 1;
	regs->eip = 0;
	regs->cs = 0;
	regs->cs_hidden.base = 0;
	regs->cs_hidden.flags = 1 << 22;
	regs->ss_hidden.flags = 1 << 22;
	regs->esp = ramsize;
	regs->ebp = ramsize;

	return true;
}
