/*
 * lib86cpu hook api test generator
 *
 * ergo720                Copyright (c) 2021
 */

#include "run.h"

#if _MSC_VER
#define FASTCALL __fastcall
#define STDCALL __stdcall
#define CDECL __cdecl
#else
#error Don't know how to specify calling conventions with this compiler
#endif


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


static uint64_t
FASTCALL test_fastcall(uint64_t a, uint16_t b, uint8_t c, uint32_t d)
{
	printf("test_fastcall called with args: %llu, %hu, %u, %u\n", a, b, c, d);

	std::vector<uint8_t> vec(0x3800, 0xAA);
	mem_write_block(cpu, 0x2800, 0x2000, vec.data());
	mem_read_block(cpu, 0, 0x3800, vec.data());
	// should print 0x6A, uninitialzed value, 0xAA
	printf("vec[0x0] = 0x%X, vec[0x27FF] = 0x%X, vec[0x2800] = 0x%X\n", vec[0x0], vec[0x27FF], vec[0x2800]);

	std::any ret;
	if (!LIB86CPU_CHECK_SUCCESS(trampoline_call(cpu, 0x17, ret, ANY_VEC(a, ANY_I32s(b), c, d)))) {
		printf("Failed to call trampoline at address 0x17!\n");
		return 0;
	}

	printf("Trampoline at address 0x17 returned %llu\n", std::any_cast<uint64_t>(ret));

	if (!LIB86CPU_CHECK_SUCCESS(trampoline_call(cpu, 0x17, ret, ANY_VEC(a, ANY_I32s(b), c, d)))) {
		printf("Failed to call trampoline at address 0x17!\n");
		return 0;
	}

	printf("Trampoline at address 0x17 returned %llu\n", std::any_cast<uint64_t>(ret));
	return 0;
}

static uint64_t
STDCALL test_stdcall(uint64_t a, uint16_t b, uint8_t c, uint32_t d)
{
	printf("test_stdcall called with args: %llu, %hu, %u, %u\n", a, b, c, d);
	return 6;
}

static uint64_t
CDECL test_cdecl(uint8_t a, uint16_t b, uint32_t c, uint64_t d)
{
	printf("test_cdecl called with args: %u, %hu, %u, %llu\n", a, b, c, d);

	std::any ret;
	if (!LIB86CPU_CHECK_SUCCESS(trampoline_call(cpu, 0x7a, ret, ANY_VEC(ANY_I32s(a), ANY_I32s(b), c, d)))) {
		printf("Failed to call trampoline at address 0x7a!\n");
		return d;
	}

	printf("Trampoline at address 0x7a returned %llu\n", std::any_cast<uint64_t>(ret));

	return d;
}

static void
CDECL test_double_ptr(int **a, int *b)
{
	printf("test_double_ptr called with args: 0x%p, 0x%p\n", a, b);

	std::any ret;
	if (!LIB86CPU_CHECK_SUCCESS(trampoline_call(cpu, 0x96, ret, ANY_VEC(ANY_I32r(a), ANY_I32r(b))))) {
		printf("Failed to call trampoline at address 0x96!\n");
		return;
	}
}

bool
gen_hook_test()
{
	size_t ramsize = 5 * 4096;

	if (!LIB86CPU_CHECK_SUCCESS(cpu_new(ramsize, cpu))) {
		printf("Failed to initialize lib86cpu!\n");
		return false;
	}

	uint8_t *ram = get_ram_ptr(cpu);
	std::memcpy(ram, hook_binary, sizeof(hook_binary));

	if (!LIB86CPU_CHECK_SUCCESS(mem_init_region_ram(cpu, 0, ramsize, 1))) {
		printf("Failed to initialize ram memory for hook test!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(hook_add(cpu, 0x17, std::unique_ptr<hook>(new hook({ call_conv::x86_fastcall, call_conv::x86_fastcall,
		{ std::vector<arg_types> { arg_types::i64, arg_types::i64, arg_types::i16, arg_types::i8, arg_types::i32 }, "test_fastcall", &test_fastcall } }))))) {
		printf("Failed to install hook!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(hook_add(cpu, 0x4a, std::unique_ptr<hook>(new hook({ call_conv::x86_stdcall, call_conv::x86_stdcall,
	{ std::vector<arg_types> { arg_types::i64, arg_types::i64, arg_types::i16, arg_types::i8, arg_types::i32 }, "test_stdcall", &test_stdcall } }))))) {
		printf("Failed to install hook!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(hook_add(cpu, 0x7a, std::unique_ptr<hook>(new hook({ call_conv::x86_cdecl, call_conv::x86_cdecl,
	{ std::vector<arg_types> { arg_types::i64, arg_types::i8, arg_types::i16, arg_types::i32, arg_types::i64 }, "test_cdecl", &test_cdecl } }))))) {
		printf("Failed to install hook!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(hook_add(cpu, 0x96, std::unique_ptr<hook>(new hook({ call_conv::x86_cdecl, call_conv::x86_cdecl,
	{ std::vector<arg_types> { arg_types::void_, arg_types::ptr2, arg_types::ptr }, "test_double_ptr", &test_double_ptr } }))))) {
		printf("Failed to install hook!\n");
		return false;
	}

	uint32_t cr0;
	read_gpr(cpu, &cr0, REG_CR0);
	cr0 |= 1;
	write_gpr(cpu, cr0, REG_CR0);
	write_gpr(cpu, 0, REG_EIP);
	write_gpr(cpu, 0, REG_CS, SEG_SEL);
	write_gpr(cpu, 0, REG_CS, SEG_BASE);
	write_gpr(cpu, 1 << 22, REG_CS, SEG_FLG);
	write_gpr(cpu, 1 << 22, REG_SS, SEG_FLG);
	write_gpr(cpu, ramsize, REG_ESP);
	write_gpr(cpu, ramsize, REG_EBP);

	return true;
}
