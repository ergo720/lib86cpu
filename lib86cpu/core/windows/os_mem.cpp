/*
 * windows memory functions
 *
 * ergo720                Copyright (c) 2023
 */

#include "internal.h"
#include "allocator.h"
#include "Windows.h"
#include "os_mem.h"


unsigned
get_mem_flags(unsigned flags)
{
	switch (flags)
	{
	case MEM_READ:
		return PAGE_READONLY;

	case MEM_WRITE:
		return PAGE_READWRITE;

	case MEM_READ | MEM_WRITE:
		return PAGE_READWRITE;

	case MEM_READ | MEM_EXEC:
		return PAGE_EXECUTE_READ;

	case MEM_READ | MEM_WRITE | MEM_EXEC:
		return PAGE_EXECUTE_READWRITE;

	case MEM_EXEC:
		return PAGE_EXECUTE;

	default:
		LIB86CPU_ABORT();
	}

	return PAGE_NOACCESS;
}

void *
os_alloc(size_t size)
{
	auto addr = VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (addr == NULL) {
		throw lc86_exp_abort("Failed to allocate memory for the generated code", lc86_status::no_memory);
	}
	return addr;
}

void
os_free(void *addr)
{
	[[maybe_unused]] auto ret = VirtualFree(addr, 0, MEM_RELEASE);
	assert(ret);
}

void
os_protect(void *addr, size_t size, unsigned prot)
{
	DWORD dummy;
	[[maybe_unused]] auto ret = VirtualProtect(addr, size, prot, &dummy);
	assert(ret);
}

void
os_flush_instr_cache(void *addr, size_t size)
{
	[[maybe_unused]] auto ret = FlushInstructionCache(GetCurrentProcess(), addr, size);
	assert(ret);
}
