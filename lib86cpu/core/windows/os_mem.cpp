/*
 * windows memory functions
 *
 * ergo720                Copyright (c) 2023
 */

#include "internal.h"
#include "allocator.h"
#include "Windows.h"
#include "os_mem.h"


void *
os_alloc(size_t size)
{
	auto addr = VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
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
os_flush_instr_cache(void *addr, size_t size)
{
	[[maybe_unused]] auto ret = FlushInstructionCache(GetCurrentProcess(), addr, size);
	assert(ret);
}
