/*
 * linux memory functions
 *
 * ergo720                Copyright (c) 2023
 */

#include "internal.h"
#include "allocator.h"
#include <sys/mman.h>
#include "os_mem.h"


void *
os_alloc(size_t size)
{
	auto addr = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (addr == MAP_FAILED) {
		throw lc86_exp_abort("Failed to allocate memory for the generated code", lc86_status::no_memory);
	}
	return addr;
}

void
os_free(void *addr, size_t size)
{
	[[maybe_unused]] auto ret = munmap(addr, size);
	assert(!ret);
}

void
os_flush_instr_cache(void *start, void *end)
{
	__builtin___clear_cache(start, end);
}
