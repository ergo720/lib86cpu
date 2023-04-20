/*
 * linux memory functions
 *
 * ergo720                Copyright (c) 2023
 */

#include "internal.h"
#include "allocator.h"
#include <sys/mman.h>
#include "os_mem.h"


int
get_mem_flags(unsigned flags)
{
	switch (flags)
	{
	case MEM_READ:
		return PROT_READ;

	case MEM_WRITE:
		return PROT_WRITE;

	case MEM_READ | MEM_WRITE:
		return PROT_READ | PROT_WRITE;

	case MEM_READ | MEM_EXEC:
		return PROT_READ | PROT_EXEC;

	case MEM_READ | MEM_WRITE | MEM_EXEC:
		return PROT_READ | PROT_WRITE | PROT_EXEC;

	case MEM_EXEC:
		return PROT_READ | PROT_EXEC;

	default:
		LIB86CPU_ABORT();
	}

	return PROT_NONE;
}

void *
os_alloc(size_t size)
{
	auto addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
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
os_protect(void *addr, size_t size, int prot)
{
	[[maybe_unused]] auto ret = mprotect(addr, size, prot);
	assert(!ret);
}

void
os_flush_instr_cache(void *start, void *end)
{
	__builtin___clear_cache(start, end);
}
