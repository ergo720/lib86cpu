/*
 * OS specific functionality
 *
 * ergo720                Copyright (c) 2019
 */

#include <assert.h>
#ifdef _WIN32
#include "Windows.h"
#endif


#ifdef _WIN32

void tc_protect(void *addr, size_t size, bool ro)
{
	DWORD dummy, perms = ro ? PAGE_EXECUTE_READ : PAGE_EXECUTE_READWRITE;
	assert(VirtualProtect(addr, size, perms, &dummy));
}

#else
#error don't know how to change memory permissions on this OS
#endif
