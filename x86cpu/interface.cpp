/*
 * x86cpu: interface.cpp
 *
 * This is the interface to the client.
 */

/* project global headers */
#include "x86cpu.h"


//////////////////////////////////////////////////////////////////////
// cpu_t
//////////////////////////////////////////////////////////////////////

x86cpu_status
cpu_new(cpu_t *&out)
{
	cpu_t *cpu;

	cpu = new cpu_t();
	if (cpu == nullptr) {
		return X86CPU_NO_MEMORY;
	}

	out = cpu;
	return X86CPU_SUCCESS;
}
