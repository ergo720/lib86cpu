#pragma once

#include "config.h"
#include "platform.h"
#include <stdint.h>

//////////////////////////////////////////////////////////////////////
// error flags
//////////////////////////////////////////////////////////////////////
enum x86cpu_status {
	X86CPU_NO_MEMORY = -3,
	X86CPU_INVALID_PARAMETER,
	X86CPU_LLVM_INTERNAL_ERROR,
	X86CPU_SUCCESS,
};

#define X86CPU_CHECK_SUCCESS(status) (((x86cpu_status)(status)) == 0)

typedef struct cpu {
	uint8_t *RAM;
} cpu_t;

API_FUNC x86cpu_status cpu_new(cpu_t *&out);
