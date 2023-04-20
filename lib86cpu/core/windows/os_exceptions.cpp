/*
 * x86-64 windows exception support
 *
 * ergo720                Copyright (c) 2022
 */

#include "lib86cpu_priv.h"
#ifdef LIB86CPU_X64_EMITTER
#include "x64/jit.h"
#endif
#include <assert.h>
#include "Windows.h"

#if defined(_WIN64)

#define UWOP_PUSH_NONVOL 0
#define UWOP_ALLOC_LARGE 1
#define UWOP_ALLOC_SMALL 2

#define EXP_RAX_idx 0
#define EXP_RCX_idx 1
#define EXP_RDX_idx 2
#define EXP_RBX_idx 3
#define EXP_RSP_idx 4
#define EXP_RBP_idx 5
#define EXP_RSI_idx 6
#define EXP_RDI_idx 7
#define EXP_R8_idx  8
#define EXP_R9_idx  9
#define EXP_R10_idx 10
#define EXP_R11_idx 11
#define EXP_R12_idx 12
#define EXP_R13_idx 13
#define EXP_R14_idx 14
#define EXP_R15_idx 15


static uint8_t unwind_info[4 + 12];

static void
create_unwind_info()
{
	// The prolog of main() always uses push rbx and sub rsp, 0x20 + sizeof(stack args) + sizeof(local vars),
	// so we can simplify the generation of the unwind table

	uint16_t unwind_codes[4] = { 0 };
	uint8_t num_unwind_codes;

	// Create UNWIND_CODE entries for sub rsp, imm32
	size_t tot_stack_allocated = get_jit_stack_required_runtime();
	if (tot_stack_allocated <= 128) {
		unwind_codes[0] = 8 | (UWOP_ALLOC_SMALL << 8) | ((tot_stack_allocated / 8 - 1) << 12);
		num_unwind_codes = 1;
	}
	else if (tot_stack_allocated <= (512 * 1024 - 8)) {
		unwind_codes[0] = 8 | (UWOP_ALLOC_LARGE << 8) | (0 << 12);
		unwind_codes[1] = tot_stack_allocated / 8;
		num_unwind_codes = 2;
	}
	else {
		unwind_codes[0] = 8 | (UWOP_ALLOC_LARGE << 8) | (1 << 12);
		uint32_t *slot32_size = reinterpret_cast<uint32_t *>(&unwind_codes[1]);
		*slot32_size = static_cast<uint32_t>(tot_stack_allocated);
		num_unwind_codes = 3;
	}

	// Create UNWIND_CODE entries for push rbx
	unwind_codes[num_unwind_codes] = 1 | (UWOP_PUSH_NONVOL << 8) | (EXP_RBX_idx << 12);
	++num_unwind_codes;

	// Create the UNWIND_INFO table
	unwind_info[0] = 1 | (0 << 3);      // version and flags
	unwind_info[1] = 8;                 // size of prolog
	unwind_info[2] = num_unwind_codes;  // num of unwind codes
	unwind_info[3] = 0;                 // frame reg and offset
	std::memcpy(&unwind_info[4], unwind_codes, sizeof(unwind_codes));
}

void
lc86_jit::gen_exception_info(uint8_t *code_ptr, size_t code_size)
{
	create_unwind_info();

	// Write .xdata
	size_t aligned_code_size = (code_size + sizeof(DWORD) - 1) & ~(sizeof(DWORD) - 1);
	std::memcpy(code_ptr + aligned_code_size, unwind_info, sizeof(unwind_info));

	// Write .pdata
	RUNTIME_FUNCTION *table = reinterpret_cast<RUNTIME_FUNCTION *>(code_ptr + aligned_code_size + sizeof(unwind_info));
	table->BeginAddress = 0;
	table->EndAddress = code_size;
	table->UnwindInfoAddress = aligned_code_size;
	m_mem.eh_frames.emplace(code_ptr, table);

	[[maybe_unused]] auto ret = RtlAddFunctionTable(table, 1, reinterpret_cast<DWORD64>(code_ptr));
	assert(ret);
}

void
os_delete_exp_info(void *addr)
{
	[[maybe_unused]] auto ret = RtlDeleteFunctionTable(static_cast<PRUNTIME_FUNCTION>(addr));
	assert(ret);
}

#endif
