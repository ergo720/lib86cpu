/*
* inline page table optimization for xbox memory accesses
*
* ergo720                Copyright (c) 2024
*/

#include "os_mem.h"
#include "ipt.h"
#include "memory_management.h"
#include "Windows.h"
#undef min // allows using std::min

#define FLASH_ROM_HANDLE 0
#define MCPX_ROM_HANDLE 1


static HANDLE ram_handle;
static HANDLE rom_handle[2];

static bool raise_page_fault;
static std::string err_msg;

// Ipt mechanism of working. At first, every ipt element points to the guard page, which causes a fault when accessed. If the page is valid in the guest, the ipt element
// is updated with the base address of the host page that maps it (if ram or rom), otherwise is backpatched with a call to a memory handler. Also, when a page is valid,
// the memory permission of the host page are updated to reflect the memory permissions of the guest page. Finally, when the page is flushed from the tlb, the page
// reverts to no-access because the ipt points to the guard page again, and the cycle repeats. Note that the current approach doesn't support debug data breakpoints, mostly
// because the debug comparisons are done with virtual addresses

void
ipt_ram_init(cpu_t *cpu, size_t ramsize)
{
	if ((ramsize != (64 * 1024 * 1024)) && (ramsize != (128 * 1024 * 1024))) {
		throw lc86_exp_abort("Invalid ram size", lc86_status::invalid_parameter);
	}

	// Reserve memory for a single guard page. This will trigger exceptions at runtime when accessing a page for the first time
	if (cpu->guard_page = (uint8_t *)VirtualAlloc(NULL, PAGE_SIZE, MEM_RESERVE, PAGE_NOACCESS); cpu->guard_page == NULL) {
		throw lc86_exp_abort("Failed to reserve memory for the guard page", lc86_status::no_memory);
	}

	// Create a regular ram allocation (accessed from the host with normal memory handlers) and also an alias of it which is only accessed from the
	// jitted code with the ipt. We need to create one alias for each xbox ram pool so that we are able to emulate the guest page permissions
	// with the host page permissions
	ram_handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, ramsize + 16, NULL);
	if (ram_handle == NULL) {
		throw lc86_exp_abort("Failed to create the ram memory mapping", lc86_status::no_memory);
	}

	if (cpu->ram = (uint8_t *)MapViewOfFile(ram_handle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0); cpu->ram == NULL) {
		throw lc86_exp_abort("Failed to map the ram view", lc86_status::no_memory);
	}

	if (cpu->ram_alias = (uint8_t *)MapViewOfFile(ram_handle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0); cpu->ram_alias == NULL) {
		throw lc86_exp_abort("Failed to map the aliased ram view", lc86_status::no_memory);
	}

	if (cpu->ram_contiguous = (uint8_t *)MapViewOfFile(ram_handle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0); cpu->ram_contiguous == NULL) {
		throw lc86_exp_abort("Failed to map the contiguous ram view", lc86_status::no_memory);
	}

	if (cpu->ram_tiled = (uint8_t *)MapViewOfFile(ram_handle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 64 * 1024 * 1024); cpu->ram_tiled == NULL) {
		throw lc86_exp_abort("Failed to map the tiled ram view", lc86_status::no_memory);
	}

	std::fill(std::begin(cpu->cpu_ctx.ipt), std::end(cpu->cpu_ctx.ipt), cpu->guard_page);
}

lc86_status
ipt_rom_init(cpu_t *cpu, size_t romsize, memory_region_t<addr_t> *rom, uint8_t *buffer)
{
	uint32_t rom_handle_idx = rom->start == FLASH_ROM_BASE ? FLASH_ROM_HANDLE : MCPX_ROM_HANDLE;

	// Allocate 16 extra bytes at then end in the case something ever does a 2,4,8,10,16 byte access on the last valid byte of the rom
	// NOTE: unlike main ram, we don't need to create rom aliases to handle page permissions because all valid rom pages are always read-only
	rom_handle[rom_handle_idx] = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, romsize + 16, NULL);
	if (rom_handle[rom_handle_idx] == NULL) {
		last_error = "Failed to create the rom memory mapping";
		return lc86_status::no_memory;
	}

	if (rom->rom_ptr = (uint8_t *)MapViewOfFile(rom_handle[rom_handle_idx], FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0); rom->rom_ptr == NULL) {
		last_error = "Failed to map the rom view";
		return lc86_status::no_memory;
	}

	if (rom->rom_alias_ptr = (uint8_t *)MapViewOfFile(rom_handle[rom_handle_idx], FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0); rom->rom_alias_ptr == NULL) {
		last_error = "Failed to map the aliased rom view";
		return lc86_status::no_memory;
	}

	std::memcpy(rom->rom_ptr, buffer, romsize);

	// Always protect the rom to make sure that nothing writes to it
	DWORD old_protect;
	if (VirtualProtect(rom->rom_alias_ptr, romsize, PAGE_READONLY, &old_protect) == 0) {
		last_error = std::format("{}: failed to mark rom memory as read-only", __func__);
		return lc86_status::internal_error;
	}

	return lc86_status::success;
}

void
ipt_ram_deinit(cpu_t *cpu)
{
	if (cpu->guard_page) {
		VirtualFree(cpu->guard_page, 0, MEM_RELEASE);
	}
	if (cpu->ram) {
		UnmapViewOfFile(cpu->ram);
	}
	if (cpu->ram_alias) {
		UnmapViewOfFile(cpu->ram_alias);
	}
	if (cpu->ram_contiguous) {
		UnmapViewOfFile(cpu->ram_contiguous);
	}
	if (cpu->ram_tiled) {
		UnmapViewOfFile(cpu->ram_tiled);
	}
	if (ram_handle) {
		CloseHandle(ram_handle);
	}
}

void
ipt_rom_deinit(uint8_t *rom_ptr, uint8_t *rom_alias_ptr, addr_t start)
{
	if (rom_ptr) {
		UnmapViewOfFile(rom_ptr);
	}
	if (rom_alias_ptr) {
		UnmapViewOfFile(rom_alias_ptr);
	}
	HANDLE handle = rom_handle[start == FLASH_ROM_BASE ? FLASH_ROM_HANDLE : MCPX_ROM_HANDLE];
	if (handle) {
		CloseHandle(handle);
	}
}

void
ipt_protect_code_page(cpu_t *cpu, addr_t phys_addr)
{
	// NOTE: tc that cross pages are never cached in the code cache

	uint8_t *ram_addr, *contiguous_addr, *tiled_addr;
	retry:
	const memory_region_t<addr_t> *region = as_memory_search_addr(cpu, phys_addr);
	if (region->type == mem_type::ram) {
		ram_addr = (uint8_t *)((uintptr_t)(&cpu->ram_alias[phys_addr - region->buff_off_start]) & ~PAGE_MASK);
		contiguous_addr = (uint8_t *)((uintptr_t)(&cpu->ram_contiguous[phys_addr - region->buff_off_start]) & ~PAGE_MASK);
		tiled_addr = (uint8_t *)((uintptr_t)(&cpu->ram_tiled[phys_addr - region->buff_off_start]) & ~PAGE_MASK);
	}
	else if (region->type == mem_type::rom) {
		// Nothing to do, because rom is always read-only
		return;
	}
	else if (region->type == mem_type::alias) {
		const memory_region_t<addr_t> *alias = region;
		AS_RESOLVE_ALIAS();
		phys_addr = region->start + alias_offset + (phys_addr - alias->start);
		goto retry;
	}
	else {
		// Nothing to do
		return;
	}

	DWORD old_protect;
	if (VirtualProtect(ram_addr, PAGE_SIZE, PAGE_READONLY, &old_protect)) {
		if (VirtualProtect(contiguous_addr, PAGE_SIZE, PAGE_READONLY, &old_protect)) {
			if (VirtualProtect(tiled_addr, PAGE_SIZE, PAGE_READONLY, &old_protect)) {
				return;
			}
		}
	}

	std::string err = std::vformat("{}: failed to change memory permissions of page at phys_addr {:#018x}", std::make_format_args(__func__, phys_addr));
	throw lc86_exp_abort(err, lc86_status::internal_error);
}

void
ipt_flush(cpu_t *cpu)
{
	std::fill(std::begin(cpu->cpu_ctx.ipt), std::end(cpu->cpu_ctx.ipt), cpu->guard_page);
}

void
ipt_flush(cpu_t *cpu, addr_t virt_addr)
{
	cpu->cpu_ctx.ipt[virt_addr >> PAGE_SHIFT] = cpu->guard_page;
}

template<bool is_write>
static void
ipt_backpatch(cpu_t *cpu, uint8_t *faulting_addr, uint32_t mem_access_size, uint32_t mem_access_offset)
{
	uint8_t *addr_to_patch = faulting_addr - mem_access_offset, *addr_nops_start;
	size_t nops_to_add, size_to_flush;

	if (mem_access_size == 1) {
		// Bytes to patch: 29 (ipt check) + 4 (MOV) -> patched: 22, nop: 11

		static const uint8_t read_write_call[] = {
			0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax,imm64
			0xff, 0xd0,                                                 // call rax
			0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // movabs rcx,imm64
		};

		std::memcpy(addr_to_patch, read_write_call, sizeof(read_write_call));
		*(uint64_t *)(addr_to_patch + 2) = is_write ? (uint64_t)&mem_write_jit_helper<uint8_t> : (uint64_t)&mem_read_jit_helper<uint8_t>;
		*(uint64_t *)(addr_to_patch + 14) = (uint64_t)&cpu->cpu_ctx;
		addr_nops_start = addr_to_patch + sizeof(read_write_call);
		nops_to_add = 11;
		size_to_flush = 33;
	}
	else {
		// Bytes to patch: 21 (page boundary check) -> nop: 21
		addr_nops_start = addr_to_patch;
		nops_to_add = size_to_flush = 21;
	}

	static const uint8_t nop1[] = { 0x90 };
	static const uint8_t nop2[] = { 0x66, 0x90 };
	static const uint8_t nop3[] = { 0x0F, 0x1F, 0x00 };
	static const uint8_t nop4[] = { 0x0F, 0x1F, 0x40, 0x00 };
	static const uint8_t nop5[] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };
	static const uint8_t nop6[] = { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
	static const uint8_t nop7[] = { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 };
	static const uint8_t nop8[] = { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
	static const uint8_t nop9[] = { 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
	static const uint8_t *nop_arr[] = { nop1, nop2, nop3, nop4, nop5, nop6, nop7, nop8, nop9 };
	size_t nop_max_size = is_multi_nop_supported ? 9 : 1, nops_left = nops_to_add;

	while (nops_left) {
		uint32_t nops_added = std::min(nops_left, nop_max_size);
		std::memcpy(addr_nops_start, nop_arr[nops_added - 1], nops_added);
		addr_nops_start += nops_added;
		nops_left -= nops_added;
	}

	os_flush_instr_cache(addr_to_patch, size_to_flush);
}

static int
ipt_exception_filter(cpu_t *cpu, EXCEPTION_POINTERS *e)
{
	// NOTE: ipt_exception_filter should never throw C++ exceptions (aka LIB86CPU_ABORT), as that seems to cause weird crashes

	if (e->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) [[likely]] {
		exp_data_t exp_data{ 0, 0, EXP_INVALID };
		addr_t faulting_guest_addr = e->ContextRecord->Rdx & 0xFFFFFFFF;
		bool is_code = false;
		uint32_t page_info;
		addr_t phys_addr;

		// The following maps don't account for the seocond MOV of 80/128 bit accesses because they cannot fault. This is because the runtime code does
		// a page cross check, and invokes a memory handler if they do
		static const std::map<uint32_t, std::pair<uint32_t, uint32_t>> read_instr_bytes = {
			{ 0x180c8b4e, { 16, 95 } }, // mov r9,QWORD PTR [rax+r11*1] - 128
			{ 0x18048b4e, { 10, 95 } },	// mov r8,QWORD PTR [rax+r11*1] - 80
			{ 0x18048b4a, { 8, 77 } },	// mov rax,QWORD PTR [rax+r11*1] - 64
			{ 0x18048b42, { 4, 77 } },	// mov eax,DWORD PTR [rax+r11*1] - 32
			{ 0x048b4266, { 2, 77 } },	// mov ax,WORD PTR [rax+r11*1] - 16
			{ 0x18048a42, { 1, 29 } }	// mov al,BYTE PTR [rax+r11*1] - 8
		};

		static const std::map<uint32_t, std::pair<uint32_t, uint32_t>> write_instr_bytes = {
			{ 0x180c894e, { 16, 84 } }, // mov QWORD PTR [rax+r11*1],r9 - 128
			{ 0x1814894e, { 10, 85 } }, // mov QWORD PTR [rax+r11*1],r10 - 80
			{ 0x1804894e, { 8, 77 } },  // mov QWORD PTR [rax+r11*1],r8 - 64
			{ 0x18048946, { 4, 77 } },  // mov DWORD PTR [rax+r11*1],r8d - 32
			{ 0x04894666, { 2, 77 } },  // mov WORD PTR [rax+r11*1],r8w - 16
			{ 0x18048846, { 1, 29 } }   // mov BYTE PTR [rax+r11*1],r8b - 8
		};

		if (e->ExceptionRecord->ExceptionInformation[0] == 0) { // fault was a read
			phys_addr = query_read_addr(cpu, faulting_guest_addr, 0, &exp_data, &page_info);
		}
		else { // fault was a write
			phys_addr = query_write_addr(cpu, faulting_guest_addr, 0, &is_code, &exp_data, &page_info);
		}

		if (exp_data.idx == EXP_PF) {
			// Page is invalid, invoke the guest exception handler
			raise_page_fault = true;
			return EXCEPTION_EXECUTE_HANDLER;
		}

		// Page is valid, figure out how to handle it
		const memory_region_t<addr_t> *region = as_memory_search_addr(cpu, phys_addr);
		uint8_t *faulting_host_addr = (uint8_t *)e->ContextRecord->Rip;

		retry:
		switch (region->type)
		{
		case mem_type::ram:
		case mem_type::rom: {
			// With ram and rom, we can update the ipt entry to point to the host page that maps the guest physical page
			uint8_t *buffer;
			if (region->type == mem_type::ram) {
				if (is_code) {
					// We have hit a code page, so we patch it to avoid further exceptions on it (this can only happen with writes)
					const auto it = write_instr_bytes.find(*(uint32_t *)faulting_host_addr);
					assert(it != write_instr_bytes.end());
					ipt_backpatch<true>(cpu, faulting_host_addr, it->second.first, it->second.second);
					e->ContextRecord->Rip -= it->second.second; // adjust rip to point to the start of the patched code
					tc_invalidate(&cpu->cpu_ctx, phys_addr, it->second.first);
					break;
				}
				size_t regionsize = region->end - region->start + 1;
				if ((phys_addr >= 0) && (phys_addr <= regionsize)) { // main ram
					buffer = cpu->ram_alias;
				}
				else if ((phys_addr >= CONTIGUOUS_START) && (phys_addr <= (CONTIGUOUS_START + regionsize))) { // contiguous ram
					buffer = cpu->ram_contiguous;
				}
				else {
					assert((phys_addr >= TILED_START) && (phys_addr <= TILED_END)); // tiled ram
					buffer = cpu->ram_tiled;
				}
			}
			else {
				if (e->ExceptionRecord->ExceptionInformation[0] == 1) {
					// Patch the attempted write to rom
					const auto it = write_instr_bytes.find(*(uint32_t *)faulting_host_addr);
					assert(it != write_instr_bytes.end());
					ipt_backpatch<true>(cpu, faulting_host_addr, it->second.first, it->second.second);
					e->ContextRecord->Rip -= it->second.second; // adjust rip to point to the start of the patched code
					break;
				}
				buffer = region->rom_alias_ptr;
			}

			uint8_t *host_page_base = buffer + ((phys_addr - region->buff_off_start) & ~PAGE_MASK);
			cpu->cpu_ctx.ipt[faulting_guest_addr >> PAGE_SHIFT] = host_page_base;

			// NOTE: the cpu is always in supervisor mode on the xbox, so we can ignore the PAGE_USER access of the page, We can also ignore PAGE_GUARD too,
			// since those are always invalid (aka PTE_PRESENT == 0)
			if (region->type != mem_type::rom) {
				DWORD new_protect, old_protect;
				if (cpu->smc[phys_addr >> PAGE_SHIFT] || !(page_info & PAGE_WRITE)) {
					new_protect = PAGE_READONLY; // read-only or code page
				} else {
					new_protect = PAGE_READWRITE;
				}
				if (VirtualProtect(host_page_base, PAGE_SIZE, new_protect, &old_protect) == 0) {
					err_msg = std::vformat("{}: failed to change memory permissions of page {:#018x}", std::make_format_args(__func__, (uintptr_t)host_page_base));
					raise_page_fault = false;
					return EXCEPTION_EXECUTE_HANDLER;
				}
			}
			e->ContextRecord->Rax = (uintptr_t)host_page_base; // adjust rax to point to the correct host page
		}
		break;

		case mem_type::mmio:
		case mem_type::unmapped: {
			// Always patch mmio accesses (should only happen with indirect memory references)
			// We do the same with unmapped regions too
			if (e->ExceptionRecord->ExceptionInformation[0] == 0) { // fault was a read
				const auto it = read_instr_bytes.find(*(uint32_t *)faulting_host_addr);
				assert(it != read_instr_bytes.end());
				ipt_backpatch<false>(cpu, faulting_host_addr, it->second.first, it->second.second);
				e->ContextRecord->Rip -= it->second.second; // adjust rip to point to the start of the patched code
			}
			else { // fault was a write
				const auto it = write_instr_bytes.find(*(uint32_t *)faulting_host_addr);
				assert(it != write_instr_bytes.end());
				ipt_backpatch<true>(cpu, faulting_host_addr, it->second.first, it->second.second);
				e->ContextRecord->Rip -= it->second.second; // adjust rip to point to the start of the patched code
			}
		}
		break;

		case mem_type::alias: {
			const memory_region_t<addr_t> *alias = region;
			AS_RESOLVE_ALIAS();
			phys_addr = region->start + alias_offset + (phys_addr - alias->start);
			goto retry;
		}
		break;

		default:
			err_msg = std::vformat("{}: unexpected memory region type {:d}", std::make_format_args(__func__, (unsigned)region->type));
			raise_page_fault = false;
			return EXCEPTION_EXECUTE_HANDLER;
		}

		// Clear the trap flag. While debugging, sometimes a single step exception is immediately triggered upon resuming execution and the debugger will not catch it for unknown
		// reasons. This will be caught by us here, and because we reject it in the below code, it will terminate the emulation. Clearing the flag here seems to fix this
		e->ContextRecord->EFlags &= ~(1 << 8);

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if ((e->ExceptionRecord->ExceptionCode != STILL_ACTIVE) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_DATATYPE_MISALIGNMENT) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_ARRAY_BOUNDS_EXCEEDED) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_FLT_DENORMAL_OPERAND) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_FLT_DIVIDE_BY_ZERO) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_FLT_INEXACT_RESULT) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_FLT_INVALID_OPERATION) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_FLT_OVERFLOW) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_FLT_STACK_CHECK) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_FLT_UNDERFLOW) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_INT_DIVIDE_BY_ZERO) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_INT_OVERFLOW) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_PRIV_INSTRUCTION) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_IN_PAGE_ERROR) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_NONCONTINUABLE_EXCEPTION) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_STACK_OVERFLOW) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_INVALID_DISPOSITION) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_GUARD_PAGE) &&
		(e->ExceptionRecord->ExceptionCode != EXCEPTION_INVALID_HANDLE) &&
		(e->ExceptionRecord->ExceptionCode != CONTROL_C_EXIT)) {
			// This is probably a C++ exception thrown by some other code in lib86cpu. According to https://devblogs.microsoft.com/oldnewthing/20100730-00/?p=13273,
			// the error code should be 0xE06D7363
			assert(e->ExceptionRecord->ExceptionCode == 0xE06D7363);
			return EXCEPTION_CONTINUE_SEARCH;
	}

	// This is not an exception we can handle, terminate the emulation
	raise_page_fault = false;
	err_msg = std::format("{}: unhandled os exception while running the jitted code", __func__);
	return EXCEPTION_EXECUTE_HANDLER;
}

static translated_code_t *
ipt_raise_exception(cpu_ctx_t *cpu_ctx)
{
	retry_exp:
	try {
		// the exception handler always returns nullptr
		return cpu_raise_exception(cpu_ctx);
	}
	catch (host_exp_t type) {
		assert(type == host_exp_t::pf_exp);

		// page fault exception while delivering another exception
		goto retry_exp;
	}

	LIB86CPU_ABORT();
}

translated_code_t *
ipt_run_guarded_code(cpu_ctx_t *cpu_ctx, translated_code_t *tc)
{
	__try {
		return tc->ptr_code(cpu_ctx);
	}
	__except (ipt_exception_filter(cpu_ctx->cpu, GetExceptionInformation())) {
		if (raise_page_fault) {
			return ipt_raise_exception(cpu_ctx);
		}

		throw lc86_exp_abort(err_msg, lc86_status::internal_error);
	}
}
