/*
* inline page table optimization for xbox memory accesses
*
* ergo720                Copyright (c) 2025
*/

#include "ipt.h"
#include "memory_management.h"
#include "os_mem.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>
#include <setjmp.h>


#define FLASH_ROM_HANDLE 0
#define MCPX_ROM_HANDLE 1

#define SIG_SAVE_CTX 0
#define SIG_GUEST_PF 1
#define SIG_FATAL_ERR 2


static int ram_fd;
static int rom_fd[2];
static std::string ram_tmp_name;
static std::string rom_tmp_name[2];
static uint64_t g_ramsize;
static uint64_t g_romsize[2];
static bool signal_updated;
static struct sigaction old_sa;
static sigjmp_buf env;
static void ipt_segfault_sigaction(int signal, siginfo_t *si, void *ctx);
static cpu_t *g_cpu;

// Ipt mechanism of working. At first, every ipt element points to the guard page, which causes a fault when accessed. If the page is valid in the guest, the ipt element
// is updated with the base address of the host page that maps it (if ram or rom), otherwise is backpatched with a call to a memory handler. Also, when a page is valid,
// the memory permission of the host page are updated to reflect the memory permissions of the guest page. Finally, when the page is flushed from the tlb, the page
// reverts to no-access because the ipt points to the guard page again, and the cycle repeats. Note that the current approach doesn't support debug data breakpoints, mostly
// because the debug comparisons are done with virtual addresses

static void
ipt_signal_init()
{
	struct sigaction sa;
	std::memset(&sa, 0, sizeof(struct sigaction));
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = ipt_segfault_sigaction;
	sa.sa_flags = SA_SIGINFO;

	if (sigaction(SIGSEGV, &sa, &old_sa) == -1) {
		throw lc86_exp_abort("Failed to install signal handler", lc86_status::internal_error);
	}
	
	signal_updated = true;
}

void
ipt_ram_init(cpu_t *cpu, uint64_t ramsize)
{
	// Do these assignemnts now so that ipt_ram_deinit knows when it needs to cleanup
	g_cpu = cpu;
	g_ramsize = ramsize;
	cpu->guard_page = (uint8_t *)MAP_FAILED;
	cpu->ram = (uint8_t *)MAP_FAILED;
	cpu->ram_alias = (uint8_t *)MAP_FAILED;
	cpu->ram_contiguous = (uint8_t *)MAP_FAILED;
	cpu->ram_tiled = (uint8_t *)MAP_FAILED;
	ram_tmp_name = "tmp-XXXXXX";
	signal_updated = false;
	
	if ((ramsize != (64 * 1024 * 1024)) && (ramsize != (128 * 1024 * 1024))) {
		throw lc86_exp_abort("Invalid ram size", lc86_status::invalid_parameter);
	}

	// Reserve memory for a single guard page. This will trigger exceptions at runtime when accessing a page for the first time
	if (cpu->guard_page = (uint8_t *)mmap(NULL, PAGE_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0); cpu->guard_page == NULL) {
		throw lc86_exp_abort("Failed to reserve memory for the guard page", lc86_status::no_memory);
	}

	// Create a regular ram allocation (accessed from the host with normal memory handlers) and also an alias of it which is only accessed from the
	// jitted code with the ipt. We need to create one alias for each xbox ram pool so that we are able to emulate the guest page permissions
	// with the host page permissions
	ram_fd = mkstemp(ram_tmp_name.data());
	if (ram_fd == -1) {
		throw lc86_exp_abort("Failed to create the ram memory file", lc86_status::internal_error);
	}
	
	if (ftruncate(ram_fd, ramsize + 16) == -1) {
		throw lc86_exp_abort("Failed to resize the temporary ram file",  lc86_status::internal_error);
	}
	
	if (cpu->ram = (uint8_t *)mmap(NULL, ramsize + 16, PROT_READ | PROT_WRITE, MAP_SHARED, ram_fd, 0); cpu->ram == MAP_FAILED) {
		throw lc86_exp_abort("Failed to map the ram view", lc86_status::no_memory);
	}

	if (cpu->ram_alias = (uint8_t *)mmap(NULL, ramsize + 16, PROT_READ | PROT_WRITE, MAP_SHARED, ram_fd, 0); cpu->ram_alias == MAP_FAILED) {
		throw lc86_exp_abort("Failed to map the aliased ram view", lc86_status::no_memory);
	}

	if (cpu->ram_contiguous = (uint8_t *)mmap(NULL, ramsize + 16, PROT_READ | PROT_WRITE, MAP_SHARED, ram_fd, 0); cpu->ram_contiguous == MAP_FAILED) {
		throw lc86_exp_abort("Failed to map the contiguous ram view", lc86_status::no_memory);
	}

	if (cpu->ram_tiled = (uint8_t *)mmap(NULL, 64 * 1024 * 1024 + 16, PROT_READ | PROT_WRITE, MAP_SHARED, ram_fd, 0); cpu->ram_tiled == MAP_FAILED) {
		throw lc86_exp_abort("Failed to map the tiled ram view", lc86_status::no_memory);
	}

	unlink(ram_tmp_name.c_str());
	close(ram_fd);
	std::fill(std::begin(cpu->cpu_ctx.ipt), std::end(cpu->cpu_ctx.ipt), cpu->guard_page);
	ram_fd = -1;
	
	ipt_signal_init();
}

lc86_status
ipt_rom_init(cpu_t *cpu, uint64_t romsize, memory_region_t<addr_t> *rom, uint8_t *buffer)
{
	// Do these assignemnts now so that ipt_rom_deinit knows when it needs to cleanup
	uint32_t rom_fd_idx = rom->start == FLASH_ROM_BASE ? FLASH_ROM_HANDLE : MCPX_ROM_HANDLE;
	g_romsize[rom_fd_idx] = romsize;
	rom->rom_ptr = (uint8_t *)MAP_FAILED;
	rom->rom_alias_ptr = (uint8_t *)MAP_FAILED;
	rom_tmp_name[rom_fd_idx] = "tmp-XXXXXX";

	// Allocate 16 extra bytes at then end in the case something ever does a 2,4,8,10,16 byte access on the last valid byte of the rom
	// NOTE: unlike main ram, we don't need to create additional rom aliases to handle page permissions because all valid rom pages are always read-only
	rom_fd[rom_fd_idx] = mkstemp(rom_tmp_name[rom_fd_idx].data());
	if (rom_fd[rom_fd_idx] == -1) {
		last_error = "Failed to create the ram memory file";
		return lc86_status::internal_error;
	}
	
	if (ftruncate(rom_fd[rom_fd_idx], romsize + 16) == -1) {
		last_error = "Failed to resize the temporary rom file";
		return lc86_status::internal_error;
	}
	
	if (rom->rom_ptr = (uint8_t *)mmap(NULL, romsize + 16, PROT_READ | PROT_WRITE, MAP_SHARED, rom_fd[rom_fd_idx], 0); rom->rom_ptr == MAP_FAILED) {
		last_error = "Failed to map the rom view";
		return lc86_status::no_memory;
	}

	if (rom->rom_alias_ptr = (uint8_t *)mmap(NULL, romsize + 16, PROT_READ | PROT_WRITE, MAP_SHARED, rom_fd[rom_fd_idx], 0); rom->rom_alias_ptr == MAP_FAILED) {
		last_error = "Failed to map the aliased rom view";
		return lc86_status::no_memory;
	}

	std::memcpy(rom->rom_ptr, buffer, romsize);
	unlink(rom_tmp_name[rom_fd_idx].c_str());
	close(rom_fd[rom_fd_idx]);
	rom_fd[rom_fd_idx] = -1;

	// Always protect the rom to make sure that nothing writes to it
	if (mprotect(rom->rom_alias_ptr, romsize + 16, PROT_READ) == -1) {
		last_error = "Failed to mark rom memory as read-only";
		return lc86_status::internal_error;
	}

	return lc86_status::success;
}

void
ipt_ram_deinit(cpu_t *cpu)
{
	if (cpu->guard_page != MAP_FAILED) {
		munmap(cpu->guard_page, PAGE_SIZE);
	}
	if (cpu->ram != MAP_FAILED) {
		munmap(cpu->ram, g_ramsize + 16);
	}
	if (cpu->ram_alias != MAP_FAILED) {
		munmap(cpu->ram_alias, g_ramsize + 16);
	}
	if (cpu->ram_contiguous != MAP_FAILED) {
		munmap(cpu->ram_contiguous, g_ramsize + 16);
	}
	if (cpu->ram_tiled != MAP_FAILED) {
		munmap(cpu->ram_tiled, 64 * 1024 * 1024 + 16);
	}
	if (ram_fd != -1) {
		unlink(ram_tmp_name.c_str());
		close(ram_fd);
	}
	if (signal_updated) {
		sigaction(SIGSEGV, &old_sa, NULL);
	}
}

void
ipt_rom_deinit(uint8_t *rom_ptr, uint8_t *rom_alias_ptr, addr_t start)
{
	uint32_t rom_fd_idx = rom_fd[start == FLASH_ROM_BASE ? FLASH_ROM_HANDLE : MCPX_ROM_HANDLE];
	if (rom_ptr != MAP_FAILED) {
		munmap(rom_ptr, g_romsize[rom_fd_idx] + 16);
	}
	if (rom_alias_ptr != MAP_FAILED) {
		munmap(rom_alias_ptr, g_romsize[rom_fd_idx] + 16);
	}
	if (rom_fd[rom_fd_idx] != -1) {
		unlink(rom_tmp_name[rom_fd_idx].c_str());
		close(rom_fd[rom_fd_idx]);
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

	if (mprotect(ram_addr, PAGE_SIZE, PROT_READ) == 0) {
		if (mprotect(contiguous_addr, PAGE_SIZE, PROT_READ) == 0) {
			if (mprotect(tiled_addr, PAGE_SIZE, PROT_READ) == 0) {
				return;
			}
		}
	}

	LIB86CPU_ABORT_msg("Failed to change memory permissions of page at phys_addr 0x%016" PRIX64, phys_addr);
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
	uint32_t nops_to_add, size_to_flush;

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
	uint32_t nop_max_size = is_multi_nop_supported ? 9 : 1, nops_left = nops_to_add;

	while (nops_left) {
		uint32_t nops_added = std::min(nops_left, nop_max_size);
		std::memcpy(addr_nops_start, nop_arr[nops_added - 1], nops_added);
		addr_nops_start += nops_added;
		nops_left -= nops_added;
	}

	os_flush_instr_cache(addr_to_patch, addr_to_patch + size_to_flush);
}

void
ipt_segfault_sigaction(int signal, siginfo_t *si, void *ctx)
{
	exp_data_t exp_data{ 0, 0, EXP_INVALID };
	ucontext_t *uc = (ucontext_t *)ctx;
	addr_t faulting_guest_addr = uc->uc_mcontext.gregs[REG_RDX] & 0xFFFFFFFF;
	bool is_code = false;
	uint32_t page_info;
	addr_t phys_addr;

	// The following maps don't account for the seocond MOV of 80/128 bit accesses because they cannot fault. This is because the runtime code does
	// a page cross check, and invokes a memory handler if they do
	static const std::map<uint32_t, std::pair<uint32_t, uint32_t>> read_instr_bytes = {
		{ 0x180c8b4e, { 16, 95 } }, // mov r9,QWORD PTR [rax+r11*1] - 128
		{ 0x18048b4e, { 10, 95 } }, // mov r8,QWORD PTR [rax+r11*1] - 80
		{ 0x18048b4a, { 8, 77 } },  // mov rax,QWORD PTR [rax+r11*1] - 64
		{ 0x18048b42, { 4, 77 } },  // mov eax,DWORD PTR [rax+r11*1] - 32
		{ 0x048b4266, { 2, 77 } },  // mov ax,WORD PTR [rax+r11*1] - 16
		{ 0x18048a42, { 1, 29 } }   // mov al,BYTE PTR [rax+r11*1] - 8
	};

	static const std::map<uint32_t, std::pair<uint32_t, uint32_t>> write_instr_bytes = {
		{ 0x180c894e, { 16, 84 } }, // mov QWORD PTR [rax+r11*1],r9 - 128
		{ 0x1814894e, { 10, 85 } }, // mov QWORD PTR [rax+r11*1],r10 - 80
		{ 0x1804894e, { 8, 77 } },  // mov QWORD PTR [rax+r11*1],r8 - 64
		{ 0x18048946, { 4, 77 } },  // mov DWORD PTR [rax+r11*1],r8d - 32
		{ 0x04894666, { 2, 77 } },  // mov WORD PTR [rax+r11*1],r8w - 16
		{ 0x18048846, { 1, 29 } }   // mov BYTE PTR [rax+r11*1],r8b - 8
	};

	if (!(uc->uc_mcontext.gregs[REG_ERR] & 2)) { // fault was a read
		phys_addr = query_read_addr(g_cpu, faulting_guest_addr, 0, &exp_data, &page_info);
	}
	else { // fault was a write
		phys_addr = query_write_addr(g_cpu, faulting_guest_addr, 0, &is_code, &exp_data, &page_info);
	}

	if (exp_data.idx == EXP_PF) {
		// Page is invalid, invoke the guest exception handler
		siglongjmp(env, SIG_GUEST_PF);
	}

	// Page is valid, figure out how to handle it
	const memory_region_t<addr_t> *region = as_memory_search_addr(g_cpu, phys_addr);
	uint8_t *faulting_host_addr = (uint8_t *)uc->uc_mcontext.gregs[REG_RIP];

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
				ipt_backpatch<true>(g_cpu, faulting_host_addr, it->second.first, it->second.second);
				uc->uc_mcontext.gregs[REG_RIP] -= it->second.second; // adjust rip to point to the start of the patched code
				tc_invalidate(&g_cpu->cpu_ctx, phys_addr, it->second.first);
				break;
			}
			size_t regionsize = region->end - region->start + 1;
			if ((phys_addr >= 0) && (phys_addr <= regionsize)) { // main ram
				buffer = g_cpu->ram_alias;
			}
			else if ((phys_addr >= CONTIGUOUS_START) && (phys_addr <= (CONTIGUOUS_START + regionsize))) { // contiguous ram
				buffer = g_cpu->ram_contiguous;
			}
			else {
				assert((phys_addr >= TILED_START) && (phys_addr <= TILED_END)); // tiled ram
				buffer = g_cpu->ram_tiled;
			}
		}
		else {
			if (uc->uc_mcontext.gregs[REG_ERR] & 2) {
				// Patch the attempted write to rom
				const auto it = write_instr_bytes.find(*(uint32_t *)faulting_host_addr);
				assert(it != write_instr_bytes.end());
				ipt_backpatch<true>(g_cpu, faulting_host_addr, it->second.first, it->second.second);
				uc->uc_mcontext.gregs[REG_RIP] -= it->second.second; // adjust rip to point to the start of the patched code
				break;
			}
			buffer = region->rom_alias_ptr;
		}

		uint8_t *host_page_base = buffer + ((phys_addr - region->buff_off_start) & ~PAGE_MASK);
		g_cpu->cpu_ctx.ipt[faulting_guest_addr >> PAGE_SHIFT] = host_page_base;

		// NOTE: the cpu is always in supervisor mode on the xbox, so we can ignore the PAGE_USER access of the page, We can also ignore PAGE_GUARD too,
		// since those are always invalid (aka PTE_PRESENT == 0)
		if (region->type != mem_type::rom) {
			int new_protect;
			if (g_cpu->smc[phys_addr >> PAGE_SHIFT] || !(page_info & PAGE_WRITE)) {
				new_protect = PROT_READ; // read-only or code page
			} else {
				new_protect = PROT_READ | PROT_WRITE;
			}
			if (mprotect(host_page_base, PAGE_SIZE, new_protect) == -1) {
				LOG(log_level::error, "Failed to change memory permissions of page at host address 0x%016" PRIX64, (uintptr_t)host_page_base);
				siglongjmp(env, SIG_FATAL_ERR);
			}
		}
		uc->uc_mcontext.gregs[REG_RAX] = (uintptr_t)host_page_base; // adjust rax to point to the correct host page
	}
	break;

	case mem_type::mmio:
	case mem_type::unmapped: {
		// Always patch mmio accesses (should only happen with indirect memory references)
		// We do the same with unmapped regions too
		if (!(uc->uc_mcontext.gregs[REG_ERR] & 2)) { // fault was a read
			const auto it = read_instr_bytes.find(*(uint32_t *)faulting_host_addr);
			assert(it != read_instr_bytes.end());
			ipt_backpatch<false>(g_cpu, faulting_host_addr, it->second.first, it->second.second);
			uc->uc_mcontext.gregs[REG_RIP] -= it->second.second; // adjust rip to point to the start of the patched code
		}
		else { // fault was a write
			const auto it = write_instr_bytes.find(*(uint32_t *)faulting_host_addr);
			assert(it != write_instr_bytes.end());
			ipt_backpatch<true>(g_cpu, faulting_host_addr, it->second.first, it->second.second);
			uc->uc_mcontext.gregs[REG_RIP] -= it->second.second; // adjust rip to point to the start of the patched code
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
		LOG(log_level::error, "Unexpected memory region type %" PRId32, (std::underlying_type_t<mem_type>)region->type);
		siglongjmp(env, SIG_FATAL_ERR);
	}
}

static translated_code_t *
ipt_raise_exception(cpu_ctx_t *cpu_ctx)
{
	retry_exp:
	try {
		// the exception handler always returns nullptr
		return cpu_raise_exception(cpu_ctx);
	}
	catch ([[maybe_unused]] host_exp_t type) {
		assert(type == host_exp_t::pf_exp);

		// page fault exception while delivering another exception
		goto retry_exp;
	}

	LIB86CPU_ABORT();
}

translated_code_t *
ipt_run_guarded_code(cpu_ctx_t *cpu_ctx, translated_code_t *tc)
{
	int ret = sigsetjmp(env, 1);
	if (ret == SIG_SAVE_CTX) {
		return tc->ptr_code(cpu_ctx);
	}
	else if (ret == SIG_GUEST_PF) {
		return ipt_raise_exception(cpu_ctx);
	}

	LIB86CPU_ABORT();
}

