/*
 * This is the interface to the client.
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#include "internal.h"
#include "memory.h"
#ifdef LIB86CPU_X64_EMITTER
#include "x64/jit.h"
#endif
#include <fstream>


static uint8_t
default_mmio_read_handler8(addr_t addr, void *opaque)
{
	LOG(log_level::warn, "Unhandled MMIO read at address %#010x", addr);
	return std::numeric_limits<uint8_t>::max();
}

static uint16_t
default_mmio_read_handler16(addr_t addr, void *opaque)
{
	LOG(log_level::warn, "Unhandled MMIO read at address %#010x", addr);
	return std::numeric_limits<uint16_t>::max();
}

static uint32_t
default_mmio_read_handler32(addr_t addr, void *opaque)
{
	LOG(log_level::warn, "Unhandled MMIO read at address %#010x", addr);
	return std::numeric_limits<uint32_t>::max();
}

static uint64_t
default_mmio_read_handler64(addr_t addr, void *opaque)
{
	LOG(log_level::warn, "Unhandled MMIO read at address %#010x", addr);
	return std::numeric_limits<uint64_t>::max();
}

static void
default_mmio_write_handler8(addr_t addr, const uint8_t value, void *opaque)
{
	LOG(log_level::warn, "Unhandled MMIO write at address %#010x", addr);
}

static void
default_mmio_write_handler16(addr_t addr, const uint16_t value, void *opaque)
{
	LOG(log_level::warn, "Unhandled MMIO write at address %#010x", addr);
}

static void
default_mmio_write_handler32(addr_t addr, const uint32_t value, void *opaque)
{
	LOG(log_level::warn, "Unhandled MMIO write at address %#010x", addr);
}

static void
default_mmio_write_handler64(addr_t addr, const uint64_t value, void *opaque)
{
	LOG(log_level::warn, "Unhandled MMIO write at address %#010x", addr);
}

static uint8_t
default_pmio_read_handler8(addr_t addr, void *opaque)
{
	LOG(log_level::warn, "Unhandled PMIO read at port %#06x", addr);
	return std::numeric_limits<uint8_t>::max();
}

static uint16_t
default_pmio_read_handler16(addr_t addr, void *opaque)
{
	LOG(log_level::warn, "Unhandled PMIO read at port %#06x", addr);
	return std::numeric_limits<uint16_t>::max();
}

static uint32_t
default_pmio_read_handler32(addr_t addr, void *opaque)
{
	LOG(log_level::warn, "Unhandled PMIO read at port %#06x", addr);
	return std::numeric_limits<uint32_t>::max();
}

static void
default_pmio_write_handler8(addr_t addr, const uint8_t value, void *opaque)
{
	LOG(log_level::warn, "Unhandled PMIO write at port %#06x", addr);
}

static void
default_pmio_write_handler16(addr_t addr, const uint16_t value, void *opaque)
{
	LOG(log_level::warn, "Unhandled PMIO write at port %#06x", addr);
}

static void
default_pmio_write_handler32(addr_t addr, const uint32_t value, void *opaque)
{
	LOG(log_level::warn, "Unhandled PMIO write at port %#06x", addr);
}

// NOTE: lib86cpu runs entirely on the single thread that calls cpu_run, so calling the below functions from other threads is not safe. Only call them
// from the hook, mmio or pmio callbacks or before the emulation starts.

/*
* cpu_new -> creates a new cpu instance. Only a single instance should exist at a time
* ramsize: size in bytes of ram buffer internally created (must be a multiple of 4096)
* out: returned cpu instance
* (optional) debuggee: name of the debuggee program to run
* ret: the status of the operation
*/
lc86_status
cpu_new(size_t ramsize, cpu_t *&out, const char *debuggee)
{
	LOG(log_level::info, "Creating new cpu...");

	out = nullptr;
	cpu_t *cpu = new cpu_t();
	if (cpu == nullptr) {
		return set_last_error(lc86_status::no_memory);
	}

	if (ramsize == 0) {
		cpu_free(cpu);
		return set_last_error(lc86_status::invalid_parameter);
	}

	cpu->cpu_ctx.ram = new uint8_t[ramsize];
	if (cpu->cpu_ctx.ram == nullptr) {
		cpu_free(cpu);
		return set_last_error(lc86_status::no_memory);
	}

	cpu->cpu_name = "Intel Pentium III";
	cpu_reset(cpu);
	// XXX: eventually, the user should be able to set the instruction formatting
	set_instr_format(cpu);
	cpu->dbg_name = debuggee ? debuggee : "";

	cpu->memory_space_tree = address_space<addr_t>::create();
	cpu->io_space_tree = address_space<port_t>::create();
	cpu->cached_regions.push_back(nullptr);

	try {
		cpu->jit = std::make_unique<lc86_jit>(cpu);
	}
	catch (lc86_exp_abort &exp) {
		cpu_free(cpu);
		last_error = exp.what();
		return exp.get_code();
	}

	LOG(log_level::info, "Created new cpu \"%s\"", cpu->cpu_name);

	cpu->cpu_ctx.cpu = out = cpu;
	return lc86_status::success;
}

/*
* cpu_free -> destroys a cpu instance. Only call this after cpu_run has returned
* cpu: a valid cpu instance
* ret: nothing
*/
void
cpu_free(cpu_t *cpu)
{
	if (cpu->cpu_ctx.ram) {
		delete[] cpu->cpu_ctx.ram;
	}

	for (auto &bucket : cpu->code_cache) {
		bucket.clear();
	}

	delete cpu;
}

/*
* cpu_run -> starts the emulation. Only returns when there is an error in lib86cpu
* cpu: a valid cpu instance
* ret: the exit reason
*/
lc86_status
cpu_run(cpu_t *cpu)
{
	cpu_sync_state(cpu);
	return cpu_start(cpu);
}

/*
* cpu_sync_state -> synchronizes internal cpu flags with the current cpu state. Only call this before cpu_run
* cpu: a valid cpu instance
* ret: nothing
*/
void
cpu_sync_state(cpu_t *cpu)
{
	tlb_flush(cpu, TLB_zero);
	cpu->cpu_ctx.hflags = 0;
	if (cpu->cpu_ctx.regs.cr0 & CR0_PE_MASK) {
		cpu->cpu_ctx.hflags |= ((cpu->cpu_ctx.regs.cs & HFLG_CPL) | HFLG_PE_MODE);
		if (cpu->cpu_ctx.regs.cs_hidden.flags & SEG_HIDDEN_DB) {
			cpu->cpu_ctx.hflags |= HFLG_CS32;
		}
		if (cpu->cpu_ctx.regs.ss_hidden.flags & SEG_HIDDEN_DB) {
			cpu->cpu_ctx.hflags |= HFLG_SS32;
		}
	}
	if (cpu->cpu_ctx.regs.cr0 & CR0_EM_MASK) {
		cpu->cpu_ctx.hflags |= HFLG_CR0_EM;
	}
}

/*
* cpu_set_flags -> sets lib86cpu flags with the current cpu state. Only call this before cpu_run
* cpu: a valid cpu instance
* ret: the status of the operation
*/
lc86_status
cpu_set_flags(cpu_t *cpu, uint32_t flags)
{
	if (flags & ~(CPU_INTEL_SYNTAX | CPU_DBG_PRESENT)) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	cpu->cpu_flags &= ~(CPU_INTEL_SYNTAX | CPU_DBG_PRESENT);
	cpu->cpu_flags |= flags;
	// XXX: eventually, the user should be able to set the instruction formatting
	set_instr_format(cpu);

	return lc86_status::success;
}

// NOTE: this functions will throw a host_exp_t::a20_changed exception when the gate status changes. See the memory API exception NOTE2 for more details.

/*
* cpu_set_a20 -> open or close the a20 gate of the cpu (can throw an exception)
* cpu: a valid cpu instance
* closed: new gate status. If true then addresses are masked with 0xFFFFFFFF (gate closed), otherwise they are masked with 0xFFEFFFFF (gate open)
* should_throw: suppresses the exception when false, otherwise can throw
* ret: nothing
*/
void
cpu_set_a20(cpu_t *cpu, bool closed, bool should_throw)
{
	uint32_t old_a20_mask = cpu->a20_mask;
	cpu->a20_mask = 0xFFFFFFFF ^ (!closed << 20);
	if (old_a20_mask != cpu->a20_mask) {
		tlb_flush(cpu, TLB_zero);
		cpu->cached_regions.clear();
		cpu->cached_regions.push_back(nullptr);
		if (should_throw) {
			throw host_exp_t::a20_changed;
		}
	}
}

/*
* register_log_func -> registers a log function to receive log events from lib86cpu
* logger: the function to call
* ret: nothing
*/
void
register_log_func(logfn_t logger)
{
	if (logger == nullptr) {
		logfn = &discard_log;
		instr_logfn = &discard_instr_log;
	}
	else {
		logfn = logger;
		instr_logfn = &log_instr;
	}
}

/*
* get_last_error -> returns a string representation of the last lib86cpu error
* ret: the error string
*/
std::string
get_last_error()
{
	return last_error;
}

/*
* get_ram_ptr -> returns a pointer to the internally allocated ram buffer
* cpu: a valid cpu instance
* ret: a pointer to the ram buffer
*/
uint8_t *
get_ram_ptr(cpu_t *cpu)
{
	return cpu->cpu_ctx.ram;
}

/*
* get_host_ptr -> returns a host pointer that maps the guest ram/rom at the specified address. This memory might not be contiguous in host memory
* cpu: a valid cpu instance
* addr: a guest virtual address pointing to a ram or rom region
* ret: a host pointer to the specified guest address, or nullptr if the address doesn't map to ram/rom or a guest exception occurs
*/
uint8_t *
get_host_ptr(cpu_t *cpu, addr_t addr)
{
	try {
		addr_t phys_addr = get_read_addr(cpu, addr, 0, 0);
		const memory_region_t<addr_t>* region = as_memory_search_addr(cpu, phys_addr);

		switch (region->type)
		{
		case mem_type::ram:
			return static_cast<uint8_t *>(get_ram_host_ptr(cpu, phys_addr));

		case mem_type::rom:
			return static_cast<uint8_t *>(get_rom_host_ptr(cpu, region, phys_addr));
		}

		set_last_error(lc86_status::invalid_parameter);
		return nullptr;
	}
	catch (host_exp_t type) {
		assert((type == host_exp_t::pf_exp) || (type == host_exp_t::de_exp));
		set_last_error(lc86_status::guest_exp);
		return nullptr;
	}
}

// NOTE1: the maximum number of regions the system can have is 65536 - 1, because their indices are cached in the cached_region_idx vector of subpage_t, which is
// implemented with uint16_t, and there's always a nullptr cached at index zero. Additionally, the number of unmapped regions is variable, and depends of the number
// of merging and splitting events that involve unmapped regions in the address_space object. These are currently not tracked, which is why the memory APIs below
// don't track the number of regions currently added to the system.
// NOTE2: these functions will throw a host_exp_t::region_changed exception when they detect the need to flush the code cache, so only call them last. If you still need
// to do more work after them, then you can catch the exception, do your work in the catch block, and then re-throw the exception. You can suppress the exception by
// passing should_throw=true. This is useful before you have called cpu_run to start the emulation, since at that point no code has been generated yet.

/*
* mem_init_region_ram -> creates a ram region (can throw an exception)
* cpu: a valid cpu instance
* start: the guest physical address where the ram starts
* size: size in bytes of ram
* should_throw: suppresses the exception when false, otherwise can throw
* ret: the status of the operation
*/
lc86_status
mem_init_region_ram(cpu_t *cpu, addr_t start, size_t size, bool should_throw)
{
	if (size == 0) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	std::unique_ptr<memory_region_t<addr_t>> ram(new memory_region_t<addr_t>);
	ram->start = start;
	ram->end = start + size - 1;
	ram->type = mem_type::ram;
	cpu->memory_space_tree->insert(std::move(ram));

	if (tc_should_clear_cache_and_tlb(cpu, start, start + size - 1, should_throw)) {
		throw host_exp_t::region_changed;
	}

	return lc86_status::success;
}

/*
* mem_init_region_io -> creates an mmio or pmio region (can throw an exception for mmio only)
* cpu: a valid cpu instance
* start: where the region starts
* size: size of the region
* io_space: true for pmio, and false for mmio
* handlers: a struct of function pointers to call back when the region is accessed from the guest
* opaque: an arbitrary host pointer which is passed to the registered r/w function for the region
* should_throw: suppresses the exception when false, otherwise can throw
* ret: the status of the operation
*/
lc86_status
mem_init_region_io(cpu_t *cpu, addr_t start, size_t size, bool io_space, io_handlers_t handlers, void *opaque, bool should_throw)
{
	if (size == 0) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	if (io_space) {
		if ((start > 65535) || ((start + size) > 65536)) {
			return set_last_error(lc86_status::invalid_parameter);
		}

		std::unique_ptr<memory_region_t<port_t>> io(new memory_region_t<port_t>);
		io->start = static_cast<port_t>(start);
		io->end = static_cast<port_t>(start) + size - 1;
		io->type = mem_type::pmio;
		io->handlers.fnr8 = handlers.fnr8 ? handlers.fnr8 : default_pmio_read_handler8;
		io->handlers.fnr16 = handlers.fnr16 ? handlers.fnr16 : default_pmio_read_handler16;
		io->handlers.fnr32 = handlers.fnr32 ? handlers.fnr32 : default_pmio_read_handler32;
		io->handlers.fnw8 = handlers.fnw8 ? handlers.fnw8 : default_pmio_write_handler8;
		io->handlers.fnw16 = handlers.fnw16 ? handlers.fnw16 : default_pmio_write_handler16;
		io->handlers.fnw32 = handlers.fnw32 ? handlers.fnw32 : default_pmio_write_handler32;
		if (opaque) {
			io->opaque = opaque;
		}

		cpu->io_space_tree->insert(std::move(io));
	}
	else {
		std::unique_ptr<memory_region_t<addr_t>> mmio(new memory_region_t<addr_t>);
		mmio->start = start;
		mmio->end = start + size - 1;
		mmio->type = mem_type::mmio;
		mmio->handlers.fnr8 = handlers.fnr8 ? handlers.fnr8 : default_mmio_read_handler8;
		mmio->handlers.fnr16 = handlers.fnr16 ? handlers.fnr16 : default_mmio_read_handler16;
		mmio->handlers.fnr32 = handlers.fnr32 ? handlers.fnr32 : default_mmio_read_handler32;
		mmio->handlers.fnr64 = handlers.fnr64 ? handlers.fnr64 : default_mmio_read_handler64;
		mmio->handlers.fnw8 = handlers.fnw8 ? handlers.fnw8 : default_mmio_write_handler8;
		mmio->handlers.fnw16 = handlers.fnw16 ? handlers.fnw16 : default_mmio_write_handler16;
		mmio->handlers.fnw32 = handlers.fnw32 ? handlers.fnw32 : default_mmio_write_handler32;
		mmio->handlers.fnw64 = handlers.fnw64 ? handlers.fnw64 : default_mmio_write_handler64;
		if (opaque) {
			mmio->opaque = opaque;
		}
		cpu->memory_space_tree->insert(std::move(mmio));

		if (tc_should_clear_cache_and_tlb(cpu, start, start + size - 1, should_throw)) {
			throw host_exp_t::region_changed;
		}
	}

	return lc86_status::success;
}

/*
* mem_init_region_alias -> creates a region that points to another region (which must not be pmio; can throw an exception)
* cpu: a valid cpu instance
* alias_start: the guest physical address where the alias starts
* ori_start: the guest physical address where the original region starts
* ori_size: size in bytes of alias
* should_throw: suppresses the exception when false, otherwise can throw
* ret: the status of the operation
*/
lc86_status
mem_init_region_alias(cpu_t *cpu, addr_t alias_start, addr_t ori_start, size_t ori_size, bool should_throw)
{
	if (ori_size == 0) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	auto aliased_region = const_cast<memory_region_t<addr_t> *>(cpu->memory_space_tree->search(ori_start));
	if ((aliased_region->start <= ori_start) && (aliased_region->end >= (ori_start + ori_size - 1)) && (aliased_region->type != mem_type::unmapped)) {
		std::unique_ptr<memory_region_t<addr_t>> alias(new memory_region_t<addr_t>);
		alias->start = alias_start;
		alias->end = alias_start + ori_size - 1;
		alias->alias_offset = ori_start - aliased_region->start;
		alias->type = mem_type::alias;
		alias->aliased_region = aliased_region;
		cpu->memory_space_tree->insert(std::move(alias));

		if (tc_should_clear_cache_and_tlb(cpu, alias_start, alias_start + ori_size - 1, should_throw)) {
			throw host_exp_t::region_changed;
		}

		return lc86_status::success;
	}

	return set_last_error(lc86_status::invalid_parameter);
}

/*
* mem_init_region_rom -> creates a rom region (can throw an exception)
* cpu: a valid cpu instance
* start: the guest physical address where the rom starts
* size: size in bytes of rom
* buffer: a pointer to a client-allocated buffer that holds the rom the region refers to
* should_throw: suppresses the exception when false, otherwise can throw
* ret: the status of the operation
*/
lc86_status
mem_init_region_rom(cpu_t *cpu, addr_t start, size_t size, uint8_t *buffer, bool should_throw)
{
	if ((size == 0) || !(buffer)) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	std::unique_ptr<memory_region_t<addr_t>> rom(new memory_region_t<addr_t>);
	rom->start = start;
	rom->end = start + size - 1;
	rom->type = mem_type::rom;
	rom->rom_idx = cpu->vec_rom.size() - 1;
	cpu->memory_space_tree->insert(std::move(rom));
	cpu->vec_rom.push_back(buffer);

	if (tc_should_clear_cache_and_tlb(cpu, start, start + size - 1, should_throw)) {
		throw host_exp_t::region_changed;
	}

	return lc86_status::success;
}

/*
* mem_destroy_region -> marks a range of addresses as unmapped (can throw an exception for any region but pmio)
* cpu: a valid cpu instance
* start: the guest physical address where to start the unmapping
* size: size in bytes to unmap
* io_space: true for pmio, false for mmio and ignored for the other regions
* should_throw: suppresses the exception when false, otherwise can throw
* ret: always success
*/
lc86_status
mem_destroy_region(cpu_t *cpu, addr_t start, size_t size, bool io_space, bool should_throw)
{
	if (io_space) {
		port_t start_io = static_cast<port_t>(start);
		port_t end_io = start + size - 1;
		cpu->io_space_tree->erase(start_io, end_io);
	}
	else {
		cpu->memory_space_tree->erase(start, start + size - 1);
		if (tc_should_clear_cache_and_tlb(cpu, start, start + size - 1, should_throw)) {
			throw host_exp_t::region_changed;
		}
	}
	return lc86_status::success;
}

/*
* mem_read_block -> reads a block of memory from ram/rom
* cpu: a valid cpu instance
* addr: the guest virtual address to read from
* size: number of bytes to read
* out: pointer where the read contents are stored to
* actual_size: number of bytes actually read
* ret: the status of the operation
*/
lc86_status
mem_read_block(cpu_t *cpu, addr_t addr, size_t size, uint8_t *out, size_t *actual_size)
{
	size_t vec_offset = 0;
	size_t page_offset = addr & PAGE_MASK;
	size_t size_left = size;

	try {
		while (size_left > 0) {
			size_t bytes_to_read = std::min(PAGE_SIZE - page_offset, size_left);
			addr_t phys_addr = get_read_addr(cpu, addr, 0, 0);

			const memory_region_t<addr_t> *region = as_memory_search_addr(cpu, phys_addr);
			retry:
			if ((phys_addr >= region->start) && ((phys_addr + bytes_to_read - 1) <= region->end)) {
				switch (region->type)
				{
				case mem_type::ram:
					std::memcpy(out + vec_offset, get_ram_host_ptr(cpu, phys_addr), bytes_to_read);
					break;

				case mem_type::rom:
					std::memcpy(out + vec_offset, get_rom_host_ptr(cpu, region, phys_addr), bytes_to_read);
					break;

				case mem_type::alias: {
					const memory_region_t<addr_t> *alias = region;
					AS_RESOLVE_ALIAS();
					phys_addr = region->start + alias_offset + (phys_addr - alias->start);
					goto retry;
				}
				break;

				case mem_type::mmio:
				case mem_type::unmapped:
				default:
					if (actual_size) {
						*actual_size = vec_offset;
					}
					return set_last_error(lc86_status::internal_error);
				}
			}
			else {
				if (actual_size) {
					*actual_size = vec_offset;
				}
				return set_last_error(lc86_status::internal_error);
			}

			page_offset = 0;
			vec_offset += bytes_to_read;
			size_left -= bytes_to_read;
			addr += bytes_to_read;
		}

		if (actual_size) {
			*actual_size = vec_offset;
		}
		return lc86_status::success;
	}
	catch (host_exp_t type) {
		assert((type == host_exp_t::pf_exp) || (type == host_exp_t::de_exp));
		if (actual_size) {
			*actual_size = vec_offset;
		}
		return set_last_error(lc86_status::guest_exp);
	}
}

template<bool fill>
lc86_status mem_write_handler(cpu_t *cpu, addr_t addr, size_t size, const void *buffer, int val, size_t *actual_size)
{
	size_t size_tot = 0;
	size_t page_offset = addr & PAGE_MASK;
	size_t size_left = size;

	try {
		while (size_left > 0) {
			uint8_t is_code;
			size_t bytes_to_write = std::min(PAGE_SIZE - page_offset, size_left);
			addr_t phys_addr = get_write_addr(cpu, addr, 0, 0, &is_code);
			if (is_code) {
				tc_invalidate(&cpu->cpu_ctx, phys_addr, bytes_to_write, cpu->cpu_ctx.regs.eip);
			}

			const memory_region_t<addr_t> *region = as_memory_search_addr(cpu, phys_addr);
			retry:
			if ((phys_addr >= region->start) && ((phys_addr + bytes_to_write - 1) <= region->end)) {
				switch (region->type)
				{
				case mem_type::ram:
					if constexpr (fill) {
						std::memset(get_ram_host_ptr(cpu, phys_addr), val, bytes_to_write);
					}
					else {
						std::memcpy(get_ram_host_ptr(cpu, phys_addr), buffer, bytes_to_write);
					}
					break;

				case mem_type::rom:
					break;

				case mem_type::alias: {
					const memory_region_t<addr_t> *alias = region;
					AS_RESOLVE_ALIAS();
					phys_addr = region->start + alias_offset + (phys_addr - alias->start);
					goto retry;
				}
				break;

				case mem_type::mmio:
				case mem_type::unmapped:
				default:
					if (actual_size) {
						*actual_size = size_tot;
					}
					return set_last_error(lc86_status::internal_error);
				}
			}
			else {
				if (actual_size) {
					*actual_size = size_tot;
				}
				return set_last_error(lc86_status::internal_error);
			}

			page_offset = 0;
			buffer = static_cast<const uint8_t *>(buffer) + bytes_to_write;
			size_tot += bytes_to_write;
			size_left -= bytes_to_write;
			addr += bytes_to_write;
		}

		if (actual_size) {
			*actual_size = size_tot;
		}
		return lc86_status::success;
	}
	catch (host_exp_t type) {
		assert((type == host_exp_t::pf_exp) || (type == host_exp_t::de_exp));
		if (actual_size) {
			*actual_size = size_tot;
		}
		return set_last_error(lc86_status::guest_exp);
	}
}

/*
* mem_write_block -> writes a block of memory to ram/rom
* cpu: a valid cpu instance
* addr: the guest virtual address to write to
* size: number of bytes to write
* buffer: pointer to a buffer that holds the bytes to write
* actual_size: number of bytes actually written
* ret: the status of the operation
*/
lc86_status
mem_write_block(cpu_t *cpu, addr_t addr, size_t size, const void *buffer, size_t *actual_size)
{
	return mem_write_handler<false>(cpu, addr, size, buffer, 0, actual_size);
}

/*
* mem_fill_block -> fills ram/rom with a value
* cpu: a valid cpu instance
* addr: the guest virtual address to write to
* size: number of bytes to write
* val: the value to write
* actual_size: number of bytes actually written
* ret: the status of the operation
*/
lc86_status
mem_fill_block(cpu_t *cpu, addr_t addr, size_t size, int val, size_t *actual_size)
{
	return mem_write_handler<true>(cpu, addr, size, nullptr, val, actual_size);
}

/*
* io_read_8/16/32 -> reads 8/16/32 bits from a pmio port
* cpu: a valid cpu instance
* port: the port to read from
* ret: the read value
*/
uint8_t
io_read_8(cpu_t *cpu, port_t port)
{
	return io_read<uint8_t>(cpu, port);
}

uint16_t
io_read_16(cpu_t *cpu, port_t port)
{
	return io_read<uint16_t>(cpu, port);
}

uint32_t
io_read_32(cpu_t *cpu, port_t port)
{
	return io_read<uint32_t>(cpu, port);
}

/*
* io_write_8/16/32 -> writes 8/16/32 bits to a pmio port
* cpu: a valid cpu instance
* port: the port to write to
* value: the value to write
* ret: nothing
*/
void
io_write_8(cpu_t *cpu, port_t port, uint8_t value)
{
	io_write<uint8_t>(cpu, port, value);
}

void
io_write_16(cpu_t *cpu, port_t port, uint16_t value)
{
	io_write<uint16_t>(cpu, port, value);
}

void
io_write_32(cpu_t *cpu, port_t port, uint32_t value)
{
	io_write<uint32_t>(cpu, port, value);
}

/*
* tlb_invalidate -> flushes tlb entries in the specified range
* cpu: a valid cpu instance
* addr_start: a guest virtual address where the flush starts
* addr_end: a guest virtual address where the flush end
* ret: nothing
*/
void
tlb_invalidate(cpu_t *cpu, addr_t addr_start, addr_t addr_end)
{
	for (uint32_t tlb_idx_s = addr_start >> PAGE_SHIFT, tlb_idx_e = addr_end >> PAGE_SHIFT; tlb_idx_s <= tlb_idx_e; tlb_idx_s++) {
		cpu->cpu_ctx.tlb[tlb_idx_s] = (cpu->cpu_ctx.tlb[tlb_idx_s] & ~TLB_VALID);
	}
}

/*
* hook_add -> adds a hook to intercept a guest function and redirect it to a host function
* cpu: a valid cpu instance
* addr: the virtual address of the first instruction of the guest function to intercept
* hook_addr: the address of the host function to call
* ret: the status of the operation
*/
lc86_status
hook_add(cpu_t *cpu, addr_t addr, void *hook_addr)
{
	// adds a host function that is called in place of the original guest function when pc reaches addr. The client is responsible for fetching the guest arguments
	// (if they need them) and fixing the guest stack/registers before the host function returns
	// NOTE: this hooks will only work when addr points to the first instruction of the hooked function (because we only check for hooks at the start
	// of the translation of a new code block)

	try {
		uint8_t is_code;
		volatile addr_t phys_addr = get_write_addr(cpu, addr, 2, cpu->cpu_ctx.regs.eip, &is_code);
		tc_invalidate(&cpu->cpu_ctx, addr, 1, cpu->cpu_ctx.regs.eip);
	}
	catch (host_exp_t type) {
		return set_last_error(lc86_status::guest_exp);
	}

	cpu->hook_map.insert_or_assign(addr, hook_addr);

	return lc86_status::success;
}

/*
* hook_remove -> removes a hook
* cpu: a valid cpu instance
* addr: the virtual address of the first instruction of the guest function to intercept
* ret: the status of the operation
*/
lc86_status
hook_remove(cpu_t *cpu, addr_t addr)
{
	const auto it = cpu->hook_map.find(addr);
	if (it == cpu->hook_map.end()) {
		return set_last_error(lc86_status::not_found);
	}

	try {
		uint8_t is_code;
		volatile addr_t phys_addr = get_write_addr(cpu, addr, 2, cpu->cpu_ctx.regs.eip, &is_code);
		cpu->hook_map.erase(it);
		tc_invalidate<true>(&cpu->cpu_ctx, addr);
	}
	catch (host_exp_t type) {
		return set_last_error(lc86_status::guest_exp);
	}

	return lc86_status::success;
}

/*
* trampoline_call -> calls the original intercepted guest function
* cpu: a valid cpu instance
* ret_eip: the virtual address to which the original guest function returns to after if finishes execution
* ret: nothing
*/
void
trampoline_call(cpu_t *cpu, const uint32_t ret_eip)
{
	// a trampoline calls the original guest function that was hooked, and it's only supposed to get called from the host function that hooed it.
	// This assumes that the guest state (regs and stack) are in the same state that the guest has set them when it called the hook, so that we can call
	// the trampoline without having to set this state up ourselves. The argument ret_eip is the eip to which the trampoline returns to after if finishes
	// executing and returns, and it tipically corresponds to the eip that the call instruction pushed on the stack.

	cpu_exec_trampoline(cpu, ret_eip);
}

/*
* get_regs_ptr -> returns a pointer to the cpu registers (eip and eflags won't be accurate)
* cpu: a valid cpu instance
* ret: a pointer to the registers
*/
regs_t *
get_regs_ptr(cpu_t *cpu)
{
	// Reading the eip at runtime will not yield the correct result because we only update it at the end of a tc
	return &cpu->cpu_ctx.regs;
}

/*
* read_eflags -> reads the current value of eflags
* cpu: a valid cpu instance
* ret: eflags
*/
uint32_t
read_eflags(cpu_t *cpu)
{
	uint32_t arth_flags = (((cpu->cpu_ctx.lazy_eflags.auxbits & 0x80000000) >> 31) | // cf
		(((cpu->cpu_ctx.lazy_eflags.parity[(cpu->cpu_ctx.lazy_eflags.result ^ (cpu->cpu_ctx.lazy_eflags.auxbits >> 8)) & 0xFF]) ^ 1) << 2) | // pf
		((cpu->cpu_ctx.lazy_eflags.auxbits & 8) << 1) | // af
		((cpu->cpu_ctx.lazy_eflags.result ? 0 : 1) << 6) | // zf
		(((cpu->cpu_ctx.lazy_eflags.result >> 31) ^ (cpu->cpu_ctx.lazy_eflags.auxbits & 1)) << 7) | // sf
		(((cpu->cpu_ctx.lazy_eflags.auxbits ^ (cpu->cpu_ctx.lazy_eflags.auxbits << 1)) & 0x80000000) >> 20) // of
		);

	return cpu->cpu_ctx.regs.eflags | arth_flags;
}

/*
* write_eflags -> writes a new value to eflags
* cpu: a valid cpu instance
* value: the value to write
* reg32: true to write to eflags, false to write to flags
* ret: nothing
*/
void
write_eflags(cpu_t *cpu, uint32_t value, bool reg32)
{
	uint32_t new_res, new_aux;
	new_aux = (((value & 1) << 31) | // cf
		((((value & 1) << 11) ^ (value & 0x800)) << 19) | // of
		((value & 0x10) >> 1) | // af
		((((value & 4) >> 2) ^ 1) << 8) | // pf
		((value & 0x80) >> 7) // sf
		);
	new_res = (((value & 0x40) << 2) ^ 0x100); // zf

	// mask out reserved bits and arithmetic flags
	if (reg32) {
		(cpu->cpu_ctx.regs.eflags &= 2) |= (value & 0x3F7700);
	}
	else {
		(cpu->cpu_ctx.regs.eflags &= 0xFFFF0002) |= (value & 0x7700);
	}
	cpu->cpu_ctx.lazy_eflags.result = new_res;
	cpu->cpu_ctx.lazy_eflags.auxbits = new_aux;
}
