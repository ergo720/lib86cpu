/*
 * This is the interface to the client.
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#include "llvm-c/Core.h"
#include "jit.h"
#include "internal.h"
#include "memory.h"
#include "clock.h"
#include <fstream>


static void
default_mmio_write_handler(addr_t addr, size_t size, const uint64_t value, void *opaque)
{
	LOG(log_level::warn, "Unhandled MMIO write at address %#010x with size %d", addr, size);
}

static uint64_t
default_mmio_read_handler(addr_t addr, size_t size, void *opaque)
{
	LOG(log_level::warn, "Unhandled MMIO read at address %#010x with size %d", addr, size);
	return std::numeric_limits<uint64_t>::max();
}

static void
default_pmio_write_handler(addr_t addr, size_t size, const uint64_t value, void *opaque)
{
	LOG(log_level::warn, "Unhandled PMIO write at port %#06x with size %d", addr, size);
}

static uint64_t
default_pmio_read_handler(addr_t addr, size_t size, void *opaque)
{
	LOG(log_level::warn, "Unhandled PMIO read at port %#06x with size %d", addr, size);
	return std::numeric_limits<uint64_t>::max();
}

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

	if ((ramsize % PAGE_SIZE) != 0) {
		cpu_free(cpu);
		return set_last_error(lc86_status::invalid_parameter);
	}

	cpu->cpu_ctx.ram = new uint8_t[ramsize];
	if (cpu->cpu_ctx.ram == nullptr) {
		cpu_free(cpu);
		return set_last_error(lc86_status::no_memory);
	}

	cpu_init(cpu);
	tsc_init(cpu);
	// XXX: eventually, the user should be able to set the instruction formatting
	set_instr_format(cpu);
	cpu->dbg_name = debuggee ? debuggee : "";

	std::unique_ptr<memory_region_t<addr_t>> mem_region(new memory_region_t<addr_t>);
	cpu->memory_space_tree = interval_tree<addr_t, std::unique_ptr<memory_region_t<addr_t>>>::create();
	mem_region->start = 0;
	mem_region->end = UINT32_MAX;
	cpu->memory_space_tree->insert(mem_region->start, mem_region->end, std::move(mem_region));
	std::unique_ptr<memory_region_t<port_t>> io_region(new memory_region_t<port_t>);
	cpu->io_space_tree = interval_tree<port_t, std::unique_ptr<memory_region_t<port_t>>>::create();
	io_region->start = 0;
	io_region->end = UINT16_MAX;
	io_region->read_handler = default_pmio_read_handler;
	io_region->write_handler = default_pmio_write_handler;
	cpu->io_space_tree->insert(io_region->start, io_region->end, std::move(io_region));

	try {
		cpu->jit = std::move(lc86_jit::create(cpu));
	}
	catch (lc86_exp_abort &exp) {
		cpu_free(cpu);
		last_error = exp.what();
		return exp.get_code();
	}

	// check if FP80 is supported by this architecture
	std::string data_layout = cpu->dl->getStringRepresentation();
	if (data_layout.find("f80") != std::string::npos) {
		LOG(log_level::info, "FP80 supported.");
		cpu->cpu_flags |= CPU_FLAG_FP80;
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
	if (cpu->dl) {
		delete cpu->dl;
	}
	if (cpu->cpu_ctx.ram) {
		delete[] cpu->cpu_ctx.ram;
	}

	for (auto &bucket : cpu->code_cache) {
		bucket.clear();
	}

	LLVMShutdown();

	delete cpu;

	// NOTE: only call this after delete cpu;. This, because destroying the cpu destroys the jit, which in turn cause llvm to call ~SectionMemoryManager,
	// That destructor internally calls releaseMappedMemory, which will then attempt to release the already deleted memory of the JITed code
	g_mapper.destroy_all_blocks();
}

/*
* cpu_run -> starts the emulation. Only returns when there is an error in lib86cpu
* cpu: a valid cpu instance
* ret: nothing
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
	if (flags & ~(CPU_INTEL_SYNTAX | CPU_CODEGEN_OPTIMIZE | CPU_PRINT_IR | CPU_PRINT_IR_OPTIMIZED | CPU_DBG_PRESENT)) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	if ((flags & CPU_PRINT_IR_OPTIMIZED) && ((flags & CPU_CODEGEN_OPTIMIZE) == 0)) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	cpu->cpu_flags &= ~(CPU_INTEL_SYNTAX | CPU_CODEGEN_OPTIMIZE | CPU_PRINT_IR | CPU_PRINT_IR_OPTIMIZED | CPU_DBG_PRESENT);
	cpu->cpu_flags |= flags;
	// XXX: eventually, the user should be able to set the instruction formatting
	set_instr_format(cpu);

	return lc86_status::success;
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
* get_ram_ptr -> returns a pointer to the internally allocated ram buffer. Do not modify its contents directly, but instead use the memory api
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
		memory_region_t<addr_t>* region = as_memory_search_addr<uint8_t>(cpu, phys_addr);

		switch (region->type)
		{
		case mem_type::ram:
			return static_cast<uint8_t *>(get_ram_host_ptr(cpu, region, phys_addr));

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

/*
* mem_init_region_ram -> creates a ram region. Only call this before cpu_run
* cpu: a valid cpu instance
* start: the guest physical address where the ram starts. Must be 4k aligned
* size: size in bytes of ram. Must be a multiple of 4096
* priority: the priority of the region. Overlapping higher prority regions will take precedence over regions with lower priority
* ret: the status of the operation
*/
lc86_status
mem_init_region_ram(cpu_t *cpu, addr_t start, size_t size, int priority)
{
	std::unique_ptr<memory_region_t<addr_t>> ram(new memory_region_t<addr_t>);

	if (size == 0) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	if ((start % PAGE_SIZE) != 0 || ((size % PAGE_SIZE) != 0)) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	addr_t end = start + size - 1;
	cpu->memory_space_tree->search(start, end, cpu->memory_out);

	for (auto &region : cpu->memory_out) {
		if (region.get()->priority == priority) {
			return set_last_error(lc86_status::invalid_parameter);
		}
	}

	ram->start = start;
	ram->end = end;
	ram->type = mem_type::ram;
	ram->priority = priority;

	if (cpu->memory_space_tree->insert(start, end, std::move(ram))) {
		return lc86_status::success;
	}
	else {
		return set_last_error(lc86_status::invalid_parameter);
	}
}

/*
* mem_init_region_io -> creates an mmio or pmio region. Only call this before cpu_run
* cpu: a valid cpu instance
* start: where the region starts. A 4K aligned guest physical address for mmio, and a 4 byte aligned port for pmio
* size: size of the region. For mmio, it must be a multiple of 4096, while for pmio, it must be a multiple of 4
* io_space: true for pmio, and false for mmio
* read_func: the function to call when this region is read from the guest
* write_func: the function to call when this region is written to from the guest
* opaque: an arbitrary host pointer which is passed to the registered r/w function for the region
* priority: the priority of the region. Overlapping higher prority regions will take precedence over regions with lower priority
* ret: the status of the operation
*/
lc86_status
mem_init_region_io(cpu_t *cpu, addr_t start, size_t size, bool io_space, fp_read read_func, fp_write write_func, void *opaque, int priority)
{
	if (size == 0) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	if (io_space) {
		std::unique_ptr<memory_region_t<port_t>> io(new memory_region_t<port_t>);

		if (cpu->num_io_regions == ((IO_MAX_PORT / IO_SIZE) - 1)) {
			return set_last_error(lc86_status::too_many);
		}

		if (start > (IO_MAX_PORT - 1) || (start + size) > IO_MAX_PORT) {
			return set_last_error(lc86_status::invalid_parameter);
		}

		if ((start % IO_SIZE) != 0 || ((size % IO_SIZE) != 0)) {
			return set_last_error(lc86_status::invalid_parameter);
		}

		port_t start_io = static_cast<port_t>(start);
		port_t end = start_io + size - 1;
		cpu->io_space_tree->search(start_io, end, cpu->io_out);

		for (auto &region : cpu->io_out) {
			if (region.get()->priority == priority) {
				return set_last_error(lc86_status::invalid_parameter);
			}
		}

		io->start = start_io;
		io->end = end;
		io->type = mem_type::pmio;
		io->priority = priority;
		if (read_func) {
			io->read_handler = read_func;
		}
		else {
			io->read_handler = default_pmio_read_handler;
		}
		if (write_func) {
			io->write_handler = write_func;
		}
		else {
			io->write_handler = default_pmio_write_handler;
		}
		if (opaque) {
			io->opaque = opaque;
		}

		if (cpu->io_space_tree->insert(start_io, end, std::move(io))) {
			cpu->num_io_regions++;
			return lc86_status::success;
		}
	}
	else {
		std::unique_ptr<memory_region_t<addr_t>> mmio(new memory_region_t<addr_t>);

		if ((start % PAGE_SIZE) != 0 || ((size % PAGE_SIZE) != 0)) {
			return set_last_error(lc86_status::invalid_parameter);
		}

		if (cpu->num_mmio_regions == MMIO_MAX_NUM) {
			return set_last_error(lc86_status::too_many);
		}

		addr_t end = start + size - 1;
		cpu->memory_space_tree->search(start, end, cpu->memory_out);

		for (auto &region : cpu->memory_out) {
			if (region.get()->priority == priority) {
				return set_last_error(lc86_status::invalid_parameter);
			}
		}

		mmio->start = start;
		mmio->end = end;
		mmio->type = mem_type::mmio;
		mmio->priority = priority;
		if (read_func) {
			mmio->read_handler = read_func;
		}
		else {
			mmio->read_handler = default_mmio_read_handler;
		}
		if (write_func) {
			mmio->write_handler = write_func;
		}
		else {
			mmio->write_handler = default_mmio_write_handler;
		}
		if (opaque) {
			mmio->opaque = opaque;
		}

		if (cpu->memory_space_tree->insert(start, end, std::move(mmio))) {
			cpu->num_mmio_regions++;
			return lc86_status::success;
		}
	}

	return set_last_error(lc86_status::invalid_parameter);
}

/*
* mem_init_region_alias -> creates a region that points to another region (which must not be pmio). Only call this before cpu_run
* cpu: a valid cpu instance
* alias_start: the guest physical address where the alias starts. Must be 4k aligned
* ori_start: the guest physical address where the original region starts. Must be 4k aligned
* ori_size: size in bytes of alias. Must be a multiple of 4096
* priority: the priority of the region. Overlapping higher prority regions will take precedence over regions with lower priority
* ret: the status of the operation
*/
lc86_status
mem_init_region_alias(cpu_t *cpu, addr_t alias_start, addr_t ori_start, size_t ori_size, int priority)
{
	std::unique_ptr<memory_region_t<addr_t>> alias(new memory_region_t<addr_t>);

	if (ori_size == 0) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	if ((alias_start % PAGE_SIZE) != 0 || (ori_start % PAGE_SIZE) != 0 || ((ori_size % PAGE_SIZE) != 0)) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	memory_region_t<addr_t> *aliased_region = nullptr;
	addr_t end = ori_start + ori_size - 1;
	cpu->memory_space_tree->search(ori_start, end, cpu->memory_out);

	for (auto &region : cpu->memory_out) {
		if ((region.get()->start <= ori_start) && (region.get()->end >= end)) {
			if (region.get()->type != mem_type::unmapped) {
				aliased_region = region.get().get();
				break;
			}
		}
	}

	if (!aliased_region) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	end = alias_start + ori_size - 1;
	cpu->memory_space_tree->search(alias_start, end, cpu->memory_out);

	for (auto &region : cpu->memory_out) {
		if (region.get()->priority == priority) {
			return set_last_error(lc86_status::invalid_parameter);
		}
	}

	alias->start = alias_start;
	alias->end = end;
	alias->alias_offset = ori_start - aliased_region->start;
	alias->type = mem_type::alias;
	alias->priority = priority;
	alias->aliased_region = aliased_region;

	if (cpu->memory_space_tree->insert(alias_start, end, std::move(alias))) {
		return lc86_status::success;
	}
	else {
		return set_last_error(lc86_status::invalid_parameter);
	}
}

/*
* mem_init_region_rom -> creates a rom region. Only call this before cpu_run
* cpu: a valid cpu instance
* start: the guest physical address where the rom starts. Must be 4k aligned
* size: size in bytes of rom. Must be a multiple of 4096
* priority: the priority of the region. Overlapping higher prority regions will take precedence over regions with lower priority
* buffer: a buffer that holds the rom that the region refers to
* ret: the status of the operation
*/
lc86_status
mem_init_region_rom(cpu_t *cpu, addr_t start, size_t size, int priority, std::unique_ptr<uint8_t[]> buffer)
{
	std::unique_ptr<memory_region_t<addr_t>> rom(new memory_region_t<addr_t>);

	if (!buffer) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	if ((start % PAGE_SIZE) != 0 || ((size % PAGE_SIZE) != 0)) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	if (cpu->num_rom_regions == ROM_MAX_NUM) {
		return set_last_error(lc86_status::too_many);
	}

	addr_t end = start + size - 1;
	cpu->memory_space_tree->search(start, end, cpu->memory_out);

	for (auto &region : cpu->memory_out) {
		if (region.get()->priority == priority) {
			return set_last_error(lc86_status::invalid_parameter);
		}
	}

	rom->start = start;
	rom->end = end;
	rom->type = mem_type::rom;
	rom->priority = priority;
	rom->rom_idx = cpu->vec_rom.size();

	if (cpu->memory_space_tree->insert(start, end, std::move(rom))) {
		cpu->vec_rom.push_back(std::move(buffer));
		cpu->num_rom_regions++;
		return lc86_status::success;
	}
	else {
		return set_last_error(lc86_status::invalid_parameter);
	}
}

/*
* mem_destroy_region -> destroys a region. At the moemnt, this is only safe for pmio, mmio, alias and rom
* cpu: a valid cpu instance
* start: the guest physical address where the region starts
* size: size in bytes of region
* io_space: true for pmio, and false for mmio
* ret: the status of the operation
*/
lc86_status
mem_destroy_region(cpu_t *cpu, addr_t start, size_t size, bool io_space)
{
	if (io_space) {
		port_t start_io = static_cast<port_t>(start);
		port_t end_io = start + size - 1;
		cpu->io_space_tree->search(start_io, end_io, cpu->io_out);
		const auto region = cpu->io_out.begin()->get().get();
		if ((region->type == mem_type::pmio) && (region->start == start_io) && (region->end == end_io)) {
			// if the above conditions are satisfied, then the erase below is going to succeed, so we can flush the iotlb and avoid needless flushes
			iotlb_flush(cpu, region);
			[[maybe_unused]] bool deleted = cpu->io_space_tree->erase(start_io, end_io);
			assert(deleted);
			cpu->num_io_regions--;
			return lc86_status::success;
		}

		return set_last_error(lc86_status::invalid_parameter);
	}
	else {
		addr_t end = start + size - 1;
		cpu->memory_space_tree->search(start, end, cpu->memory_out);
		auto region = cpu->memory_out.begin()->get().get();

		if (region->type == mem_type::alias) {
			AS_RESOLVE_ALIAS();
		}

		if (region->type == mem_type::rom) {
			if ((region->start == start) && (region->end == end)) {
				// if the above conditions are satisfied, then the erase below is going to succeed, so we can flush the tlb and avoid needless flushes
				// we must also flush the code cache because code can exist in a rom region
				rom_flush_cached(cpu, region);
				cpu->vec_rom.erase(cpu->vec_rom.begin() + region->rom_idx);
				tc_cache_clear(cpu);
				[[maybe_unused]] bool deleted = cpu->memory_space_tree->erase(start, end);
				assert(deleted);
				cpu->num_rom_regions--;
				return lc86_status::success;
			}
			else {
				return set_last_error(lc86_status::invalid_parameter);
			}
		}
		else if (region->type == mem_type::mmio) {
			if ((region->start == start) && (region->end == end)) {
				// if the above conditions are satisfied, then the erase below is going to succeed, so we can flush the tlb and avoid needless flushes
				mmio_flush_cached(cpu, region);
				[[maybe_unused]] bool deleted = cpu->memory_space_tree->erase(start, end);
				assert(deleted);
				cpu->num_mmio_regions--;
				return lc86_status::success;
			}
			else {
				return set_last_error(lc86_status::invalid_parameter);
			}
		}
		else if (cpu->memory_space_tree->erase(start, end)) {
			return lc86_status::success;
		}
		else {
			return set_last_error(lc86_status::invalid_parameter);
		}
	}
}

/*
* mem_read_block -> reads a block of memory from ram/rom. Only call this from an mmio/pmio/hook callback
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

			memory_region_t<addr_t> *region = as_memory_search_addr<uint8_t>(cpu, phys_addr);
			retry:
			if ((phys_addr >= region->start) && ((phys_addr + bytes_to_read - 1) <= region->end)) {
				switch (region->type)
				{
				case mem_type::ram:
					std::memcpy(out + vec_offset, get_ram_host_ptr(cpu, region, phys_addr), bytes_to_read);
					break;

				case mem_type::rom:
					std::memcpy(out + vec_offset, get_rom_host_ptr(cpu, region, phys_addr), bytes_to_read);
					break;

				case mem_type::alias: {
					memory_region_t<addr_t> *alias = region;
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

			memory_region_t<addr_t> *region = as_memory_search_addr<uint8_t>(cpu, phys_addr);
			retry:
			if ((phys_addr >= region->start) && ((phys_addr + bytes_to_write - 1) <= region->end)) {
				switch (region->type)
				{
				case mem_type::ram:
					if constexpr (fill) {
						std::memset(get_ram_host_ptr(cpu, region, phys_addr), val, bytes_to_write);
					}
					else {
						std::memcpy(get_ram_host_ptr(cpu, region, phys_addr), buffer, bytes_to_write);
					}
					break;

				case mem_type::rom:
					break;

				case mem_type::alias: {
					memory_region_t<addr_t> *alias = region;
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
* mem_write_block -> writes a block of memory to ram/rom. Only call this from a hook
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
* mem_fill_block -> fills ram/rom with a value. Only call this from an mmio/pmio/hook callback
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
* io_read_8/16/32 -> reads 8/16/32 bits from a pmio port. Only call this from an mmio/pmio/hook callback
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
* io_write_8/16/32 -> writes 8/16/32 bits to a pmio port. Only call this from an mmio/pmio/hook callback
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
* tlb_invalidate -> flushes tlb entries in the specified range. Only call this from an mmio/pmio/hook callback
* cpu: a valid cpu instance
* addr_start: a guest virtual address where the flush starts
* addr_end: a guest virtual address where the flush end
* ret: nothing
*/
void
tlb_invalidate(cpu_t *cpu, addr_t addr_start, addr_t addr_end)
{
	for (uint32_t tlb_idx_s = addr_start >> PAGE_SHIFT, tlb_idx_e = addr_end >> PAGE_SHIFT; tlb_idx_s <= tlb_idx_e; tlb_idx_s++) {
		cpu->cpu_ctx.tlb[tlb_idx_s] = (cpu->cpu_ctx.tlb[tlb_idx_s] & (TLB_RAM | TLB_CODE));
	}
}

/*
* hook_add -> adds a hook to intercept a guest function and redirect it to a host function. Only call this from a hook
* cpu: a valid cpu instance
* addr: the virtual address of the first instruction of the guest function to intercept
* obj: an object that holds additional data on the hook
* ret: the status of the operation
*/
lc86_status
hook_add(cpu_t *cpu, addr_t addr, std::unique_ptr<hook> obj)
{
	// adds a host function that is called in place of the original guest function when pc reaches addr. The client is responsible for fetching the guest arguments
	// (if they need them) and fixing the guest stack/register before the host function returns
	// NOTE: this hooks will only work when addr points to the first instruction of the hooked function (because we only check for hooks at the start
	// of the translation of a new code block)

	if (cpu->hook_map.contains(addr)) {
		return set_last_error(lc86_status::already_exist);
	}

	if (obj.get() == nullptr) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	if (obj->args_t.size() != obj->args_val.size()) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	cpu->hook_map.emplace(addr, std::move(obj));

	try {
		uint8_t is_code;
		volatile addr_t phys_addr = get_write_addr(cpu, addr, 2, cpu->cpu_ctx.regs.eip, &is_code);
		tc_invalidate(&cpu->cpu_ctx, addr, 1, cpu->cpu_ctx.regs.eip);
	}
	catch (host_exp_t type) {
		return set_last_error(lc86_status::guest_exp);
	}

	return lc86_status::success;
}

/*
* hook_remove -> removes a hook. Only call this from a hook. If called from the same hook which is being removed, it won't return and it will throw an exception instead
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
* trampoline_call -> calls the original intercepted guest function. Only call this from a hook
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
		(((((cpu->cpu_ctx.lazy_eflags.result | -cpu->cpu_ctx.lazy_eflags.result) >> 31) & 1) ^ 1) << 6) | // zf
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
