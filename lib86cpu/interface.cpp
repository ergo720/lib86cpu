/*
 * This is the interface to the client.
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#include "jit.h"
#include "internal.h"
#include "memory.h"
#include "clock.h"
#include <fstream>


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
	cpu->io_space_tree->insert(io_region->start, io_region->end, std::move(io_region));

	cpu->jit = std::move(lc86_jit::create(cpu));

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

	llvm_shutdown();

	delete cpu;
}

lc86_status
cpu_run(cpu_t *cpu)
{
	cpu_sync_state(cpu);
	return cpu_start(cpu);
}

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

std::string
get_last_error()
{
	return last_error;
}

uint8_t *
get_ram_ptr(cpu_t *cpu)
{
	return cpu->cpu_ctx.ram;
}

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

lc86_status
mem_init_region_io(cpu_t *cpu, addr_t start, size_t size, bool io_space, fp_read read_func, fp_write write_func, void *opaque, int priority)
{
	bool inserted;

	if (size == 0) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	if (io_space) {
		std::unique_ptr<memory_region_t<port_t>> io(new memory_region_t<port_t>);

		if (start > 65535 || (start + size) > 65536) {
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

		inserted = cpu->io_space_tree->insert(start_io, end, std::move(io));
	}
	else {
		std::unique_ptr<memory_region_t<addr_t>> io(new memory_region_t<addr_t>);
		addr_t end = start + size - 1;
		cpu->memory_space_tree->search(start, end, cpu->memory_out);

		for (auto &region : cpu->memory_out) {
			if (region.get()->priority == priority) {
				return set_last_error(lc86_status::invalid_parameter);
			}
		}

		io->start = start;
		io->end = end;
		io->type = mem_type::mmio;
		io->priority = priority;
		if (read_func) {
			io->read_handler = read_func;
		}
		else {
			io->read_handler = default_mmio_read_handler;
		}
		if (write_func) {
			io->write_handler = write_func;
		}
		else {
			io->write_handler = default_mmio_write_handler;
		}
		if (opaque) {
			io->opaque = opaque;
		}

		inserted = cpu->memory_space_tree->insert(start, end, std::move(io));
	}

	if (inserted) {
		return lc86_status::success;
	}
	else {
		return set_last_error(lc86_status::invalid_parameter);
	}
}

// XXX Are aliased regions allowed in the io space as well?
lc86_status
mem_init_region_alias(cpu_t *cpu, addr_t alias_start, addr_t ori_start, size_t ori_size, int priority)
{
	std::unique_ptr<memory_region_t<addr_t>> alias(new memory_region_t<addr_t>);

	if (ori_size == 0) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	memory_region_t<addr_t> *aliased_region = nullptr;
	addr_t end = ori_start + ori_size - 1;
	cpu->memory_space_tree->search(ori_start, end, cpu->memory_out);

	if (cpu->memory_out.empty()) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	for (auto &region : cpu->memory_out) {
		if ((region.get()->start <= ori_start) && (region.get()->end >= end)) {
			aliased_region = region.get().get();
			break;
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

lc86_status
mem_init_region_rom(cpu_t *cpu, addr_t start, size_t size, uint32_t offset, int priority, const char *rom_path, uint8_t *&out)
{
	std::unique_ptr<memory_region_t<addr_t>> rom(new memory_region_t<addr_t>);

	if (out == nullptr) {
		std::ifstream ifs(rom_path, std::ios_base::in | std::ios_base::binary);
		if (!ifs.is_open()) {
			return set_last_error(lc86_status::invalid_parameter);
		}
		ifs.seekg(0, ifs.end);
		size_t length = ifs.tellg();
		ifs.seekg(0, ifs.beg);

		if (length == 0) {
			return set_last_error(lc86_status::invalid_parameter);
		}
		else if (offset + size > length) {
			return set_last_error(lc86_status::invalid_parameter);
		}

		std::unique_ptr<uint8_t[]> rom_ptr(new uint8_t[size]);
		ifs.seekg(offset);
		ifs.read(reinterpret_cast<char *>(&rom_ptr[0]), size);
		ifs.close();
		cpu->vec_rom.push_back(std::make_pair(std::move(rom_ptr), 0));
		rom->rom_idx = cpu->vec_rom.size() - 1;
	}
	else {
		for (int i = 0; i < cpu->vec_rom.size(); i++) {
			if (cpu->vec_rom[i].first.get() == out) {
				rom->rom_idx = i;
				break;
			}
		}

		if (rom->rom_idx == -1) {
			return set_last_error(lc86_status::invalid_parameter);
		}
	}

	addr_t end = start + size - 1;
	cpu->memory_space_tree->search(start, end, cpu->memory_out);

	for (auto &region : cpu->memory_out) {
		if (region.get()->priority == priority) {
			if (out == nullptr) {
				cpu->vec_rom.pop_back();
			}
			return set_last_error(lc86_status::invalid_parameter);
		}
	}

	rom->start = start;
	rom->end = end;
	rom->type = mem_type::rom;
	rom->priority = priority;

	auto &rom_ref = cpu->vec_rom[rom->rom_idx];
	if (cpu->memory_space_tree->insert(start, end, std::move(rom))) {
		out = rom_ref.first.get();
		rom_ref.second++;
		return lc86_status::success;
	}

	if (out == nullptr) {
		cpu->vec_rom.pop_back();
	}
	return set_last_error(lc86_status::invalid_parameter);
}

lc86_status
mem_destroy_region(cpu_t *cpu, addr_t start, size_t size, bool io_space)
{
	bool deleted;
	int rom_idx = -1;

	if (io_space) {
		port_t start_io = static_cast<port_t>(start);
		port_t end = start + size - 1;
		deleted = cpu->io_space_tree->erase(start_io, end);
	}
	else {
		bool found = false;
		addr_t end = start + size - 1;
		cpu->memory_space_tree->search(start, end, cpu->memory_out);
		for (auto &region : cpu->memory_out) {
			if ((region.get().get()->start == start) && (region.get().get()->end == end)) {
				if (region.get().get()->type == mem_type::rom) {
					rom_idx = region.get().get()->rom_idx;
				}
				found = true;
				break;
			}
		}

		if (!found) {
			return set_last_error(lc86_status::invalid_parameter);
		}

		deleted = cpu->memory_space_tree->erase(start, end);
	}

	if (deleted) {
		if (rom_idx != -1) {
			cpu->vec_rom[rom_idx].second--;
			if (cpu->vec_rom[rom_idx].second == 0) {
				cpu->vec_rom.erase(cpu->vec_rom.begin() + rom_idx);
			}
		}
		return lc86_status::success;
	}
	else {
		return set_last_error(lc86_status::invalid_parameter);
	}
}

lc86_status
mem_read_block(cpu_t *cpu, addr_t addr, size_t size, uint8_t *out)
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

				case mem_type::mmio:
					return set_last_error(lc86_status::invalid_parameter);

				case mem_type::alias: {
					memory_region_t<addr_t> *alias = region;
					AS_RESOLVE_ALIAS();
					phys_addr = region->start + alias_offset + (phys_addr - alias->start);
					goto retry;
				}
				break;

				case mem_type::unmapped:
					LOG(log_level::warn, "Memory read to unmapped memory at address %#010x with size %zu", phys_addr, bytes_to_read);
					std::memcpy(out + vec_offset, std::vector<uint8_t>(bytes_to_read, 0xFF).data(), bytes_to_read);
					break;

				default:
					return set_last_error(lc86_status::internal_error);
				}
			}
			else {
				LOG(log_level::warn, "Memory read at address %#010x with size %zu is not completely inside a memory region", phys_addr, bytes_to_read);
				std::memcpy(out + vec_offset, std::vector<uint8_t>(bytes_to_read, 0xFF).data(), bytes_to_read);
			}

			page_offset = 0;
			vec_offset += bytes_to_read;
			size_left -= bytes_to_read;
			addr += bytes_to_read;
		}

		return lc86_status::success;
	}
	catch (host_exp_t type) {
		assert((type == host_exp_t::pf_exp) || (type == host_exp_t::de_exp));
		return set_last_error(lc86_status::guest_exp);
	}
}

// NOTE1: this is not correct if the client writes to the same tc we are executing (because we pass nullptr as tc argument to tc_invalidate)
// NOTE2: if a page fault is raised on a page after the first one is written to, this will result in a partial write. I'm not sure if this is a problem though
template<bool fill>
lc86_status mem_write_handler(cpu_t *cpu, addr_t addr, size_t size, const void *buffer, int val)
{
	size_t page_offset = addr & PAGE_MASK;
	size_t size_left = size;

	try {
		while (size_left > 0) {
			uint8_t is_code;
			size_t bytes_to_write = std::min(PAGE_SIZE - page_offset, size_left);
			addr_t phys_addr = get_write_addr(cpu, addr, 0, 0, &is_code);
			if (is_code) {
				tc_invalidate(&cpu->cpu_ctx, nullptr, phys_addr, bytes_to_write, 0);
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

				case mem_type::mmio:
					return set_last_error(lc86_status::invalid_parameter);

				case mem_type::alias: {
					memory_region_t<addr_t> *alias = region;
					AS_RESOLVE_ALIAS();
					phys_addr = region->start + alias_offset + (phys_addr - alias->start);
					goto retry;
				}
				break;

				case mem_type::unmapped:
					LOG(log_level::warn, "Memory write to unmapped memory at address %#010x with size %zu", phys_addr, bytes_to_write);
					break;

				default:
					return set_last_error(lc86_status::internal_error);
				}
			}
			else {
				LOG(log_level::warn, "Memory write at address %#010x with size %zu is not completely inside a memory region", phys_addr, bytes_to_write);
			}

			page_offset = 0;
			buffer = static_cast<const uint8_t *>(buffer) + bytes_to_write;
			size_left -= bytes_to_write;
			addr += bytes_to_write;
		}

		return lc86_status::success;
	}
	catch (host_exp_t type) {
		assert((type == host_exp_t::pf_exp) || (type == host_exp_t::de_exp));
		return set_last_error(lc86_status::guest_exp);
	}
}

lc86_status
mem_write_block(cpu_t *cpu, addr_t addr, size_t size, const void *buffer)
{
	return mem_write_handler<false>(cpu, addr, size, buffer, 0);
}

lc86_status
mem_fill_block(cpu_t *cpu, addr_t addr, size_t size, int val)
{
	return mem_write_handler<true>(cpu, addr, size, nullptr, val);
}

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

void
tlb_invalidate(cpu_t *cpu, addr_t addr_start, addr_t addr_end)
{
	for (uint32_t tlb_idx_s = addr_start >> PAGE_SHIFT, tlb_idx_e = addr_end >> PAGE_SHIFT; tlb_idx_s <= tlb_idx_e; tlb_idx_s++) {
		cpu->cpu_ctx.tlb[tlb_idx_s] = (cpu->cpu_ctx.tlb[tlb_idx_s] & (TLB_RAM | TLB_CODE));
	}
}

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

	tc_invalidate(&cpu->cpu_ctx, nullptr, addr, 1, 0);

	return lc86_status::success;
}

lc86_status
hook_remove(cpu_t *cpu, addr_t addr)
{
	const auto it = cpu->hook_map.find(addr);
	if (it == cpu->hook_map.end()) {
		return set_last_error(lc86_status::not_found);
	}

	tc_invalidate(&cpu->cpu_ctx, nullptr, it->first, 1, 0);
	cpu->hook_map.erase(it);

	return lc86_status::success;
}

void
trampoline_call(cpu_t *cpu, const uint32_t ret_eip)
{
	// a trampoline calls the original guest function that was hooked, and it's only supposed to get called from the host function that hooed it.
	// This assumes that the guest state (regs and stack) are in the same state that the guest has set them when it called the hook, so that we can call
	// the trampoline without having to set this state up ourselves. The argument ret_eip is the eip to which the trampoline returns to after if finishes
	// executing and returns, and it tipically corresponds to the eip that the call instruction pushed on the stack.

	cpu_exec_trampoline(cpu, ret_eip);
}

regs_t *get_regs_ptr(cpu_t *cpu)
{
	// Reading the eip at runtime will not yield the correct result because we only update it at the end of a tc
	return &cpu->cpu_ctx.regs;
}

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
