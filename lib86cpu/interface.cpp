/*
 * This is the interface to the client.
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#include "jit.h"
#include "internal.h"
#include "memory.h"
#include <fstream>


void
cpu_sync_state(cpu_t *cpu)
{
	uint16_t cs = cpu->cpu_ctx.regs.cs;
	if (cpu->cpu_ctx.regs.cr0 & CR0_PE_MASK) {
		cpu->cpu_ctx.hflags |= ((cpu->cpu_ctx.regs.cs & HFLG_CPL) | HFLG_PE_MODE);
		if (cpu->cpu_ctx.regs.cs_hidden.flags & SEG_HIDDEN_DB) {
			cpu->cpu_ctx.hflags |= HFLG_CS32;
		}
		if (cpu->cpu_ctx.regs.ss_hidden.flags & SEG_HIDDEN_DB) {
			cpu->cpu_ctx.hflags |= HFLG_SS32;
		}
	}
}

tl::expected<cpu_t *, lc86_status>
cpu_new(size_t ramsize)
{
	printf("Creating new cpu...\n");

	cpu_t *cpu = new cpu_t();
	if (cpu == nullptr) {
		return tl::unexpected<lc86_status>(lc86_status::NO_MEMORY);
	}

	if ((ramsize % PAGE_SIZE) != 0) {
		cpu_free(cpu);
		return tl::unexpected<lc86_status>(lc86_status::INVALID_PARAMETER);
	}

	cpu->cpu_ctx.ram = new uint8_t[ramsize];
	if (cpu->cpu_ctx.ram == nullptr) {
		cpu_free(cpu);
		return tl::unexpected<lc86_status>(lc86_status::NO_MEMORY);
	}

	cpu_init(cpu);

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

	// check if FP80 and FP128 are supported by this architecture
	std::string data_layout = cpu->dl->getStringRepresentation();
	if (data_layout.find("f80") != std::string::npos) {
		LOG("INFO: FP80 supported.\n");
		cpu->cpu_flags |= CPU_FLAG_FP80;
	}

	// check if we need to swap guest memory.
	if (cpu->dl->isBigEndian()) {
		cpu->cpu_flags |= CPU_FLAG_SWAPMEM;
	}

	printf("Created new cpu \"%s\"\n", cpu->cpu_name);

	cpu->cpu_ctx.cpu = cpu;
	return cpu;
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

void
cpu_run(cpu_t *cpu)
{
	cpu_sync_state(cpu);
	cpu_start(cpu);
	LIB86CPU_ABORT();
}

static void
default_mmio_write_handler(addr_t addr, size_t size, uint32_t value, void *opaque)
{
	LOG("Unhandled MMIO write at address %#010x with size %d\n", addr, size);
}

static uint32_t
default_mmio_read_handler(addr_t addr, size_t size, void *opaque)
{
	LOG("Unhandled MMIO read at address %#010x with size %d\n", addr, size);
	return std::numeric_limits<uint32_t>::max();
}

static void
default_pmio_write_handler(addr_t addr, size_t size, uint32_t value, void *opaque)
{
	LOG("Unhandled PMIO write at port %#06x with size %d\n", addr, size);
}

static uint32_t
default_pmio_read_handler(addr_t addr, size_t size, void *opaque)
{
	LOG("Unhandled PMIO read at port %#06x with size %d\n", addr, size);
	return std::numeric_limits<uint32_t>::max();
}

lc86_status
memory_init_region_ram(cpu_t *cpu, addr_t start, size_t size, int priority)
{
	std::unique_ptr<memory_region_t<addr_t>> ram(new memory_region_t<addr_t>);

	if (size == 0) {
		return lc86_status::INVALID_PARAMETER;
	}

	if ((start % PAGE_SIZE) != 0 || ((size % PAGE_SIZE) != 0)) {
		return lc86_status::INVALID_PARAMETER;
	}

	addr_t end = start + size - 1;
	cpu->memory_space_tree->search(start, end, cpu->memory_out);

	for (auto &region : cpu->memory_out) {
		if (region.get()->priority == priority) {
			return lc86_status::INVALID_PARAMETER;
		}
	}

	ram->start = start;
	ram->end = end;
	ram->type = mem_type::RAM;
	ram->priority = priority;

	if (cpu->memory_space_tree->insert(start, end, std::move(ram))) {
		return lc86_status::SUCCESS;
	}
	else {
		return lc86_status::INVALID_PARAMETER;
	}
}

lc86_status
memory_init_region_io(cpu_t *cpu, addr_t start, size_t size, bool io_space, fp_read read_func, fp_write write_func, void *opaque, int priority)
{
	bool inserted;

	if (size == 0) {
		return lc86_status::INVALID_PARAMETER;
	}

	if (io_space) {
		std::unique_ptr<memory_region_t<port_t>> io(new memory_region_t<port_t>);

		if (start > 65535 || (start + size) > 65536) {
			return lc86_status::INVALID_PARAMETER;
		}

		port_t start_io = static_cast<port_t>(start);
		port_t end = start_io + size - 1;
		cpu->io_space_tree->search(start_io, end, cpu->io_out);

		for (auto &region : cpu->io_out) {
			if (region.get()->priority == priority) {
				return lc86_status::INVALID_PARAMETER;
			}
		}

		io->start = start_io;
		io->end = end;
		io->type = mem_type::PMIO;
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
				return lc86_status::INVALID_PARAMETER;
			}
		}

		io->start = start;
		io->end = end;
		io->type = mem_type::MMIO;
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
		return lc86_status::SUCCESS;
	}
	else {
		return lc86_status::INVALID_PARAMETER;
	}
}

// XXX Are aliased regions allowed in the io space as well?
lc86_status
memory_init_region_alias(cpu_t *cpu, addr_t alias_start, addr_t ori_start, size_t ori_size, int priority)
{
	std::unique_ptr<memory_region_t<addr_t>> alias(new memory_region_t<addr_t>);

	if (ori_size == 0) {
		return lc86_status::INVALID_PARAMETER;
	}

	memory_region_t<addr_t> *aliased_region = nullptr;
	addr_t end = ori_start + ori_size - 1;
	cpu->memory_space_tree->search(ori_start, end, cpu->memory_out);

	if (cpu->memory_out.empty()) {
		return lc86_status::INVALID_PARAMETER;
	}

	for (auto &region : cpu->memory_out) {
		if ((region.get()->start <= ori_start) && (region.get()->end >= end)) {
			aliased_region = region.get().get();
			break;
		}
	}

	if (!aliased_region) {
		return lc86_status::INVALID_PARAMETER;
	}

	end = alias_start + ori_size - 1;
	cpu->memory_space_tree->search(alias_start, end, cpu->memory_out);

	for (auto &region : cpu->memory_out) {
		if (region.get()->priority == priority) {
			return lc86_status::INVALID_PARAMETER;
		}
	}

	alias->start = alias_start;
	alias->end = end;
	alias->alias_offset = ori_start - aliased_region->start;
	alias->type = mem_type::ALIAS;
	alias->priority = priority;
	alias->aliased_region = aliased_region;

	if (cpu->memory_space_tree->insert(alias_start, end, std::move(alias))) {
		return lc86_status::SUCCESS;
	}
	else {
		return lc86_status::INVALID_PARAMETER;
	}
}

lc86_status
memory_init_region_rom(cpu_t *cpu, addr_t start, size_t size, uint32_t offset, int priority, const char *rom_path, uint8_t *&out)
{
	std::unique_ptr<memory_region_t<addr_t>> rom(new memory_region_t<addr_t>);

	if (out == nullptr) {
		std::ifstream ifs(rom_path, std::ios_base::in | std::ios_base::binary);
		if (!ifs.is_open()) {
			return lc86_status::INVALID_PARAMETER;
		}
		ifs.seekg(0, ifs.end);
		size_t length = ifs.tellg();
		ifs.seekg(0, ifs.beg);

		if (length == 0) {
			return lc86_status::INVALID_PARAMETER;
		}
		else if (offset + size > length) {
			return lc86_status::INVALID_PARAMETER;
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
			return lc86_status::INVALID_PARAMETER;
		}
	}

	addr_t end = start + size - 1;
	cpu->memory_space_tree->search(start, end, cpu->memory_out);

	for (auto &region : cpu->memory_out) {
		if (region.get()->priority == priority) {
			goto fail;
		}
	}

	rom->start = start;
	rom->end = end;
	rom->type = mem_type::ROM;
	rom->priority = priority;

	auto &rom_ref = cpu->vec_rom[rom->rom_idx];
	if (cpu->memory_space_tree->insert(start, end, std::move(rom))) {
		out = rom_ref.first.get();
		rom_ref.second++;
		return lc86_status::SUCCESS;
	}

	fail:
	if (out == nullptr) {
		cpu->vec_rom.pop_back();
	}
	return lc86_status::INVALID_PARAMETER;
}

lc86_status
memory_destroy_region(cpu_t *cpu, addr_t start, size_t size, bool io_space)
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
				if (region.get().get()->type == mem_type::ROM) {
					rom_idx = region.get().get()->rom_idx;
				}
				found = true;
				break;
			}
		}

		if (!found) {
			return lc86_status::INVALID_PARAMETER;
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
		return lc86_status::SUCCESS;
	}
	else {
		return lc86_status::INVALID_PARAMETER;
	}
}

tl::expected<uint8_t, lc86_status>
mem_read_8(cpu_t *cpu, addr_t addr)
{
	try {
		return mem_read<uint8_t>(cpu, addr, 0, 0);
	}
	catch (exp_data_t exp_data) {
		return tl::unexpected<lc86_status>(lc86_status::PAGE_FAULT);
	}
}

tl::expected<uint16_t, lc86_status>
mem_read_16(cpu_t *cpu, addr_t addr)
{
	try {
		return mem_read<uint16_t>(cpu, addr, 0, 0);
	}
	catch (exp_data_t exp_data) {
		return tl::unexpected<lc86_status>(lc86_status::PAGE_FAULT);
	}
}

tl::expected<uint32_t, lc86_status>
mem_read_32(cpu_t *cpu, addr_t addr)
{
	try {
		return mem_read<uint32_t>(cpu, addr, 0, 0);
	}
	catch (exp_data_t exp_data) {
		return tl::unexpected<lc86_status>(lc86_status::PAGE_FAULT);
	}
}

tl::expected<uint64_t, lc86_status>
mem_read_64(cpu_t *cpu, addr_t addr)
{
	try {
		return mem_read<uint64_t>(cpu, addr, 0, 0);
	}
	catch (exp_data_t exp_data) {
		return tl::unexpected<lc86_status>(lc86_status::PAGE_FAULT);
	}
}

// NOTE: this is not correct if the client writes to a page that holds translated code (becaue we pass nullptr as tc argument)
lc86_status
mem_write_8(cpu_t *cpu, addr_t addr, uint8_t value)
{
	try {
		mem_write<uint8_t>(cpu, addr, value, 0, 0, nullptr);
		return lc86_status::SUCCESS;
	}
	catch (exp_data_t exp_data) {
		return lc86_status::PAGE_FAULT;
	}
}

lc86_status
mem_write_16(cpu_t *cpu, addr_t addr, uint16_t value)
{
	try {
		mem_write<uint16_t>(cpu, addr, value, 0, 0, nullptr);
		return lc86_status::SUCCESS;
	}
	catch (exp_data_t exp_data) {
		return lc86_status::PAGE_FAULT;
	}
}

lc86_status
mem_write_32(cpu_t *cpu, addr_t addr, uint32_t value)
{
	try {
		mem_write<uint32_t>(cpu, addr, value, 0, 0, nullptr);
		return lc86_status::SUCCESS;
	}
	catch (exp_data_t exp_data) {
		return lc86_status::PAGE_FAULT;
	}
}

lc86_status
mem_write_64(cpu_t *cpu, addr_t addr, uint64_t value)
{
	try {
		mem_write<uint64_t>(cpu, addr, value, 0, 0, nullptr);
		return lc86_status::SUCCESS;
	}
	catch (exp_data_t exp_data) {
		return lc86_status::PAGE_FAULT;
	}
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

lc86_status
io_write_8(cpu_t *cpu, port_t port, uint8_t value)
{
	io_write<uint8_t>(cpu, port, value);
	return lc86_status::SUCCESS;
}

lc86_status
io_write_16(cpu_t *cpu, port_t port, uint16_t value)
{
	io_write<uint16_t>(cpu, port, value);
	return lc86_status::SUCCESS;
}

lc86_status
io_write_32(cpu_t *cpu, port_t port, uint32_t value)
{
	io_write<uint32_t>(cpu, port, value);
	return lc86_status::SUCCESS;
}

lc86_status
hook_add(cpu_t *cpu, addr_t addr, std::unique_ptr<hook> obj)
{
	// NOTE: this hooks will only work as expected when they are added before cpu execution starts (becasue
	// we don't flush the code cache here) and only when addr points to the first instruction of the hooked
	// function (because we only check for hooks at the start of the translation of a new code block)

	if (cpu->hook_map.find(addr) != cpu->hook_map.end()) {
		return lc86_status::ALREADY_EXIST;
	}

	if (obj.get() == nullptr) {
		return lc86_status::INVALID_PARAMETER;
	}

	if (obj->info.args.size() == 0) {
		return lc86_status::INVALID_PARAMETER;
	}

	if (obj->info.args.size() > 1) {
		for (unsigned i = 1; i < obj->info.args.size(); i++) {
			if (obj->info.args[i] == arg_types::VOID) {
				return lc86_status::INVALID_PARAMETER;
			}
		}
	}

	obj->trmp_vec.clear();
	cpu->hook_map.emplace(addr, std::move(obj));

	return lc86_status::SUCCESS;
}

lc86_status
trampoline_call(cpu_t *cpu, addr_t addr, std::any &ret, std::vector<std::any> args)
{
	auto it = cpu->hook_map.find(addr);
	if (it == cpu->hook_map.end()) {
		return lc86_status::NOT_FOUND;
	}

	return cpu_exec_trampoline(cpu, addr, it->second.get(), ret, args);
}
