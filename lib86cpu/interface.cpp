/*
 * This is the interface to the client.
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#include "jit.h"
#include "internal.h"
#include <fstream>

static void
sync_hflags(cpu_t *cpu)
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

lib86cpu_status
cpu_new(size_t ramsize, cpu_t *&out)
{
	cpu_t *cpu;
	out = nullptr;

	printf("Creating new cpu...\n");

	cpu = new cpu_t();
	if (cpu == nullptr) {
		return LIB86CPU_NO_MEMORY;
	}

	if ((ramsize % PAGE_SIZE) != 0) {
		cpu_free(cpu);
		return LIB86CPU_INVALID_PARAMETER;
	}

	cpu->cpu_ctx.ram = new uint8_t[ramsize];
	if (cpu->cpu_ctx.ram == nullptr) {
		cpu_free(cpu);
		return LIB86CPU_NO_MEMORY;
	}

	cpu_x86_init(cpu);

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

	cpu->jit = std::move(lib86cpu_jit::create(cpu));

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

	out = cpu->cpu_ctx.cpu = cpu;
	return LIB86CPU_SUCCESS;
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

lib86cpu_status
cpu_run(cpu_t *cpu)
{
	sync_hflags(cpu);

	return cpu_exec_tc(cpu);
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

lib86cpu_status
memory_init_region_ram(cpu_t *cpu, addr_t start, size_t size, int priority)
{
	std::unique_ptr<memory_region_t<addr_t>> ram(new memory_region_t<addr_t>);

	if (size == 0) {
		return LIB86CPU_INVALID_PARAMETER;
	}

	if ((start % PAGE_SIZE) != 0 || ((size % PAGE_SIZE) != 0)) {
		return LIB86CPU_INVALID_PARAMETER;
	}

	addr_t end = start + size - 1;
	cpu->memory_space_tree->search(start, end, cpu->memory_out);

	for (auto &region : cpu->memory_out) {
		if (region.get()->priority == priority) {
			return LIB86CPU_INVALID_PARAMETER;
		}
	}

	ram->start = start;
	ram->end = end;
	ram->type = MEM_RAM;
	ram->priority = priority;

	if (cpu->memory_space_tree->insert(start, end, std::move(ram))) {
		return LIB86CPU_SUCCESS;
	}
	else {
		return LIB86CPU_INVALID_PARAMETER;
	}
}

lib86cpu_status
memory_init_region_io(cpu_t *cpu, addr_t start, size_t size, bool io_space, fp_read read_func, fp_write write_func, void *opaque, int priority)
{
	bool inserted;

	if (size == 0) {
		return LIB86CPU_INVALID_PARAMETER;
	}

	if (io_space) {
		std::unique_ptr<memory_region_t<port_t>> io(new memory_region_t<port_t>);

		if (start > 65535 || (start + size) > 65536) {
			return LIB86CPU_INVALID_PARAMETER;
		}

		port_t start_io = static_cast<port_t>(start);
		port_t end = start_io + size - 1;
		cpu->io_space_tree->search(start_io, end, cpu->io_out);

		for (auto &region : cpu->io_out) {
			if (region.get()->priority == priority) {
				return LIB86CPU_INVALID_PARAMETER;
			}
		}

		io->start = start_io;
		io->end = end;
		io->type = MEM_PMIO;
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
				return LIB86CPU_INVALID_PARAMETER;
			}
		}

		io->start = start;
		io->end = end;
		io->type = MEM_MMIO;
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
		return LIB86CPU_SUCCESS;
	}
	else {
		return LIB86CPU_INVALID_PARAMETER;
	}
}

// XXX Are aliased regions allowed in the io space as well?
lib86cpu_status
memory_init_region_alias(cpu_t *cpu, addr_t alias_start, addr_t ori_start, size_t ori_size, int priority)
{
	std::unique_ptr<memory_region_t<addr_t>> alias(new memory_region_t<addr_t>);

	if (ori_size == 0) {
		return LIB86CPU_INVALID_PARAMETER;
	}

	memory_region_t<addr_t> *aliased_region = nullptr;
	addr_t end = ori_start + ori_size - 1;
	cpu->memory_space_tree->search(ori_start, end, cpu->memory_out);

	if (cpu->memory_out.empty()) {
		return LIB86CPU_INVALID_PARAMETER;
	}

	for (auto &region : cpu->memory_out) {
		if ((region.get()->start <= ori_start) && (region.get()->end >= end)) {
			aliased_region = region.get().get();
			break;
		}
	}

	if (!aliased_region) {
		return LIB86CPU_INVALID_PARAMETER;
	}

	end = alias_start + ori_size - 1;
	cpu->memory_space_tree->search(alias_start, end, cpu->memory_out);

	for (auto &region : cpu->memory_out) {
		if (region.get()->priority == priority) {
			return LIB86CPU_INVALID_PARAMETER;
		}
	}

	alias->start = alias_start;
	alias->end = end;
	alias->alias_offset = ori_start - aliased_region->start;
	alias->type = MEM_ALIAS;
	alias->priority = priority;
	alias->aliased_region = aliased_region;

	if (cpu->memory_space_tree->insert(alias_start, end, std::move(alias))) {
		return LIB86CPU_SUCCESS;
	}
	else {
		return LIB86CPU_INVALID_PARAMETER;
	}
}

lib86cpu_status
memory_init_region_rom(cpu_t *cpu, addr_t start, size_t size, uint32_t offset, int priority, const char *rom_path, uint8_t *&out)
{
	std::unique_ptr<memory_region_t<addr_t>> rom(new memory_region_t<addr_t>);

	if (out == nullptr) {
		std::ifstream ifs(rom_path, std::ios_base::in | std::ios_base::binary);
		if (!ifs.is_open()) {
			return LIB86CPU_INVALID_PARAMETER;
		}
		ifs.seekg(0, ifs.end);
		size_t length = ifs.tellg();
		ifs.seekg(0, ifs.beg);

		if (length == 0) {
			return LIB86CPU_INVALID_PARAMETER;
		}
		else if (offset + size > length) {
			return LIB86CPU_INVALID_PARAMETER;
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
			return LIB86CPU_INVALID_PARAMETER;
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
	rom->type = MEM_ROM;
	rom->priority = priority;

	auto &rom_ref = cpu->vec_rom[rom->rom_idx];
	if (cpu->memory_space_tree->insert(start, end, std::move(rom))) {
		out = rom_ref.first.get();
		rom_ref.second++;
		return LIB86CPU_SUCCESS;
	}

	fail:
	if (out == nullptr) {
		cpu->vec_rom.pop_back();
	}
	return LIB86CPU_INVALID_PARAMETER;
}

lib86cpu_status
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
				if (region.get().get()->type == MEM_ROM) {
					rom_idx = region.get().get()->rom_idx;
				}
				found = true;
				break;
			}
		}

		if (!found) {
			return LIB86CPU_INVALID_PARAMETER;
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
		return LIB86CPU_SUCCESS;
	}
	else {
		return LIB86CPU_INVALID_PARAMETER;
	}
}

lib86cpu_status
hook_add(cpu_t *cpu, addr_t addr, std::unique_ptr<hook> obj)
{
	// NOTE: this hooks will only work as expected when they are added before cpu execution starts (becasue
	// we don't flush the code cache here) and only when addr points to the first instruction of the hooked
	// function (because we only check for hooks at the start of the translation of a new code block)

	if (cpu->hook_map.find(addr) != cpu->hook_map.end()) {
		return LIB86CPU_ALREADY_EXIST;
	}

	if (obj.get() == nullptr) {
		return LIB86CPU_INVALID_PARAMETER;
	}

	if (obj->info.args.size() == 0) {
		return LIB86CPU_INVALID_PARAMETER;
	}

	if (obj->info.args.size() > 1) {
		for (unsigned i = 1; i < obj->info.args.size(); i++) {
			if (obj->info.args[i] == arg_types::VOID) {
				return LIB86CPU_INVALID_PARAMETER;
			}
		}
	}

	cpu->hook_map.emplace(addr, std::move(obj));

	return LIB86CPU_SUCCESS;
}
