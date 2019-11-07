/*
 * This is the interface to the client.
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

/* project global headers */
#include "x86cpu.h"
#include "x86_internal.h"


x86cpu_status
cpu_new(size_t ramsize, cpu_t *&out)
{
	cpu_t *cpu;
	x86cpu_status status = X86CPU_SUCCESS;

	cpu = new cpu_t();
	if (cpu == nullptr) {
		status = X86CPU_NO_MEMORY;
		goto fail;
	}

	cpu->RAM = new uint8_t[ramsize]();
	if (cpu->RAM == nullptr) {
		status = X86CPU_NO_MEMORY;
		goto fail;
	}

	status = cpu_x86_init(cpu);
	if (!X86CPU_CHECK_SUCCESS(status)) {
		goto fail;
	}

	out = cpu;
	return status;

fail:
	out = nullptr;
	cpu_free(cpu);
	return status;
}

void
cpu_free(cpu_t *cpu)
{
	delete[] cpu->RAM;
	delete cpu;
}

x86cpu_status
memory_init_region_ram(cpu_t *cpu, addr_t start, size_t size, int priority)
{
	addr_t end;
	std::unique_ptr<memory_region_t<addr_t>> ram(new memory_region_t<addr_t>);
	std::set<std::tuple<addr_t, addr_t, const std::unique_ptr<memory_region_t<addr_t>> &>> out;

	if (size == 0) {
		return X86CPU_INVALID_PARAMETER;
	}

	end = start + size - 1;
	cpu->memory_space_tree->search(start, end, out);

	for (auto &region : out) {
		if (std::get<2>(region)->priority == priority) {
			return X86CPU_INVALID_PARAMETER;
		}
	}

	ram->start = start;
	ram->type = MEM_RAM;
	ram->priority = priority;

	if (cpu->memory_space_tree->insert(start, end, std::move(ram))) {
		return X86CPU_SUCCESS;
	}
	else {
		return X86CPU_INVALID_PARAMETER;
	}
}

x86cpu_status
memory_init_region_io(cpu_t *cpu, addr_t start, size_t size, bool io_space, fp_read read_func, fp_write write_func, void *opaque, int priority)
{
	bool inserted;

	if (size == 0) {
		return X86CPU_INVALID_PARAMETER;
	}

	if (io_space) {
		io_port_t start_io;
		io_port_t end;
		std::unique_ptr<memory_region_t<io_port_t>> io(new memory_region_t<io_port_t>);
		std::set<std::tuple<io_port_t, io_port_t, const std::unique_ptr<memory_region_t<io_port_t>> &>> out;

		if (start > 65535 || (start + size) > 65536) {
			return X86CPU_INVALID_PARAMETER;
		}

		start_io = static_cast<io_port_t>(start);
		end = start_io + size - 1;
		cpu->io_space_tree->search(start_io, end, out);

		for (auto &region : out) {
			if (std::get<2>(region)->priority == priority) {
				return X86CPU_INVALID_PARAMETER;
			}
		}

		io->start = start_io;
		io->type = MEM_PMIO;
		io->priority = priority;
		if (read_func) {
			io->read_handler = read_func;
		}
		if (write_func) {
			io->write_handler = write_func;
		}
		if (opaque) {
			io->opaque = opaque;
		}

		inserted = cpu->io_space_tree->insert(start_io, end, std::move(io));
	}
	else {
		addr_t end;
		std::unique_ptr<memory_region_t<addr_t>> io(new memory_region_t<addr_t>);
		std::set<std::tuple<addr_t, addr_t, const std::unique_ptr<memory_region_t<addr_t>> &>> out;

		end = start + size - 1;
		cpu->memory_space_tree->search(start, end, out);

		for (auto &region : out) {
			if (std::get<2>(region)->priority == priority) {
				return X86CPU_INVALID_PARAMETER;
			}
		}

		io->start = start;
		io->type = MEM_MMIO;
		io->priority = priority;
		if (read_func) {
			io->read_handler = read_func;
		}
		if (write_func) {
			io->write_handler = write_func;
		}
		if (opaque) {
			io->opaque = opaque;
		}

		inserted = cpu->memory_space_tree->insert(start, end, std::move(io));
	}

	if (inserted) {
		return X86CPU_SUCCESS;
	}
	else {
		return X86CPU_INVALID_PARAMETER;
	}
}

// XXX Are aliased regions allowed in the io space as well?
x86cpu_status
memory_init_region_alias(cpu_t *cpu, addr_t alias_start, addr_t ori_start, size_t ori_size, int priority)
{
	addr_t end;
	memory_region_t<addr_t> *aliased_region;
	std::unique_ptr<memory_region_t<addr_t>> alias(new memory_region_t<addr_t>);
	std::set<std::tuple<addr_t, addr_t, const std::unique_ptr<memory_region_t<addr_t>> &>> out;

	if (ori_size == 0) {
		return X86CPU_INVALID_PARAMETER;
	}

	aliased_region = nullptr;
	end = ori_start + ori_size - 1;
	cpu->memory_space_tree->search(ori_start, end, out);

	if (out.empty()) {
		return X86CPU_INVALID_PARAMETER;
	}

	for (auto &region : out) {
		if ((std::get<0>(region) <= ori_start) && (std::get<1>(region) >= end)) {
			aliased_region = std::get<2>(region).get();
			break;
		}
	}

	if (!aliased_region) {
		return X86CPU_INVALID_PARAMETER;
	}

	end = alias_start + ori_size - 1;
	cpu->memory_space_tree->search(alias_start, end, out);

	for (auto &region : out) {
		if (std::get<2>(region)->priority == priority) {
			return X86CPU_INVALID_PARAMETER;
		}
	}

	alias->start = alias_start;
	alias->alias_offset = ori_start - aliased_region->start;
	alias->type = MEM_ALIAS;
	alias->priority = priority;
	alias->aliased_region = aliased_region;

	if (cpu->memory_space_tree->insert(alias_start, end, std::move(alias))) {
		return X86CPU_SUCCESS;
	}
	else {
		return X86CPU_INVALID_PARAMETER;
	}
}

x86cpu_status
memory_destroy_region(cpu_t *cpu, addr_t start, size_t size, bool io_space)
{
	bool deleted;

	if (io_space) {
		io_port_t start_io;
		io_port_t end;

		start_io = static_cast<io_port_t>(start);
		end = start + size - 1;
		deleted = cpu->io_space_tree->erase(start_io, end);
	}
	else {
		addr_t end;

		end = start + size - 1;
		deleted = cpu->memory_space_tree->erase(start, end);
	}

	if (deleted) {
		return X86CPU_SUCCESS;
	}
	else {
		return X86CPU_INVALID_PARAMETER;
	}
}
