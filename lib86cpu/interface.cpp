/*
 * This is the interface to the client.
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#include "llvm/IR/Module.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/ExecutionEngine/Orc/LLJIT.h"
#include "lib86cpu.h"
#include "x86_internal.h"


static void
sync_hflags(cpu_t *cpu)
{
	cpu->cpu_ctx.hflags = (cpu->cpu_ctx.regs.cs & HFLG_CPL) | HFLG_CPL_PRIV;
	if (cpu->cpu_ctx.regs.cr0 & CR0_PE_MASK) {
		cpu->cpu_ctx.hflags |= HFLG_PE_MODE;
		if (cpu->cpu_ctx.regs.cs_hidden.flags & SEG_HIDDEN_DB) {
			cpu->cpu_ctx.hflags |= HFLG_CS32;
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

	cpu->ram = new uint8_t[ramsize];
	if (cpu->ram == nullptr) {
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

	// init llvm
	InitializeNativeTarget();
	InitializeNativeTargetAsmParser();
	InitializeNativeTargetAsmPrinter();
	auto jtmb = orc::JITTargetMachineBuilder::detectHost();
	if (!jtmb) {
		cpu_free(cpu);
		return LIB86CPU_LLVM_ERROR;
	}
	SubtargetFeatures features;
	StringMap<bool> host_features;
	if (sys::getHostCPUFeatures(host_features))
		for (auto &F : host_features) {
			features.AddFeature(F.first(), F.second);
		}
	jtmb->setCPU(sys::getHostCPUName())
		.addFeatures(features.getFeatures())
		.setRelocationModel(None)
		.setCodeModel(None);
	auto dl = jtmb->getDefaultDataLayoutForTarget();
	if (!dl) {
		cpu_free(cpu);
		return LIB86CPU_LLVM_ERROR;
	}
	cpu->dl = new DataLayout(*dl);
	if (cpu->dl == nullptr) {
		cpu_free(cpu);
		return LIB86CPU_NO_MEMORY;
	}
	// XXX use sys::getHostNumPhysicalCores from llvm to exclude logical cores?
	auto jit = orc::LLJIT::Create(std::move(*jtmb), *dl, std::thread::hardware_concurrency());
	if (!jit) {
		cpu_free(cpu);
		return LIB86CPU_LLVM_ERROR;
	}
	cpu->jit = std::move(*jit);
	cpu->jit->getMainJITDylib().setGenerator(
		*orc::DynamicLibrarySearchGenerator::GetForCurrentProcess(*dl));
#ifdef _WIN32
	// workaround for llvm bug D65548
	cpu->jit->getObjLinkingLayer().setOverrideObjectFlagsWithResponsibilityFlags(true);
#endif

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
	if (cpu->ram) {
		delete[] cpu->ram;
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

	// main cpu loop
	while (true) {
		lib86cpu_status status = cpu_exec_tc(cpu);
		switch (status)
		{
		case LIB86CPU_LLVM_ERROR:
		case LIB86CPU_NO_MEMORY:
		case LIB86CPU_UNKNOWN_INSTR:
		case LIB86CPU_OP_NOT_IMPLEMENTED:
			// these are fatal errors, simply exit the cpu loop
			return status;
		}
	}
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
	return 0xFFFFFFFF;
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
	return 0xFFFFFFFF;
}

lib86cpu_status
memory_init_region_ram(cpu_t *cpu, addr_t start, size_t size, int priority)
{
	std::unique_ptr<memory_region_t<addr_t>> ram(new memory_region_t<addr_t>);

	if (size == 0) {
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
memory_destroy_region(cpu_t *cpu, addr_t start, size_t size, bool io_space)
{
	bool deleted;

	if (io_space) {
		port_t start_io = static_cast<port_t>(start);
		port_t end = start + size - 1;
		deleted = cpu->io_space_tree->erase(start_io, end);
	}
	else {
		addr_t end = start + size - 1;
		deleted = cpu->memory_space_tree->erase(start, end);
	}

	if (deleted) {
		return LIB86CPU_SUCCESS;
	}
	else {
		return LIB86CPU_INVALID_PARAMETER;
	}
}
