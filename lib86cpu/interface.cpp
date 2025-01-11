/*
 * This is the interface to the client.
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#include <fstream>
#include <cstring>
#include "internal.h"
#include "memory_management.h"
#include "os_mem.h"
#ifdef LIB86CPU_X64_EMITTER
#include "x64/jit.h"
#endif
#ifdef XBOX_CPU
#include "ipt.h"
#endif


static uint8_t
default_mmio_read_handler8(addr_t addr, void *opaque)
{
	return log_unhandled_read<uint8_t, mem_type::mmio>(addr);
}

static uint16_t
default_mmio_read_handler16(addr_t addr, void *opaque)
{
	return log_unhandled_read<uint16_t, mem_type::mmio>(addr);
}

static uint32_t
default_mmio_read_handler32(addr_t addr, void *opaque)
{
	return log_unhandled_read<uint32_t, mem_type::mmio>(addr);
}

static uint64_t
default_mmio_read_handler64(addr_t addr, void *opaque)
{
	return log_unhandled_read<uint64_t, mem_type::mmio>(addr);
}

static void
default_mmio_write_handler8(addr_t addr, const uint8_t value, void *opaque)
{
	log_unhandled_write<uint8_t, mem_type::mmio>(addr, value);
}

static void
default_mmio_write_handler16(addr_t addr, const uint16_t value, void *opaque)
{
	log_unhandled_write<uint16_t, mem_type::mmio>(addr, value);
}

static void
default_mmio_write_handler32(addr_t addr, const uint32_t value, void *opaque)
{
	log_unhandled_write<uint32_t, mem_type::mmio>(addr, value);
}

static void
default_mmio_write_handler64(addr_t addr, const uint64_t value, void *opaque)
{
	log_unhandled_write<uint64_t, mem_type::mmio>(addr, value);
}

static uint8_t
default_pmio_read_handler8(addr_t addr, void *opaque)
{
	return log_unhandled_read<uint8_t, mem_type::pmio>(addr);
}

static uint16_t
default_pmio_read_handler16(addr_t addr, void *opaque)
{
	return log_unhandled_read<uint16_t, mem_type::pmio>(addr);
}

static uint32_t
default_pmio_read_handler32(addr_t addr, void *opaque)
{
	return log_unhandled_read<uint32_t, mem_type::pmio>(addr);
}

static void
default_pmio_write_handler8(addr_t addr, const uint8_t value, void *opaque)
{
	log_unhandled_write<uint8_t, mem_type::pmio>(addr, value);
}

static void
default_pmio_write_handler16(addr_t addr, const uint16_t value, void *opaque)
{
	log_unhandled_write<uint16_t, mem_type::pmio>(addr, value);
}

static void
default_pmio_write_handler32(addr_t addr, const uint32_t value, void *opaque)
{
	log_unhandled_write<uint32_t, mem_type::pmio>(addr, value);
}

// NOTE: lib86cpu runs entirely on the single thread that calls cpu_run, so calling the below functions from other threads is not safe. Only call them
// from the hook, mmio or pmio callbacks or before the emulation starts. An exception to this is for the functions explicitly marked as multi-thread safe

/*
* cpu_new -> creates a new cpu instance. Only a single instance should exist at a time
* ramsize: size in bytes of ram buffer internally created (must be a multiple of 4096)
* out: returned cpu instance
* (optional) int_fn: a pair where 1st is a function that returns the vector number when a hw interrupt is serviced, and 2nd is an opaque argument passed to
* the function when lib86cpu calls it. Not necessary if you never generate hw interrupts
* (optional) debuggee: name of the debuggee program to run
* ret: the status of the operation
*/
lc86_status
cpu_new(uint32_t ramsize, cpu_t *&out, std::pair<fp_int, void *> int_data, const char *debuggee)
{
	out = nullptr;

	if (!verify_cpu_features()) {
		// When this fails, last_error is set to a custom message
		return lc86_status::not_supported;
	}

	cpu_t *cpu = new cpu_t();
	if (cpu == nullptr) {
		return set_last_error(lc86_status::no_memory);
	}

	if (ramsize == 0) {
		cpu_free(cpu);
		return set_last_error(lc86_status::invalid_parameter);
	}

	try {
#ifdef XBOX_CPU
		ipt_ram_init(cpu, ramsize);
#else
		// allocate 16 extra bytes at then end in the case something ever does a 2,4,8,10,16 byte access on the last valid byte of ram
		cpu->ram = std::vector<uint8_t>(ramsize + 16, 0);
#endif
	}
	catch (const lc86_exp_abort &exp) {
		cpu_free(cpu);
		last_error = exp.what();
		return exp.get_code();
	}
	catch (const std::exception &exp) {
		cpu_free(cpu);
		last_error = exp.what();
		return set_last_error(lc86_status::no_memory);
	}

	cpu->dbg_name = debuggee ? debuggee : "";
	cpu->int_data = int_data.first ? int_data : std::pair<fp_int, void *>{ default_get_int_vec, nullptr };

	cpu->memory_space_tree = address_space<addr_t>::create();
	cpu->io_space_tree = address_space<port_t>::create();

	try {
		cpu->jit = std::make_unique<lc86_jit>(cpu);
	}
	catch (lc86_exp_abort &exp) {
		cpu_free(cpu);
		last_error = exp.what();
		return exp.get_code();
	}

	cpu_reset(cpu);
	// default to att syntax in the case the user doesn't set a format
	set_instr_format(cpu);

	std::random_device rd;
	cpu->rng_gen.seed(rd());
	cpu->cpu_thr_id = std::thread::id();

	cpu->cpu_ctx.cpu = out = cpu;
	return lc86_status::success;
}

/*
* cpu_free -> destroys a cpu instance. Only call this after cpu_run/cpu_run_until has returned
* cpu: a valid cpu instance
* ret: nothing
*/
void
cpu_free(cpu_t *cpu)
{
#ifdef XBOX_CPU
	ipt_ram_deinit(cpu);
#endif

	for (auto &bucket : cpu->code_cache) {
		bucket.clear();
	}

	delete cpu;
}

template<bool should_purge>
static void cpu_sync_state(cpu_t *cpu)
{
	// only flush the tlb and the code cache if the cpu mode changed
	if ((cpu->cpu_ctx.regs.cr0 & CR0_PE_MASK) != ((cpu->cpu_ctx.hflags & HFLG_PE_MODE) >> PE_MODE_SHIFT)) {
		tlb_flush_g(cpu);
		if constexpr (should_purge) {
			tc_cache_purge(cpu);
		}
		else {
			tc_cache_clear(cpu);
		}
	}

	// there's no need to sync HFLG_TRAMP since those can never be set when this is called either from the client or from cpu_run
	cpu->cpu_ctx.hflags = 0;
	cpu->cpu_ctx.hflags |= (cpu->cpu_ctx.regs.cs & HFLG_CPL);
	if (cpu->cpu_ctx.regs.cs_hidden.flags & SEG_HIDDEN_DB) {
		cpu->cpu_ctx.hflags |= HFLG_CS32;
	}
	if (cpu->cpu_ctx.regs.ss_hidden.flags & SEG_HIDDEN_DB) {
		cpu->cpu_ctx.hflags |= HFLG_SS32;
	}
	if (cpu->cpu_ctx.regs.cs_hidden.base == 0) {
		cpu->cpu_ctx.hflags |= HFLG_CS_IS_ZERO;
	}
	if (cpu->cpu_ctx.regs.ds_hidden.base == 0) {
		cpu->cpu_ctx.hflags |= HFLG_DS_IS_ZERO;
	}
	if (cpu->cpu_ctx.regs.ss_hidden.base == 0) {
		cpu->cpu_ctx.hflags |= HFLG_SS_IS_ZERO;
	}
	if (cpu->cpu_ctx.regs.es_hidden.base == 0) {
		cpu->cpu_ctx.hflags |= HFLG_ES_IS_ZERO;
	}
	if (cpu->cpu_ctx.regs.fs_hidden.base == 0) {
		cpu->cpu_ctx.hflags |= HFLG_FS_IS_ZERO;
	}
	if (cpu->cpu_ctx.regs.gs_hidden.base == 0) {
		cpu->cpu_ctx.hflags |= HFLG_GS_IS_ZERO;
	}
	if (cpu->cpu_ctx.regs.cr0 & CR0_PE_MASK) {
		cpu->cpu_ctx.hflags |= HFLG_PE_MODE;
	}
	if (cpu->cpu_ctx.regs.cr0 & CR0_EM_MASK) {
		cpu->cpu_ctx.hflags |= HFLG_CR0_EM;
	}
	if (cpu->cpu_ctx.regs.cr0 & CR0_TS_MASK) {
		cpu->cpu_ctx.hflags |= HFLG_CR0_TS;
	}
	if (cpu->cpu_ctx.regs.cr4 & CR4_OSFXSR_MASK) {
		cpu->cpu_ctx.hflags |= HFLG_CR4_OSFXSR;
	}
	if (cpu->cpu_ctx.regs.cr4 & CR4_VME_MASK) {
		cpu->cpu_ctx.hflags |= HFLG_CR4_VME;
	}
	if (cpu->cpu_ctx.regs.cr4 & CR4_PVI_MASK) {
		cpu->cpu_ctx.hflags |= HFLG_CR4_PVI;
	}
}

/*
* cpu_run -> starts the emulation. Only returns when there is an error in lib86cpu, cpu_sync_state internally called
* cpu: a valid cpu instance
* ret: the exit reason
*/
lc86_status
cpu_run(cpu_t *cpu)
{
	if (cpu->cpu_flags & CPU_TIMEOUT) {
		return set_last_error(lc86_status::invalid_parameter);
	}
	cpu_sync_state<true>(cpu);
	return cpu_start<true>(cpu);
}

/*
* cpu_run -> starts the emulation. Returns when (1) there is an error in lib86cpu (2) the timeout time has been reached. cpu_sync_state not internally called
* cpu: a valid cpu instance
* timeout_time: a timeout in microseconds representing a future time point to reach before returning
* ret: the exit reason
*/
lc86_status
cpu_run_until(cpu_t *cpu, uint64_t timeout_time)
{
	cpu->timer.timeout_time = timeout_time;
	return cpu_start<false>(cpu);
}

/*
* cpu_run -> changes the timeout time currently set
* cpu: a valid cpu instance
* timeout_time: a timeout in microseconds representing a future time point to reach before returning
* ret: nothing
*/
void
cpu_set_timeout(cpu_t *cpu, uint64_t timeout_time)
{
	cpu->timer.timeout_time = timeout_time;
}

/*
* cpu_exit->submit to the cpu a request to terminate the emulation (this function is multi - thread safe)
* cpu: a valid cpu instance
* ret: nothing
*/
void
cpu_exit(cpu_t *cpu)
{
	cpu->raise_int_fn(&cpu->cpu_ctx, CPU_ABORT_INT);
}

/*
* cpu_sync_state -> synchronizes internal cpu flags with the current cpu state. This is necessary to call when cr0, cs, cs_flags and ss_flags have changed.
* Only call while the emulation is not running
* cpu: a valid cpu instance
* ret: nothing
*/
void
cpu_sync_state(cpu_t *cpu)
{
	cpu_sync_state<false>(cpu);
}

/*
* cpu_set_flags -> sets lib86cpu flags with the current cpu state. Only call this while the emulation is not running
* cpu: a valid cpu instance
* flags: the flags to set
* ret: the status of the operation
*/
lc86_status
cpu_set_flags(cpu_t *cpu, uint32_t flags)
{
	if (flags & ~(CPU_SYNTAX_MASK | CPU_DBG_PRESENT | CPU_ABORT_ON_HLT)) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	switch (flags & CPU_SYNTAX_MASK)
	{
	case CPU_ATT_SYNTAX:
	case CPU_INTEL_SYNTAX:
	case CPU_MASM_SYNTAX:
		break;

	default:
		return set_last_error(lc86_status::invalid_parameter);
	}

	if ((cpu->cpu_flags & (CPU_DBG_PRESENT | CPU_ABORT_ON_HLT)) != (flags & (CPU_DBG_PRESENT | CPU_ABORT_ON_HLT))) {
		// CPU_DBG_PRESENT and CPU_ABORT_ON_HLT change the code emitted for lidt and hlt respectively, so we need to flush the cache if those changed
		tc_cache_clear(cpu);
	}

	cpu->cpu_flags &= ~(CPU_SYNTAX_MASK | CPU_DBG_PRESENT | CPU_ABORT_ON_HLT);
	cpu->cpu_flags |= flags;
	set_instr_format(cpu);

	return lc86_status::success;
}

// NOTE: this function uses should_int in the same manner as the memory APIs when when the gate status changes.

/*
* cpu_set_a20 -> open or close the a20 gate of the cpu
* cpu: a valid cpu instance
* closed: new gate status. If true then addresses are masked with 0xFFFFFFFF (gate closed), otherwise they are masked with 0xFFEFFFFF (gate open)
* should_int: raises a guest interrupt when true, otherwise the change takes effect immediately
* ret: nothing
*/
void
cpu_set_a20(cpu_t *cpu, bool closed, bool should_int)
{
	uint32_t old_a20_mask = cpu->a20_mask;
	cpu->new_a20 = 0xFFFFFFFF ^ (!closed << 20);
	if (old_a20_mask != cpu->new_a20) {
		if (should_int) {
			cpu->raise_int_fn(&cpu->cpu_ctx, CPU_A20_INT);
		}
		else {
			cpu->a20_mask = cpu->new_a20;
			tc_clear_cache_and_tlb(cpu);
		}
	}
}

static void
cpu_force_suspend(cpu_t *cpu)
{
	cpu->suspend_flg.test_and_set();
	cpu->raise_int_fn(&cpu->cpu_ctx, CPU_SUSPEND_INT);
}

/*
* cpu_suspend -> submit a request to stop the cpu (this function is multi-thread safe)
* cpu: a valid cpu instance
* should_ret: true if the cpu thread should return from cpu_run/_until when paused, false if it should block instead
* ret: nothing
*/
void
cpu_suspend(cpu_t *cpu, bool should_ret)
{
	cpu->is_saving_state.wait(true);
	cpu->suspend_should_throw = should_ret;
	cpu_force_suspend(cpu);
}

/*
* cpu_resume -> submit a request to resume execution of the cpu (this function is multi-thread safe)
* cpu: a valid cpu instance
* ret: nothing
*/
void
cpu_resume(cpu_t *cpu)
{
	cpu->is_saving_state.wait(true);
	cpu->suspend_flg.clear();
	cpu->suspend_flg.notify_all();
}

/*
* cpu_is_suspended -> check is the cpu is actually suspended (this function is multi-thread safe)
* cpu: a valid cpu instance
* ret: true if the cpu is suspended, false otherwise
*/
bool
cpu_is_suspended(cpu_t *cpu)
{
	return cpu->is_suspended.test();
}

/*
* cpu_raise_hw_int -> raises the hardware interrupt line (this function is multi-thread safe)
* cpu: a valid cpu instance
* ret: nothing
*/
void
cpu_raise_hw_int_line(cpu_t *cpu)
{
	cpu->raise_int_fn(&cpu->cpu_ctx, CPU_HW_INT);
}

/*
* cpu_raise_hw_int -> lowers the hardware interrupt line (this function is multi-thread safe)
* cpu: a valid cpu instance
* ret: nothing
*/
void
cpu_lower_hw_int_line(cpu_t *cpu)
{
	cpu->clear_int_fn(&cpu->cpu_ctx, CPU_HW_INT);
}

template<bool is_save>
static lc86_status cpu_snapshot_handler(cpu_t *cpu, cpu_save_state_t *cpu_state, ram_save_state_t *ram_state, std::pair<fp_int, void *> int_data = { nullptr, nullptr })
{
	if (cpu->is_saving_state.test_and_set() == true) {
		cpu->is_saving_state.wait(true);
	}

	lc86_status ret;
	if (cpu->cpu_thr_id == std::this_thread::get_id()) {
		// We cannot safely save/load the cpu state from the cpu thread while it's running, because it could be executing code in the middle of a tc
		ret = set_last_error(lc86_status::internal_error);
	}
	else if (cpu->cpu_thr_id == std::thread::id()) {
		// We are called from the cpu thread while the cpu is not running, so we don't need to suspend the cpu
		if constexpr (is_save) {
			ret = cpu_save_state(cpu, cpu_state, ram_state);
		}
		else {
			ret = cpu_load_state(cpu, cpu_state, ram_state, int_data);
		}
	}
	else {
		// We are called from another thread, so we must suspend the cpu first
		bool curr_suspend_flg = cpu->suspend_flg.test();
		bool curr_suspend_should_throw = cpu->suspend_should_throw.load();
		if (!curr_suspend_flg) {
			cpu->suspend_should_throw = false;
			cpu_force_suspend(cpu);
		}
		while (cpu_is_suspended(cpu) == false) {
			std::this_thread::yield();
		}
		if constexpr (is_save) {
			ret = cpu_save_state(cpu, cpu_state, ram_state);
		}
		else {
			ret = cpu_load_state(cpu, cpu_state, ram_state, int_data);
			cpu->state_loaded = true;
		}
		if (!curr_suspend_flg) {
			cpu->suspend_should_throw = curr_suspend_should_throw;
			cpu_resume(cpu);
		}
	}

	cpu->is_saving_state.clear();
	cpu->is_saving_state.notify_all();

	return ret;
}

// NOTE1: these functions will fail if it is called from the cpu thread while it's executing guest code
// NOTE2: if the cpu thread is not running, then don't start it again until after these functions have returned, and don't call other APIs either

/*
* cpu_take_snapshot -> saves a snapshot of the cpu state (this function is multi-thread safe)
* cpu: a valid cpu instance
* cpu_state: a buffer that receives the saved cpu state (must be allocated by the client)
* ram_state: a buffer that receives the saved ram state (must be allocated by the client)
* ret: the status of the operation
*/
lc86_status
cpu_take_snapshot(cpu_t *cpu, cpu_save_state_t *cpu_state, ram_save_state_t *ram_state)
{
	return cpu_snapshot_handler<true>(cpu, cpu_state, ram_state);
}

// NOTE: this function will fail if it is called from the cpu thread while it's executing guest code

/*
* cpu_restore_snapshot -> restores a snapshot of the cpu state (this function is multi-thread safe)
* cpu: a valid cpu instance
* cpu_state: a buffer that receives the saved cpu state (must be allocated by the client)
* ram_state: a buffer that receives the saved ram state (must be allocated by the client)
* (optional) int_fn: a pair where 1st is a function that returns the vector number when a hw interrupt is serviced, and 2nd is an opaque argument passed to
* the function when lib86cpu calls it. Not necessary if you never generate hw interrupts
* ret: the status of the operation
*/
lc86_status
cpu_restore_snapshot(cpu_t *cpu, cpu_save_state_t *cpu_state, ram_save_state_t *ram_state, std::pair<fp_int, void *> int_data)
{
	return cpu_snapshot_handler<false>(cpu, cpu_state, ram_state, int_data);
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
#if XBOX_CPU
	return cpu->ram;
#else
	return cpu->ram.data();
#endif
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
		addr_t phys_addr = get_read_addr(cpu, addr, 0);
		const memory_region_t<addr_t>* region = as_memory_search_addr(cpu, phys_addr);

		switch (region->type)
		{
		case mem_type::ram:
			return static_cast<uint8_t *>(get_ram_host_ptr(cpu, region, phys_addr));

		case mem_type::rom:
			return static_cast<uint8_t *>(get_rom_host_ptr(region, phys_addr));
		}

		set_last_error(lc86_status::invalid_parameter);
		return nullptr;
	}
	catch (host_exp_t type) {
		assert((type == host_exp_t::pf_exp) || (type == host_exp_t::db_exp));
		set_last_error(lc86_status::guest_exp);
		return nullptr;
	}
}

// NOTE1: the maximum number of regions the system can have is 65536 - 1, because their indices are cached in the cached_region_idx vector of subpage_t, which is
// implemented with uint16_t, and there's always a nullptr cached at index zero. Additionally, the number of unmapped regions is variable, and depends of the number
// of merging and splitting events that involve unmapped regions in the address_space object. These are currently not tracked, which is why the memory APIs below
// don't track the number of regions currently added to the system.
// NOTE2: these functions will raise a guest interrupt when they detect the need to flush the code cache. You can suppress the interrupt and make them have effect
// immediately by passing should_int=false. This is only safe before you have called cpu_run/cpu_run_until to start the emulation, since at that point no code
// has been generated yet.

/*
* mem_init_region_ram -> creates a ram region
* cpu: a valid cpu instance
* start: the guest physical address where the ram starts
* size: size in bytes of ram
* should_int: raises a guest interrupt when true, otherwise the change takes effect immediately
* ret: the status of the operation
*/
lc86_status
mem_init_region_ram(cpu_t *cpu, addr_t start, uint32_t size, bool should_int)
{
	if (size == 0) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	std::unique_ptr<memory_region_t<addr_t>> ram(new memory_region_t<addr_t>);
	ram->start = ram->buff_off_start = start;
	ram->end = std::min(static_cast<uint64_t>(start) + size - 1, to_u64(0xFFFFFFFF));
	ram->type = mem_type::ram;

	if (should_int) {
		cpu->regions_changed.push_back(std::make_pair(true, std::move(ram)));
		cpu->raise_int_fn(&cpu->cpu_ctx, CPU_REGION_INT);
	}
	else {
		cpu->memory_space_tree->insert(std::move(ram));
		tc_clear_cache_and_tlb(cpu);
	}

	return lc86_status::success;
}

/*
* mem_init_region_io -> creates an mmio or pmio region
* cpu: a valid cpu instance
* start: where the region starts
* size: size of the region
* io_space: true for pmio, and false for mmio
* handlers: a struct of function pointers to call back when the region is accessed from the guest
* opaque: an arbitrary host pointer which is passed to the registered r/w function for the region
* should_int: raises a guest interrupt when true, otherwise the change takes effect immediately
* update: if 0, creates a new region. If 1, request an update to the handlers and the opaque member of an existing region that owns start. If 2,
* also request an interrupt to make visible the updated region to the cpu. When 3, only request the interrupt (the region arguments are ignored in this case).
* The last behaviour is useful to cache multiple update requests and only trigger the interrupt at the end. When not 0, should_int must be true.
* ret: the status of the operation
*/
lc86_status
mem_init_region_io(cpu_t *cpu, addr_t start, uint32_t size, bool io_space, io_handlers_t handlers, void *opaque, bool should_int, int update)
{
	if (update) {
		if (!should_int) {
			return set_last_error(lc86_status::invalid_parameter);
		}

		if ((update == 1) || (update == 2)) {
			if (io_space) {
				handlers.fnr8 = handlers.fnr8 ? handlers.fnr8 : default_pmio_read_handler8;
				handlers.fnr16 = handlers.fnr16 ? handlers.fnr16 : default_pmio_read_handler16;
				handlers.fnr32 = handlers.fnr32 ? handlers.fnr32 : default_pmio_read_handler32;
				handlers.fnw8 = handlers.fnw8 ? handlers.fnw8 : default_pmio_write_handler8;
				handlers.fnw16 = handlers.fnw16 ? handlers.fnw16 : default_pmio_write_handler16;
				handlers.fnw32 = handlers.fnw32 ? handlers.fnw32 : default_pmio_write_handler32;
			}
			else {
				handlers.fnr8 = handlers.fnr8 ? handlers.fnr8 : default_mmio_read_handler8;
				handlers.fnr16 = handlers.fnr16 ? handlers.fnr16 : default_mmio_read_handler16;
				handlers.fnr32 = handlers.fnr32 ? handlers.fnr32 : default_mmio_read_handler32;
				handlers.fnr64 = handlers.fnr64 ? handlers.fnr64 : default_mmio_read_handler64;
				handlers.fnw8 = handlers.fnw8 ? handlers.fnw8 : default_mmio_write_handler8;
				handlers.fnw16 = handlers.fnw16 ? handlers.fnw16 : default_mmio_write_handler16;
				handlers.fnw32 = handlers.fnw32 ? handlers.fnw32 : default_mmio_write_handler32;
				handlers.fnw64 = handlers.fnw64 ? handlers.fnw64 : default_mmio_write_handler64;
			}

			cpu->regions_updated.emplace_back(start, io_space, handlers, opaque);
			if (update == 2) {
				cpu->raise_int_fn(&cpu->cpu_ctx, CPU_HANDLER_INT);
			}
		}
		else if (update == 3) {
			cpu->raise_int_fn(&cpu->cpu_ctx, CPU_HANDLER_INT);
		}
		else {
			return set_last_error(lc86_status::invalid_parameter);
		}
	}
	else {
		if (size == 0) {
			return set_last_error(lc86_status::invalid_parameter);
		}

		if (io_space) {
			if ((start > 65535) || ((start + size) > 65536)) {
				return set_last_error(lc86_status::invalid_parameter);
			}

			std::unique_ptr<memory_region_t<port_t>> io(new memory_region_t<port_t>);
			io->start = static_cast<port_t>(start);
			uint64_t end_io1 = io->start + size - 1;
			io->end = std::min(end_io1, to_u64(0xFFFF));
			io->type = mem_type::pmio;
			io->handlers.fnr8 = handlers.fnr8 ? handlers.fnr8 : default_pmio_read_handler8;
			io->handlers.fnr16 = handlers.fnr16 ? handlers.fnr16 : default_pmio_read_handler16;
			io->handlers.fnr32 = handlers.fnr32 ? handlers.fnr32 : default_pmio_read_handler32;
			io->handlers.fnw8 = handlers.fnw8 ? handlers.fnw8 : default_pmio_write_handler8;
			io->handlers.fnw16 = handlers.fnw16 ? handlers.fnw16 : default_pmio_write_handler16;
			io->handlers.fnw32 = handlers.fnw32 ? handlers.fnw32 : default_pmio_write_handler32;
			io->opaque = opaque;

			cpu->io_space_tree->insert(std::move(io));
		}
		else {
			std::unique_ptr<memory_region_t<addr_t>> mmio(new memory_region_t<addr_t>);
			mmio->start = start;
			mmio->end = std::min(static_cast<uint64_t>(start) + size - 1, to_u64(0xFFFFFFFF));
			mmio->type = mem_type::mmio;
			mmio->handlers.fnr8 = handlers.fnr8 ? handlers.fnr8 : default_mmio_read_handler8;
			mmio->handlers.fnr16 = handlers.fnr16 ? handlers.fnr16 : default_mmio_read_handler16;
			mmio->handlers.fnr32 = handlers.fnr32 ? handlers.fnr32 : default_mmio_read_handler32;
			mmio->handlers.fnr64 = handlers.fnr64 ? handlers.fnr64 : default_mmio_read_handler64;
			mmio->handlers.fnw8 = handlers.fnw8 ? handlers.fnw8 : default_mmio_write_handler8;
			mmio->handlers.fnw16 = handlers.fnw16 ? handlers.fnw16 : default_mmio_write_handler16;
			mmio->handlers.fnw32 = handlers.fnw32 ? handlers.fnw32 : default_mmio_write_handler32;
			mmio->handlers.fnw64 = handlers.fnw64 ? handlers.fnw64 : default_mmio_write_handler64;
			mmio->opaque = opaque;

			if (should_int) {
				cpu->regions_changed.push_back(std::make_pair(true, std::move(mmio)));
				cpu->raise_int_fn(&cpu->cpu_ctx, CPU_REGION_INT);
			}
			else {
				cpu->memory_space_tree->insert(std::move(mmio));
				tc_clear_cache_and_tlb(cpu);
			}
		}
	}

	return lc86_status::success;
}

/*
* mem_init_region_alias -> creates a region that points to another region
* cpu: a valid cpu instance
* alias_start: the guest physical address where the alias starts
* ori_start: the guest physical address where the original region starts
* ori_size: size in bytes of alias
* should_int: raises a guest interrupt when true, otherwise the change takes effect immediately
* ret: the status of the operation
*/
lc86_status
mem_init_region_alias(cpu_t *cpu, addr_t alias_start, addr_t ori_start, uint32_t ori_size, bool should_int)
{
	if (ori_size == 0) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	auto aliased_region = const_cast<memory_region_t<addr_t> *>(cpu->memory_space_tree->search(ori_start));
	if ((aliased_region->start <= ori_start) && (aliased_region->end >= (ori_start + ori_size - 1)) && (aliased_region->type != mem_type::unmapped)) {
		std::unique_ptr<memory_region_t<addr_t>> alias(new memory_region_t<addr_t>);
		alias->start = alias_start;
		alias->end = std::min(static_cast<uint64_t>(alias_start) + ori_size - 1, to_u64(0xFFFFFFFF));
		alias->alias_offset = ori_start - aliased_region->start;
		alias->type = mem_type::alias;
		alias->aliased_region = aliased_region;

		if (should_int) {
			cpu->regions_changed.push_back(std::make_pair(true, std::move(alias)));
			cpu->raise_int_fn(&cpu->cpu_ctx, CPU_REGION_INT);
		}
		else {
			cpu->memory_space_tree->insert(std::move(alias));
			tc_clear_cache_and_tlb(cpu);
		}

		return lc86_status::success;
	}

	return set_last_error(lc86_status::invalid_parameter);
}

/*
* mem_init_region_rom -> creates a rom region
* cpu: a valid cpu instance
* start: the guest physical address where the rom starts
* size: size in bytes of rom
* buffer: a pointer to a client-allocated buffer that holds the rom the region refers to
*         In the xbox build, its contents are copied to an internal buffer and no longer used afterward
* should_int: raises a guest interrupt when true, otherwise the change takes effect immediately
* ret: the status of the operation
*/
lc86_status
mem_init_region_rom(cpu_t *cpu, addr_t start, uint32_t size, uint8_t *buffer, bool should_int)
{
	if ((size == 0) || !(buffer)) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	std::unique_ptr<memory_region_t<addr_t>> rom(new memory_region_t<addr_t>);
	rom->start = rom->buff_off_start = start;
	rom->end = std::min(static_cast<uint64_t>(start) + size - 1, to_u64(0xFFFFFFFF));
	rom->type = mem_type::rom;
	rom->rom_ptr = buffer;

#ifdef XBOX_CPU
	if ((start != FLASH_ROM_BASE) && (start != MCPX_ROM_BASE)) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	if (lc86_status status = ipt_rom_init(cpu, size, rom.get(), buffer); !LC86_SUCCESS(status)) {
		return status;
	}

	std::memcpy(rom->rom_ptr, buffer, size);
#endif

	if (should_int) {
		cpu->regions_changed.push_back(std::make_pair(true, std::move(rom)));
		cpu->raise_int_fn(&cpu->cpu_ctx, CPU_REGION_INT);
	}
	else {
		cpu->memory_space_tree->insert(std::move(rom));
		tc_clear_cache_and_tlb(cpu);
	}

	return lc86_status::success;
}

/*
* mem_destroy_region -> marks a range of addresses as unmapped
* cpu: a valid cpu instance
* start: the guest physical address where to start the unmapping
* size: size in bytes to unmap
* io_space: true for pmio, false for mmio and ignored for the other regions
* should_int: raises a guest interrupt when true, otherwise the change takes effect immediately
* ret: always success
*/
lc86_status
mem_destroy_region(cpu_t *cpu, addr_t start, uint32_t size, bool io_space, bool should_int)
{
	if (io_space) {
		port_t start_io = static_cast<port_t>(start);
		uint64_t end_io1 = start_io + size - 1;
		port_t end_io = std::min(end_io1, to_u64(0xFFFF));
		cpu->io_space_tree->erase(start_io, end_io);
	}
	else {
		addr_t end = std::min(static_cast<uint64_t>(start) + size - 1, to_u64(0xFFFFFFFF));
		if (should_int) {
			cpu->regions_changed.push_back(std::make_pair(false, std::make_unique<memory_region_t<addr_t>>(start, end)));
			cpu->raise_int_fn(&cpu->cpu_ctx, CPU_REGION_INT);
		}
		else {
			cpu->memory_space_tree->erase(start, end);
			tc_clear_cache_and_tlb(cpu);
		}
	}
	return lc86_status::success;
}

template<bool is_virt>
lc86_status mem_read_block(cpu_t *cpu, addr_t addr, uint32_t size, uint8_t *out, uint32_t *actual_size)
{
	uint32_t vec_offset = 0;
	uint32_t page_offset = addr & PAGE_MASK;
	uint32_t size_left = size;

	try {
		while (size_left > 0) {
			addr_t phys_addr;
			uint32_t bytes_to_read = std::min(PAGE_SIZE - page_offset, size_left);
			if constexpr (is_virt) {
				phys_addr = get_read_addr(cpu, addr, 0);
			}
			else {
				phys_addr = addr;
			}

			const memory_region_t<addr_t> *region = as_memory_search_addr(cpu, phys_addr);
			retry:
			if ((phys_addr >= region->start) && ((phys_addr + bytes_to_read - 1) <= region->end)) {
				switch (region->type)
				{
				case mem_type::ram:
					std::memcpy(out + vec_offset, get_ram_host_ptr(cpu, region, phys_addr), bytes_to_read);
					break;

				case mem_type::rom:
					std::memcpy(out + vec_offset, get_rom_host_ptr(region, phys_addr), bytes_to_read);
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
		assert((type == host_exp_t::pf_exp) || (type == host_exp_t::db_exp));
		if (actual_size) {
			*actual_size = vec_offset;
		}
		return set_last_error(lc86_status::guest_exp);
	}
}

/*
* mem_read_block -> reads a block of memory from ram/rom. Addr is either a virtual (_virt) or physical (_phys) guest address
* cpu: a valid cpu instance
* addr: the guest address to read from
* size: number of bytes to read
* out: pointer where the read contents are stored to
* actual_size: number of bytes actually read
* ret: the status of the operation
*/
lc86_status
mem_read_block_virt(cpu_t *cpu, addr_t addr, uint32_t size, uint8_t *out, uint32_t *actual_size)
{
	return mem_read_block<true>(cpu, addr, size, out, actual_size);
}

lc86_status
mem_read_block_phys(cpu_t *cpu, addr_t addr, uint32_t size, uint8_t *out, uint32_t *actual_size)
{
	return mem_read_block<false>(cpu, addr, size, out, actual_size);
}

template<bool fill, bool is_virt>
lc86_status mem_write_handler(cpu_t *cpu, addr_t addr, uint32_t size, const void *buffer, int val, uint32_t *actual_size)
{
	uint32_t size_tot = 0;
	uint32_t page_offset = addr & PAGE_MASK;
	uint32_t size_left = size;

	try {
		while (size_left > 0) {
			bool is_code;
			addr_t phys_addr;
			uint32_t bytes_to_write = std::min(PAGE_SIZE - page_offset, size_left);
			if constexpr (is_virt) {
				phys_addr = get_write_addr(cpu, addr, 0, &is_code);
				if (is_code) {
					tc_invalidate(&cpu->cpu_ctx, phys_addr, bytes_to_write);
				}
			}
			else {
				phys_addr = addr;
				tc_invalidate(&cpu->cpu_ctx, phys_addr, bytes_to_write);
			}

			const memory_region_t<addr_t> *region = as_memory_search_addr(cpu, phys_addr);
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
		assert((type == host_exp_t::pf_exp) || (type == host_exp_t::db_exp));
		if (actual_size) {
			*actual_size = size_tot;
		}
		return set_last_error(lc86_status::guest_exp);
	}
}

/*
* mem_write_block -> writes a block of memory to ram/rom. Addr is either a virtual (_virt) or physical (_phys) guest address
* cpu: a valid cpu instance
* addr: the guest virtual address to write to
* size: number of bytes to write
* buffer: pointer to a buffer that holds the bytes to write
* actual_size: number of bytes actually written
* ret: the status of the operation
*/
lc86_status
mem_write_block_virt(cpu_t *cpu, addr_t addr, uint32_t size, const void *buffer, uint32_t *actual_size)
{
	return mem_write_handler<false, true>(cpu, addr, size, buffer, 0, actual_size);
}

lc86_status
mem_write_block_phys(cpu_t *cpu, addr_t addr, uint32_t size, const void *buffer, uint32_t *actual_size)
{
	return mem_write_handler<false, false>(cpu, addr, size, buffer, 0, actual_size);
}

/*
* mem_fill_block -> fills ram/rom with a value. Addr is either a virtual (_virt) or physical (_phys) guest address
* cpu: a valid cpu instance
* addr: the guest address to write to
* size: number of bytes to write
* val: the value to write
* actual_size: number of bytes actually written
* ret: the status of the operation
*/
lc86_status
mem_fill_block_virt(cpu_t *cpu, addr_t addr, uint32_t size, int val, uint32_t *actual_size)
{
	return mem_write_handler<true, true>(cpu, addr, size, nullptr, val, actual_size);
}

lc86_status
mem_fill_block_phys(cpu_t *cpu, addr_t addr, uint32_t size, int val, uint32_t *actual_size)
{
	return mem_write_handler<true, false>(cpu, addr, size, nullptr, val, actual_size);
}

template<typename T>
static lc86_status io_read_handler(cpu_t *cpu, port_t port, T &out)
{
	try {
		out = io_read_helper<T>(&cpu->cpu_ctx, port);
		return lc86_status::success;
	}
	catch (host_exp_t type) {
		assert(type == host_exp_t::db_exp);
		return set_last_error(lc86_status::guest_exp);
	}
}

/*
* io_read_8/16/32 -> reads 8/16/32 bits from a pmio port
* cpu: a valid cpu instance
* port: the port to read from
* out: pointer where the read contents are stored to
* ret: the read value
*/
lc86_status
io_read_8(cpu_t *cpu, port_t port, uint8_t &out)
{
	return io_read_handler<uint8_t>(cpu, port, out);
}

lc86_status
io_read_16(cpu_t *cpu, port_t port, uint16_t &out)
{
	return io_read_handler<uint16_t>(cpu, port, out);
}

lc86_status
io_read_32(cpu_t *cpu, port_t port, uint32_t &out)
{
	return io_read_handler<uint32_t>(cpu, port, out);
}

template<typename T>
static lc86_status io_write_handler(cpu_t *cpu, port_t port, T val)
{
	try {
		io_write_helper<T>(&cpu->cpu_ctx, port, val);
		return lc86_status::success;
	}
	catch (host_exp_t type) {
		assert(type == host_exp_t::db_exp);
		return set_last_error(lc86_status::guest_exp);
	}
}

/*
* io_write_8/16/32 -> writes 8/16/32 bits to a pmio port
* cpu: a valid cpu instance
* port: the port to write to
* value: the value to write
* ret: the status of the operation
*/
lc86_status
io_write_8(cpu_t *cpu, port_t port, uint8_t value)
{
	return io_write_handler<uint8_t>(cpu, port, value);
}

lc86_status
io_write_16(cpu_t *cpu, port_t port, uint16_t value)
{
	return io_write_handler<uint16_t>(cpu, port, value);
}

lc86_status
io_write_32(cpu_t *cpu, port_t port, uint32_t value)
{
	return io_write_handler<uint32_t>(cpu, port, value);
}

/*
* tlb_invalidate -> flushes tlb entries for the specified page
* cpu: a valid cpu instance
* addr: the guest virtual address of the specified page
* ret: nothing
*/
void
tlb_invalidate(cpu_t *cpu, addr_t addr)
{
	// this relies on the fact that, even with the most restrictive permission type, if the entry is valid, then TLB_SUP_READ must be set. Note that more permissive
	// accesses will set additional permission bits in the entry, in addition to TLB_SUP_READ

	uint32_t idx = (addr >> PAGE_SHIFT) & ITLB_IDX_MASK;
	uint64_t tag = ((static_cast<uint64_t>(addr) << ITLB_TAG_SHIFT64) & ITLB_TAG_MASK64) | TLB_SUP_READ;
	for (unsigned i = 0; i < ITLB_NUM_LINES; ++i) {
		if (((cpu->itlb[idx][i].entry & (ITLB_TAG_MASK64 | TLB_SUP_READ)) ^ tag) == 0) {
			cpu->itlb[idx][i].entry = 0;
			cpu->itlb[idx][i].region = nullptr;
			break;
		}
	}
	idx = (addr >> PAGE_SHIFT) & DTLB_IDX_MASK;
	tag = ((static_cast<uint64_t>(addr) << DTLB_TAG_SHIFT64) & DTLB_TAG_MASK64) | TLB_SUP_READ;
	for (unsigned i = 0; i < DTLB_NUM_LINES; ++i) {
		if (((cpu->dtlb[idx][i].entry & (DTLB_TAG_MASK64 | TLB_SUP_READ)) ^ tag) == 0) {
			cpu->dtlb[idx][i].entry = 0;
			cpu->dtlb[idx][i].region = nullptr;
			break;
		}
	}

#ifdef XBOX_CPU
	// Page tables might have changed, so we must flush the affected entry in the ipt too
	ipt_flush(cpu, addr);
#endif

	// unlink all tc that jump to the invalidated page
	tc_unlink_page(cpu, addr);
}

/*
* hook_add -> adds a hook to intercept a guest function and redirect it to a host function
* cpu: a valid cpu instance
* addr: the virtual address of the first instruction of the guest function to intercept
* hook_addr: the address of the host function to call
* ret: the status of the operation
*/
lc86_status
hook_add(cpu_t *cpu, addr_t addr, hook_t hook_addr)
{
	// adds a host function that is called in place of the original guest function when pc reaches addr. The client is responsible for fetching the guest arguments
	// (if they need them) and fixing the guest stack/registers before the host function returns
	// NOTE: this hooks will only work when addr points to the first instruction of the hooked function (because we only check for hooks at the start
	// of the translation of a new code block)

	try {
		addr_t phys_addr = get_code_addr(cpu, addr);
		tc_invalidate(&cpu->cpu_ctx, phys_addr, 1);
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

	bool is_code;
	exp_data_t exp_data{0, 0, EXP_INVALID};
	uint32_t page_info;
	addr_t phys_addr = query_write_addr(cpu, addr, 2, &is_code, &exp_data, &page_info);
	if (exp_data.idx != EXP_INVALID) {
		return set_last_error(lc86_status::guest_exp);
	}
	cpu->hook_map.erase(it);
	tc_invalidate<true>(&cpu->cpu_ctx, phys_addr);

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
	// a trampoline calls the original guest function that was hooked, and it's only supposed to get called from the host function that hooked it.
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

/*
* read_ftag -> reads the current value of ftag
* cpu: a valid cpu instance
* ret: ftag
*/
uint16_t
read_ftags(cpu_t *cpu)
{
	uint16_t ftag = 0;
	for (unsigned i = 0; i < 8; ++i) {
		ftag |= (cpu->cpu_ctx.regs.ftags[i] << (i * 2));
	}
	return ftag;
}

/*
* write_ftag -> writes a new value to ftag
* cpu: a valid cpu instance
* value: the value to write
* ret: nothing
*/
void
write_ftags(cpu_t *cpu, uint16_t value)
{
	for (unsigned i = 0; i < 8; ++i) {
		uint16_t tag_val = value & (3 << (i * 2));
		cpu->cpu_ctx.regs.ftags[i] = tag_val >> (i * 2);
	}
}

/*
* read_fstatus -> reads the current value of fstatus
* cpu: a valid cpu instance
* ret: fstatus
*/
uint16_t
read_fstatus(cpu_t *cpu)
{
	uint16_t fstatus = (cpu->cpu_ctx.regs.fstatus & ~FPU_SW_TOP);
	fstatus |= (cpu->cpu_ctx.fpu_data.ftop << 11);
	return fstatus;
}

/*
* write_fstatus -> writes a new value to fstatus
* cpu: a valid cpu instance
* value: the value to write
* ret: nothing
*/
void
write_fstatus(cpu_t *cpu, uint16_t value)
{
	cpu->cpu_ctx.fpu_data.ftop = (value & FPU_SW_TOP) >> 11;
	cpu->cpu_ctx.regs.fstatus = value;
}
