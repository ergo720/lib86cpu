/*
 * common functions used by the library
 *
 * ergo720                Copyright (c) 2020
 */

#pragma once

#include "lib86cpu_priv.h"
#include "endianness.h"


// these flags are ORed with the flags in lib86cpu.h, so avoid conflicts
#define CPU_TIMEOUT             (1 << 3)
#define CPU_INHIBIT_DBG_TRAP    (1 << 4)
#define CPU_DISAS_ONE           (1 << 7)
#define CPU_ALLOW_CODE_WRITE    (1 << 8)
#define CPU_FORCE_INSERT        (1 << 9)
#define CPU_SINGLE_STEP         (1 << 10)
#define CPU_SAVED_FLG_MASK      (CPU_SYNTAX_MASK | CPU_ABORT_ON_HLT)

#define CPU_NUM_REGS 43

#define NUM_VARGS(...) std::tuple_size<decltype(std::make_tuple(__VA_ARGS__))>::value

#define LOG(lv, msg, ...) do { logfn(lv, NUM_VARGS(__VA_ARGS__), msg __VA_OPT__(,) __VA_ARGS__); } while(0)

#define LIB86CPU_ABORT() \
do {\
    cpu_abort(static_cast<int32_t>(lc86_status::internal_error), "%s:%d: lib86cpu fatal error in function %s", __FILE__, __LINE__, __func__);\
} while (0)

#define LIB86CPU_ABORT_msg(msg, ...) \
do {\
    cpu_abort(static_cast<int32_t>(lc86_status::internal_error), msg __VA_OPT__(,) __VA_ARGS__);\
} while (0)


class lc86_exp_abort : public std::runtime_error
{
public:
    explicit lc86_exp_abort(const std::string &msg, lc86_status status) : runtime_error(msg.c_str()), status(status) {}
    explicit lc86_exp_abort(const char *msg, lc86_status status) : runtime_error(msg), status(status) {}
    lc86_status get_code() { return status; }

private:
    lc86_status status;
};

void cpu_reset(cpu_t *cpu);
template<bool run_forever>
lc86_status cpu_start(cpu_t *cpu);
[[noreturn]] JIT_API void cpu_runtime_abort(const char *msg);
[[noreturn]] void cpu_abort(int32_t code, const char *msg, ...);
void discard_log(log_level lv, const unsigned count, const char *msg, ...);
lc86_status set_last_error(lc86_status status);
void cpu_exec_trampoline(cpu_t *cpu, const uint32_t ret_eip);
bool verify_cpu_features();
uint16_t default_get_int_vec(void *opaque);
lc86_status cpu_save_state(cpu_t *cpu, cpu_save_state_t *cpu_state, ram_save_state_t *ram_state);
lc86_status cpu_load_state(cpu_t *cpu, cpu_save_state_t *cpu_state, ram_save_state_t *ram_state, std::pair<fp_int, void *> int_data);
uint64_t muldiv128(uint64_t a, uint64_t b, uint64_t c);

inline uint64_t
to_u64(auto val)
{
    return static_cast<uint64_t>(val);
}

inline logfn_t logfn = &discard_log;
inline std::string last_error = "The operation completed successfully";

template<typename T>
consteval const char *get_prix_prefix()
{
	if constexpr (sizeof(T) == 1) {
		return PRIX8;
	}
	else if constexpr (sizeof(T) == 2) {
		return PRIX16;
	}
	else if constexpr (sizeof(T) == 4) {
		return PRIX32;
	}
	else if constexpr (sizeof(T) == 8) {
		return PRIX64;
	}
	else {
		return "";
	}
}

template<typename T, mem_type type>
void log_unhandled_write(addr_t addr, T value)
{
	if constexpr ((sizeof(T) == 10) || (sizeof(T) == 16)) {
		constexpr size_t val_high_digits = sizeof(T) == 10 ? 4 : 16;
		using type_high_digits = std::conditional_t<sizeof(T) == 10, uint16_t, uint64_t>;
		type_high_digits high = value.high;
		uint64_t low = value.low;
		if constexpr (type == mem_type::unmapped) {
			LOG(log_level::warn, ("Memory write of value high=0x%0" + std::to_string(val_high_digits) + get_prix_prefix<type_high_digits>() + " and low=0x%016" PRIX64 " to \
unmapped memory at address 0x%08" PRIX32 " with size %" PRId32).c_str(),
				high, low, addr, sizeof(T));
		}
		else {
			LOG(log_level::warn, ("Unhandled mmio write of value high=0x%0" + std::to_string(val_high_digits) + get_prix_prefix<type_high_digits>() + " and low=0x%016" PRIX64 " at \
address 0x%08" PRIX32 " with size %" PRId32).c_str(),
				high, low, addr, sizeof(T));
		}
	}
	else {
		constexpr size_t val_digits = sizeof(T) * 2;
		if constexpr (type == mem_type::unmapped) {
			LOG(log_level::warn, ("Memory write of value 0x%0" + std::to_string(val_digits) + get_prix_prefix<T>() + " to unmapped memory at address 0x%08" PRIX32 " with size %" PRId32).c_str(),
				value, addr, sizeof(T));
		}
		else if constexpr (type == mem_type::mmio) {
			LOG(log_level::warn, ("Unhandled mmio write of value 0x%0" + std::to_string(val_digits) + get_prix_prefix<T>() + " at address 0x%08" PRIX32 " with size %" PRId32).c_str(),
				value, addr, sizeof(T));
		}
		else {
			LOG(log_level::warn, ("Unhandled pmio write of value 0x%0" + std::to_string(val_digits) + get_prix_prefix<T>() + " at port 0x%04" PRIX16 " with size %" PRId32).c_str(),
				value, addr, sizeof(T));
		}
	}
}

template<typename T, mem_type type>
T log_unhandled_read(addr_t addr)
{
	if constexpr ((sizeof(T) == 10) || (sizeof(T) == 16)) {
		if constexpr (type == mem_type::unmapped) {
			LOG(log_level::warn, "Memory read to unmapped memory at address 0x%08" PRIX32 " with size %" PRId32, addr, sizeof(T));
		}
		else {
			LOG(log_level::warn, "Unhandled mmio read at address 0x%08" PRIX32 " with size %" PRId32, addr, sizeof(T));
		}
		return T();
	}
	else {
		constexpr size_t val_digits = sizeof(T) * 2 + 2;
		if constexpr (type == mem_type::unmapped) {
			LOG(log_level::warn, "Memory read to unmapped memory at address 0x%08" PRIX32 " with size %" PRId32, addr, sizeof(T));
		}
		else if constexpr (type == mem_type::mmio) {
			LOG(log_level::warn, "Unhandled mmio read at address 0x%08" PRIX32 " with size %" PRId32, addr, sizeof(T));
		}
		else {
			LOG(log_level::warn, "Unhandled pmio read at port 0x%04" PRIX16 " with size %" PRId32, addr, sizeof(T));
		}
		return 0;
	}
}
