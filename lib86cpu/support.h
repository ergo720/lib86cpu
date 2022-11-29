/*
 * common functions used by the library
 *
 * ergo720                Copyright (c) 2020
 */

#pragma once

#include "lib86cpu_priv.h"
#include "endianness.h"


#define CPU_DISAS_ONE           (1 << 7)
#define CPU_ALLOW_CODE_WRITE    (1 << 8)
#define CPU_FORCE_INSERT        (1 << 9)
#define CPU_SINGLE_STEP         (1 << 10)

#define CPU_NUM_REGS 43

#define NUM_VARGS(...) std::tuple_size<decltype(std::make_tuple(__VA_ARGS__))>::value

#define LOG(lv, msg, ...) do { logfn(lv, NUM_VARGS(__VA_ARGS__), msg, __VA_ARGS__); } while(0)

#define LIB86CPU_ABORT() \
do {\
    cpu_abort(static_cast<int32_t>(lc86_status::internal_error), "%s:%d: lib86cpu fatal error in function %s", __FILE__, __LINE__, __func__);\
} while (0)

#define LIB86CPU_ABORT_msg(msg, ...) \
do {\
    cpu_abort(static_cast<int32_t>(lc86_status::internal_error), msg, __VA_ARGS__);\
} while (0)


class lc86_exp_abort : public std::exception
{
public:
    explicit lc86_exp_abort(const std::string &msg, lc86_status status) : exception(msg.c_str()), status(status) {}
    explicit lc86_exp_abort(const char *msg, lc86_status status) : exception(msg), status(status) {}
    lc86_status get_code() { return status; }

private:
    lc86_status status;
};

void cpu_reset(cpu_t *cpu);
lc86_status cpu_start(cpu_t *cpu);
[[noreturn]] void cpu_runtime_abort(const char *msg);
[[noreturn]] void cpu_abort(int32_t code, const char *msg, ...);
std::string lc86status_to_str(lc86_status status);
void discard_log(log_level lv, const unsigned count, const char *msg, ...);
lc86_status set_last_error(lc86_status status);
void cpu_exec_trampoline(cpu_t *cpu, const uint32_t ret_eip);

inline logfn_t logfn = &discard_log;
inline std::string last_error = "";
