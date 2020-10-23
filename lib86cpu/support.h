/*
 * common functions used by the library
 *
 * ergo720                Copyright (c) 2020
 */

#pragma once

#include "lib86cpu.h"


#define CPU_IGNORE_TC           (1 << 6)
#define CPU_DISAS_ONE           (1 << 7)
#define CPU_ALLOW_CODE_WRITE    (1 << 8)
#define CPU_FORCE_INSERT        (1 << 9)

#define CPU_INTEL_SYNTAX_SHIFT  1

#define CPU_NUM_REGS 33

#ifdef DEBUG_LOG
#define LOG(...) do { printf(__VA_ARGS__); } while(0)
#else
#define LOG(...)
#endif

#define LIB86CPU_ABORT() \
do {\
    char str[500];\
    std::snprintf(str, 500, "%s:%d: lib86cpu fatal error in function %s", __FILE__, __LINE__, __func__);\
    cpu_abort(static_cast<int32_t>(lc86_status::INTERNAL_ERROR), str);\
} while (0)

#define LIB86CPU_ABORT_msg(...) \
do {\
    char str[500];\
    std::snprintf(str, 500, __VA_ARGS__);\
    cpu_abort(static_cast<int32_t>(lc86_status::INTERNAL_ERROR), str);\
} while (0)


class lc86_exp_abort : public std::exception
{
public:
    explicit lc86_exp_abort(const std::string &msg, lc86_status status) : exception(msg.c_str()), code(status) {}
    explicit lc86_exp_abort(const char *msg, lc86_status status) : exception(msg), code(status) {}
    lc86_status get_code() { return code; }

private:
    lc86_status code;
};

void cpu_init(cpu_t *cpu);
lc86_status cpu_start(cpu_t *cpu);
[[noreturn]] void cpu_abort(int32_t code);
[[noreturn]] void cpu_abort(int32_t code, const char *msg);
std::string lc86status_to_str(lc86_status code);
lc86_status cpu_exec_trampoline(cpu_t *cpu, addr_t addr, hook *hook_ptr, std::any &ret, std::vector<std::any> &args);
