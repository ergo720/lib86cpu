/*
 * x86 llvm frontend exports to translator
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once

#define _CTX() (*tc->ctx)


Function *create_tc_prologue(cpu_t *cpu, translated_code_t *tc);
Function *create_tc_epilogue(cpu_t *cpu, translated_code_t *tc, Function *func, disas_ctx_t *disas_ctx);
void optimize(translated_code_t *tc, Function *func);
