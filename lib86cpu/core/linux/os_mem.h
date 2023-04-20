/*
 * linux memory functions
 *
 * ergo720                Copyright (c) 2023
 */

#pragma once


int get_mem_flags(unsigned flags);
void *os_alloc(size_t size);
void os_free(void *addr, size_t size);
void os_protect(void *addr, size_t size, int prot);
void os_flush_instr_cache(void *addr, void *end);
