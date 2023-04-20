/*
 * windows memory functions
 *
 * ergo720                Copyright (c) 2023
 */

#pragma once


unsigned get_mem_flags(unsigned flags);
void *os_alloc(size_t size);
void os_free(void *addr);
void os_protect(void *addr, size_t size, unsigned prot);
void os_flush_instr_cache(void *addr, size_t size);
