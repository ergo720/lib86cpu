/*
 * linux memory functions
 *
 * ergo720                Copyright (c) 2023
 */

#pragma once


void *os_alloc(size_t size);
void os_free(void *addr, size_t size);
void os_flush_instr_cache(void *addr, void *end);
