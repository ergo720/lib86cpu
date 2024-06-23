/*
 * memory allocator for the jit
 *
 * ergo720                Copyright (c) 2020
 */

#include "lib86cpu_priv.h"
#include "internal.h"
#include "allocator.h"
#include "os_mem.h"
#include "os_exceptions.h"


mem_manager::mem_manager()
{
	m_code_block_area = os_alloc(CODE_CACHE_MAX_SIZE * BLOCK_SIZE + BLOCK_SIZE); // 32768 code blocks + another one for aux functions
	init_pool();
}

void
mem_manager::init_pool()
{
	block_header_t *addr = static_cast<block_header_t *>(m_code_block_area);
	m_head = addr;
	for (unsigned i = 0; i < CODE_CACHE_MAX_SIZE - 1; ++i) {
		addr->next = reinterpret_cast<block_header_t *>(reinterpret_cast<uint8_t *>(addr) + BLOCK_SIZE);
		addr = addr->next;
	}
	addr->next = nullptr;
}

void *
mem_manager::alloc()
{
	assert(m_head);
	block_header_t *addr = m_head;
	m_head = m_head->next;
	return addr;
}

void
mem_manager::free(void *ptr)
{
	static_cast<block_header_t *>(ptr)->next = m_head;
	m_head = static_cast<block_header_t *>(ptr);
}

void
mem_manager::destroy_all_blocks()
{
#if defined(_WIN64) || defined(__linux__)
	for (const auto &eh_pair : m_eh_frames) {
		os_delete_exp_info(eh_pair.second);
	}

	m_eh_frames.clear();
#endif

#if defined(_WIN64)
	for (auto &block : m_big_blocks) {
		os_free(block.first);
	}
#elif defined(__linux__)
	for (auto &block : m_big_blocks) {
		os_free(block.first, block.second);
	}
#endif

	init_pool();
	m_big_blocks.clear();
}

void
mem_manager::purge_all_blocks()
{
	destroy_all_blocks();
#if defined(_WIN64)
	os_free(m_code_block_area);
#elif defined(__linux__)
	os_free(m_code_block_area, CODE_CACHE_MAX_SIZE * BLOCK_SIZE + BLOCK_SIZE);
#endif
}

mem_block
mem_manager::allocate_sys_mem(size_t num_bytes)
{
	if (num_bytes == 0) {
		return mem_block();
	}

	if (num_bytes > BLOCK_SIZE) {
		size_t block_size = (num_bytes + PAGE_MASK) & ~PAGE_MASK;
		void *addr = os_alloc(block_size);
		mem_block block(addr, block_size);
		m_big_blocks.emplace(addr, block_size);
		return block;
	}

	return mem_block(alloc(), BLOCK_SIZE);
}

mem_block
mem_manager::get_non_pooled_sys_mem(size_t num_bytes)
{
	if (num_bytes == 0) {
		return mem_block();
	}

	return mem_block(reinterpret_cast<uint8_t *>(m_code_block_area) + CODE_CACHE_MAX_SIZE * BLOCK_SIZE, BLOCK_SIZE);
}

void
mem_manager::flush_instr_cache(const mem_block &block)
{
	void *addr = block.addr;
	size_t size = block.size;

	if (addr == nullptr || size == 0) {
		return;
	}

#if defined(_WIN64)
	os_flush_instr_cache(addr, size);
#elif defined(__linux__)
	void *start = addr;
	void *end = static_cast<char *>(addr) + size;
	os_flush_instr_cache(start, end);
#endif
}

void
mem_manager::release_sys_mem(void *addr)
{
	if (addr == nullptr) {
		return;
	}

#if defined(_WIN64) || defined(__linux__)
	void *main_addr = reinterpret_cast<uint8_t *>(addr) + 16;
	if (auto it = m_eh_frames.find(main_addr); it != m_eh_frames.end()) {
		os_delete_exp_info(it->second);
		m_eh_frames.erase(main_addr);
	}
#endif
	
	if (auto it = m_big_blocks.find(addr); it != m_big_blocks.end()) {
#if defined(_WIN64)
		os_free(it->first);
#elif defined(__linux__)
		os_free(it->first, it->second);
#endif
		m_big_blocks.erase(addr);
		return;
	}

	free(addr);
}
