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


mem_manager::block_header_t *
mem_manager::create_pool()
{
	block_header_t *start = static_cast<block_header_t *>(os_alloc(POOL_SIZE));
	block_header_t *addr = start;
	for (unsigned i = 0; i < BLOCKS_PER_POOL - 1; i++) {
		addr->next = reinterpret_cast<block_header_t *>(reinterpret_cast<uint8_t *>(addr) + BLOCK_SIZE);
		addr = addr->next;
	}

	addr->next = nullptr;
	blocks.emplace_back(start);
	return start;
}

void *
mem_manager::alloc()
{
	if (head == nullptr) {
		head = create_pool();
	}

	block_header_t *addr = head;
	head = head->next;
	return addr;
}

void
mem_manager::free(void *ptr)
{
	// this is necessary because we mark the code section memory as read-only after the code is written to it
	os_protect(ptr, BLOCK_SIZE, get_mem_flags(MEM_READ | MEM_WRITE));
	static_cast<block_header_t *>(ptr)->next = head;
	head = static_cast<block_header_t *>(ptr);
}

void
mem_manager::destroy_all_blocks()
{
#if defined(_WIN64) || defined(__linux__)
	for (const auto &eh_pair : eh_frames) {
		os_delete_exp_info(eh_pair.second);
	}

	eh_frames.clear();
#endif

#if defined(_WIN64)
	for (auto &addr : blocks) {
		os_free(addr);
	}

	for (auto &block : big_blocks) {
		os_free(block.first);
	}
#elif defined(__linux__)
	for (auto &addr : blocks) {
		os_free(addr, POOL_SIZE);
	}

	for (auto &block : big_blocks) {
		os_free(block.first, block.second);
	}
#endif

	big_blocks.clear();
	blocks.clear();
	head = nullptr;
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
		big_blocks.emplace(addr, block_size);
		return block;
	}

	return mem_block(alloc(), BLOCK_SIZE);
}

void
mem_manager::protect_sys_mem(const mem_block &block, unsigned flags)
{
	void *addr = block.addr;
	size_t size = block.size;

	if (addr == nullptr || size == 0) {
		return;
	}

	os_protect(addr, size, get_mem_flags(flags));

	if (flags & MEM_EXEC) {
#if defined(_WIN64)
		os_flush_instr_cache(addr, size);
#elif defined(__linux__)
		void *start = addr;
		void *end = static_cast<char *>(addr) + size;
		os_flush_instr_cache(start, end);
#endif
	}
}

void
mem_manager::release_sys_mem(void *addr)
{
	if (addr == nullptr) {
		return;
	}

#if defined(_WIN64)
	void *main_addr = reinterpret_cast<uint8_t *>(addr) + 16;
	if (auto it = eh_frames.find(main_addr); it != eh_frames.end()) {
		os_delete_exp_info(it->second);
		eh_frames.erase(main_addr);
	}
#endif
	
	if (auto it = big_blocks.find(addr); it != big_blocks.end()) {
#if defined(_WIN64)
		os_free(it->first);
#elif defined(__linux__)
		os_free(it->first, it->second);
#endif
		big_blocks.erase(addr);
		return;
	}

	free(addr);
}
