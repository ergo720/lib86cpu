/*
 * memory allocator for the jit
 *
 * ergo720                Copyright (c) 2023
 */

#include "lib86cpu_priv.h"
#include "internal.h"
#include "allocator.h"
#include <sys/mman.h>


extern "C" {
	void __deregister_frame(void *);
}

static int
get_mem_flags(unsigned flags)
{
	switch (flags)
	{
	case MEM_READ:
		return PROT_READ;

	case MEM_WRITE:
		return PROT_WRITE;

	case MEM_READ | MEM_WRITE:
		return PROT_READ | PROT_WRITE;

	case MEM_READ | MEM_EXEC:
		return PROT_READ | PROT_EXEC;

	case MEM_READ | MEM_WRITE | MEM_EXEC:
		return PROT_READ | PROT_WRITE | PROT_EXEC;

	case MEM_EXEC:
		return PROT_READ | PROT_EXEC;

	default:
		LIB86CPU_ABORT();
	}

	return PROT_NONE;
}

mem_manager::block_header_t *
mem_manager::create_pool()
{
	block_header_t *start = static_cast<block_header_t *>(mmap(NULL, POOL_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
	if (start == MAP_FAILED) {
		return nullptr;
	}

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
		if (head == nullptr) {
			return nullptr;
		}
	}

	block_header_t *addr = head;
	head = head->next;
	return addr;
}

void
mem_manager::free(void *ptr)
{
	// this is necessary because we mark the code section memory as read-only after the code is written to it
	[[maybe_unused]] int ret = mprotect(ptr, BLOCK_SIZE, PROT_READ | PROT_WRITE);
	assert(!ret);
	static_cast<block_header_t *>(ptr)->next = head;
	head = static_cast<block_header_t *>(ptr);
}

void
mem_manager::destroy_all_blocks()
{
	for (const auto &eh_pair : eh_frames) {
		__deregister_frame(eh_pair.second);
	}

	eh_frames.clear();

	for (auto &addr : blocks) {
		munmap(addr, POOL_SIZE);
	}

	for (auto &block : big_blocks) {
		munmap(block.first, block.second);
	}
	
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

		void *addr = mmap(NULL, block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		if (addr == MAP_FAILED) {
			return mem_block();
		}

		mem_block block(addr, block_size);
		big_blocks.emplace(addr, block_size);
		return block;
	}

	void *addr = alloc();
	if (addr == nullptr) {
		return mem_block();
	}

	return mem_block(addr, BLOCK_SIZE);
}

void
mem_manager::protect_sys_mem(const mem_block &block, unsigned flags)
{
	void *addr = block.addr;
	size_t size = block.size;

	if (addr == nullptr || size == 0) {
		return;
	}

	int prot = get_mem_flags(flags);
	[[maybe_unused]] auto ret = mprotect(addr, size, prot);
	assert(!ret);

	if (flags & MEM_EXEC) {
		void *start = addr;
		void *end = static_cast<char *>(addr) + size;
		__builtin___clear_cache(start, end);
	}
}

void
mem_manager::release_sys_mem(void *addr)
{
	if (addr == nullptr) {
		return;
	}
	
	void *main_addr = reinterpret_cast<uint8_t *>(addr) + 16;
	if (auto it = eh_frames.find(main_addr); it != eh_frames.end()) {
		__deregister_frame(it->second);
		eh_frames.erase(main_addr);
	}

	if (auto it = big_blocks.find(addr); it != big_blocks.end()) {
		[[maybe_unused]] auto ret = munmap(it->first, it->second);
		assert(!ret);
		big_blocks.erase(addr);
		return;
	}

	free(addr);
}
