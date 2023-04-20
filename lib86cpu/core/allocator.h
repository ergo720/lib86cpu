/*
 * memory allocator for the jit
 *
 * ergo720                Copyright (c) 2020
 */

#pragma once

#include <vector>
#include <map>

#define POOL_SIZE        (64 * 1024)             // 64 KiB
#define BLOCK_SIZE       (4 * 1024)              // 4 KiB
#define BLOCKS_PER_POOL  POOL_SIZE / BLOCK_SIZE  // 16

#define MEM_READ  (1 << 0)
#define MEM_WRITE (1 << 1)
#define MEM_EXEC  (1 << 2)


struct mem_block {
	void *addr;
	size_t size;
	mem_block() : addr(nullptr), size(0ULL) {}
	mem_block(void *addr, size_t size) : addr(addr), size(size) {}
};

class mem_manager {
public:
	mem_block allocate_sys_mem(size_t num_bytes);
	void protect_sys_mem(const mem_block &block, unsigned flags);
	void release_sys_mem(void *addr);
	void destroy_all_blocks();
	~mem_manager() { destroy_all_blocks(); }

#if defined(_WIN64) || defined(__linux__)
	std::map<void *, void *> eh_frames;
#endif

private:
	struct block_header_t {
		block_header_t *next;
	};
	block_header_t *head = nullptr;
	std::vector<void *> blocks;
	std::map<void *, size_t> big_blocks;

	block_header_t *create_pool();
	void *alloc();
	void free(void *ptr);
};
