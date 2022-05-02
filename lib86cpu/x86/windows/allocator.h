/*
 * memory allocator for the jit
 *
 * ergo720                Copyright (c) 2020
 */

#pragma once

#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include <vector>
#include <map>

// for some reason the llvm file Target.h imported by SectionMemoryManager.h has a "inline" macro defined when using MSVC,
// which causes a compiler error in the inline below, so we undefine it
#ifdef inline
#undef inline
#endif

#define POOL_SIZE        (64 * 1024)             // 64 KiB
#define BLOCK_SIZE       (4 * 1024)              // 4 KiB
#define BLOCKS_PER_POOL  POOL_SIZE / BLOCK_SIZE  // 16

using namespace llvm;


class mem_manager final : public SectionMemoryManager::MemoryMapper {
public:
	sys::MemoryBlock allocateMappedMemory(SectionMemoryManager::AllocationPurpose purpose, size_t num_bytes,
		const sys::MemoryBlock *const near_block, unsigned flags, std::error_code &ec) override;
	std::error_code protectMappedMemory(const sys::MemoryBlock &block, unsigned flags) override;
	std::error_code releaseMappedMemory(sys::MemoryBlock &block) override;
	void free_block(const sys::MemoryBlock &block);
	~mem_manager() override;
	mem_manager() : head(nullptr) {}

private:
	struct block_header_t {
		block_header_t *next;
	};
	block_header_t *head;
	std::map<void *, size_t> big_blocks;
	std::vector<void *> blocks;
	block_header_t *create_pool();
	void *alloc();
	void free(void *ptr);
};

inline mem_manager g_mem_manager;
