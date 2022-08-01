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


class mem_manager;
class mem_mapper final : public SectionMemoryManager::MemoryMapper {
public:
	friend class mem_manager;
	sys::MemoryBlock allocateMappedMemory(SectionMemoryManager::AllocationPurpose purpose, size_t num_bytes,
		const sys::MemoryBlock *const near_block, unsigned flags, std::error_code &ec) override;
	std::error_code protectMappedMemory(const sys::MemoryBlock &block, unsigned flags) override;
	std::error_code releaseMappedMemory(sys::MemoryBlock &block) override;
	void free_block(const sys::MemoryBlock &block);
	void destroy_all_blocks();
	~mem_mapper() override {}

private:
	std::vector<void *> blocks;

#if defined(_WIN64) && defined(_MSC_VER)
	// NOTE: these variables should really belong to mem_manager, but llvm destroys the SectionMemoryManager object after the emission of every code block,
	// which means we would lose them, so we instead keep them here

	uintptr_t image_base = 0;
	std::vector<uintptr_t> eh_frames;
	uintptr_t curr_pxdata_addr = 0;
#else
	struct block_header_t {
		block_header_t *next;
	};
	block_header_t *head = nullptr;
	std::map<void *, size_t> big_blocks;

	block_header_t *create_pool();
	void *alloc();
	void free(void *ptr);
#endif
};

inline mem_mapper g_mapper;

class mem_manager final : public SectionMemoryManager {
public:
#if defined(_WIN64) && defined(_MSC_VER)
	uint8_t *allocateCodeSection(uintptr_t Size, unsigned Alignment, unsigned SectionID, StringRef SectionName) override;
	uint8_t *allocateDataSection(uintptr_t Size, unsigned Alignment, unsigned SectionID, StringRef SectionName, bool isReadOnly) override;
	void registerEHFrames(uint8_t *Addr, uint64_t LoadAddr, size_t Size) override;
	void deregisterEHFrames() override;
#endif
	mem_manager() : SectionMemoryManager(&g_mapper) {}
};
