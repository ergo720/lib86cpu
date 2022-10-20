/*
 * memory allocator for the jit
 *
 * ergo720                Copyright (c) 2020
 */

#include "lib86cpu_priv.h"
#include "internal.h"
#include "allocator.h"
#include "Windows.h"


DWORD
get_mem_flags(unsigned flags)
{
	switch (flags)
	{
	case MEM_READ:
		return PAGE_READONLY;

	case MEM_WRITE:
		return PAGE_READWRITE;

	case MEM_READ | MEM_WRITE:
		return PAGE_READWRITE;

	case MEM_READ | MEM_EXEC:
		return PAGE_EXECUTE_READ;

	case MEM_READ | MEM_WRITE | MEM_EXEC:
		return PAGE_EXECUTE_READWRITE;

	case MEM_EXEC:
		return PAGE_EXECUTE;

	default:
		LIB86CPU_ABORT();
	}

	return PAGE_NOACCESS;
}

mem_manager::block_header_t *
mem_manager::create_pool()
{
	block_header_t *start = static_cast<block_header_t *>(VirtualAlloc(NULL, POOL_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	if (start == NULL) {
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
	DWORD dummy;
	[[maybe_unused]] DWORD ret = VirtualProtect(ptr, BLOCK_SIZE, PAGE_READWRITE, &dummy);
	assert(ret);
	static_cast<block_header_t *>(ptr)->next = head;
	head = static_cast<block_header_t *>(ptr);
}

void
mem_manager::destroy_all_blocks()
{
#if defined(_WIN64)
	for (const auto &eh_pair : eh_frames) {
		RtlDeleteFunctionTable(static_cast<PRUNTIME_FUNCTION>(eh_pair.second));
	}

	eh_frames.clear();
#endif

	for (auto &addr : blocks) {
		VirtualFree(addr, 0, MEM_RELEASE);
	}

	for (auto &block : big_blocks) {
		VirtualFree(block.first, 0, MEM_RELEASE);
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

		void *addr = VirtualAlloc(NULL, block_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (addr == NULL) {
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

	DWORD dummy, prot = get_mem_flags(flags);
	[[maybe_unused]] auto ret = VirtualProtect(addr, size, prot, &dummy);
	assert(ret);

	if (flags & MEM_EXEC) {
		ret = FlushInstructionCache(GetCurrentProcess(), addr, size);
		assert(ret);
	}
}

void
mem_manager::release_sys_mem(void *addr)
{
	if (addr == nullptr) {
		return;
	}

#if defined(_WIN64)
	if (auto it = eh_frames.find(addr); it != eh_frames.end()) {
		[[maybe_unused]] auto ret = RtlDeleteFunctionTable(static_cast<PRUNTIME_FUNCTION>(it->second));
		assert(ret);
		eh_frames.erase(addr);
	}
#endif
	
	if (auto it = big_blocks.find(addr); it != big_blocks.end()) {
		[[maybe_unused]] auto ret = VirtualFree(it->first, 0, MEM_RELEASE);
		assert(ret);
		big_blocks.erase(addr);
		return;
	}

	free(addr);
}
