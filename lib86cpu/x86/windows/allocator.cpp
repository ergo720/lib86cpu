/*
 * memory allocator for the jit
 *
 * ergo720                Copyright (c) 2020
 */

#include "lib86cpu_priv.h"
#include "internal.h"
#include "allocator.h"
#include "llvm/Support/WindowsError.h"
#include "Windows.h"


DWORD
get_mem_flags(unsigned flags)
{
	switch (flags)
	{
	case sys::Memory::MF_READ:
		return PAGE_READONLY;

	case sys::Memory::MF_WRITE:
		return PAGE_READWRITE;

	case sys::Memory::MF_READ | sys::Memory::MF_WRITE:
		return PAGE_READWRITE;

	case sys::Memory::MF_READ | sys::Memory::MF_EXEC:
		return PAGE_EXECUTE_READ;

	case sys::Memory::MF_READ | sys::Memory::MF_WRITE | sys::Memory::MF_EXEC:
		return PAGE_EXECUTE_READWRITE;

	case sys::Memory::MF_EXEC:
		return PAGE_EXECUTE;

	default:
		LIB86CPU_ABORT();
	}

	return PAGE_NOACCESS;
}

mem_mapper::block_header_t *
mem_mapper::create_pool()
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
mem_mapper::alloc()
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
mem_mapper::free(void *ptr)
{
	// this is necessary because llvm marks the code section memory as read-only after the code is written to it
	DWORD dummy;
	[[maybe_unused]] DWORD ret = VirtualProtect(ptr, BLOCK_SIZE, PAGE_READWRITE, &dummy);
	assert(ret);
	static_cast<block_header_t *>(ptr)->next = head;
	head = static_cast<block_header_t *>(ptr);
}

void
mem_mapper::destroy_all_blocks()
{
#if defined(_WIN64) && defined(_MSC_VER)
	for (const auto &load_addr : g_mapper.eh_frames) {
		RtlDeleteFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(load_addr));
	}
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

sys::MemoryBlock
mem_mapper::allocateMappedMemory(SectionMemoryManager::AllocationPurpose purpose, size_t num_bytes,
	const sys::MemoryBlock *const near_block, unsigned flags, std::error_code &ec)
{
	ec = std::error_code();
	if (num_bytes == 0) {
		return sys::MemoryBlock();
	}

	if (num_bytes > BLOCK_SIZE) {
		void *addr = VirtualAlloc(NULL, num_bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (addr == NULL) {
			ec = mapWindowsError(GetLastError());
			return sys::MemoryBlock();
		}

		size_t block_size = (num_bytes + 0xFFF) & ~0xFFF;
		sys::MemoryBlock block(addr, block_size);
		if (flags & sys::Memory::ProtectionFlags::MF_EXEC) {
			sys::Memory::InvalidateInstructionCache(block.base(), block.allocatedSize());
		}

		big_blocks.emplace(addr, block_size);
		return block;
	}

	void *addr = alloc();
	if (addr == nullptr) {
		ec = mapWindowsError(ERROR_NOT_ENOUGH_MEMORY);
		return sys::MemoryBlock();
	}

	sys::MemoryBlock block(addr, BLOCK_SIZE);
	if (flags & sys::Memory::ProtectionFlags::MF_EXEC) {
		sys::Memory::InvalidateInstructionCache(block.base(), block.allocatedSize());
	}

	return block;
}

std::error_code
mem_mapper::protectMappedMemory(const sys::MemoryBlock &block, unsigned flags)
{
	void *addr = block.base();
	size_t size = block.allocatedSize();

	if (addr == nullptr || size == 0) {
		return std::error_code();
	}

	DWORD dummy, prot = get_mem_flags(flags);
	if (!VirtualProtect(addr, size, prot, &dummy)) {
		return mapWindowsError(GetLastError());
	}

	if (flags & sys::Memory::ProtectionFlags::MF_EXEC) {
		sys::Memory::InvalidateInstructionCache(addr, size);
	}

	return std::error_code();
}

std::error_code
mem_mapper::releaseMappedMemory(sys::MemoryBlock &block)
{
	void *addr = block.base();
	size_t size = block.allocatedSize();

	if (addr == 0 || size == 0) {
		return std::error_code();
	}

	if (size > BLOCK_SIZE) {
		auto it = big_blocks.find(addr);
		if (it != big_blocks.end()) {
			if (!VirtualFree(it->first, 0, MEM_RELEASE)) {
				return mapWindowsError(::GetLastError());
			}

			big_blocks.erase(addr);
		}

		// this can happen when this is called from ~SectionMemoryManager. If the iterator is end(), it means the block was
		// already freed with a previous call of free_block(), and thus we don't need to do anything
		block = std::move(sys::MemoryBlock());
		return std::error_code();
	}

	free(addr);
	block = std::move(sys::MemoryBlock());
	return std::error_code();
}

void
mem_mapper::free_block(const sys::MemoryBlock &block)
{
	// NOTE: we never uninstall the exception table when a code block is freed. This, because if we throw an exception from a helper called from the JIted
	// code, the stack frame of the caller must still be walked, and thus it needs the table

	void *addr = block.base();
	assert(block.allocatedSize() == 0);

	if (addr == 0) {
		return;
	}

	auto it = big_blocks.find(addr);
	if (it != big_blocks.end()) {
		[[maybe_unused]] BOOL ret = VirtualFree(it->first, 0, MEM_RELEASE);
		assert(ret);
		big_blocks.erase(addr);
		return;
	}

	free(addr);
}

#if defined(_WIN64) && defined(_MSC_VER)

uint8_t *
mem_manager::allocateCodeSection(uintptr_t Size, unsigned Alignment, unsigned SectionID, StringRef SectionName)
{
	uint8_t *allocated = llvm::SectionMemoryManager::allocateCodeSection(Size, Alignment, SectionID, SectionName);
	if (SectionName == ".text") {
		g_mapper.image_base = reinterpret_cast<uint64_t>(allocated);
	}
	return allocated;
}

void
mem_manager::registerEHFrames(uint8_t *Addr, uint64_t LoadAddr, size_t Size)
{
	if (g_mapper.image_base && (LoadAddr > g_mapper.image_base)) {
		RtlAddFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(LoadAddr), Size / sizeof(RUNTIME_FUNCTION), g_mapper.image_base);
		g_mapper.eh_frames.push_back(LoadAddr);
	}
}

void
mem_manager::deregisterEHFrames()
{
	for (const auto &load_addr : g_mapper.eh_frames) {
		RtlDeleteFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(load_addr));
	}
	g_mapper.eh_frames.clear();
}

#endif
