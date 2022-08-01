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

#if !defined(_WIN64) && defined(_MSC_VER)

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

#endif

void
mem_mapper::destroy_all_blocks()
{
#if defined(_WIN64) && defined(_MSC_VER)
	for (const auto &load_addr : g_mapper.eh_frames) {
		RtlDeleteFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(load_addr));
	}

	for (auto &addr : blocks) {
		VirtualFree(addr, 0, MEM_RELEASE);
	}

	g_mapper.eh_frames.clear();
	blocks.clear();
	curr_pxdata_addr = 0;
	image_base = 0;
#else
	for (auto &addr : blocks) {
		VirtualFree(addr, 0, MEM_RELEASE);
	}

	for (auto &block : big_blocks) {
		VirtualFree(block.first, 0, MEM_RELEASE);
	}

	big_blocks.clear();
	blocks.clear();
	head = nullptr;
#endif
}

sys::MemoryBlock
mem_mapper::allocateMappedMemory(SectionMemoryManager::AllocationPurpose purpose, size_t num_bytes,
	const sys::MemoryBlock *const near_block, unsigned flags, std::error_code &ec)
{
	ec = std::error_code();
	if (num_bytes == 0) {
		return sys::MemoryBlock();
	}

#if defined(_WIN64) && defined(_MSC_VER)

	size_t block_size = (num_bytes + PAGE_MASK) & ~PAGE_MASK;

	// use PAGE_EXECUTE_READWRITE because we are called directly from mem_manager::allocateCodeSection, which causes llvm to skip the call to protectMappedMemory
	void *addr = VirtualAlloc(NULL, block_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (addr == NULL) {
		ec = mapWindowsError(GetLastError());
		return sys::MemoryBlock();
	}

	sys::MemoryBlock block(addr, block_size);
	if (flags & sys::Memory::ProtectionFlags::MF_EXEC) {
		sys::Memory::InvalidateInstructionCache(block.base(), block.allocatedSize());
	}

	blocks.push_back(addr);
	return block;

#else

	if (num_bytes > BLOCK_SIZE) {
		size_t block_size = (num_bytes + PAGE_MASK) & ~PAGE_MASK;

		void *addr = VirtualAlloc(NULL, block_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (addr == NULL) {
			ec = mapWindowsError(GetLastError());
			return sys::MemoryBlock();
		}

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

#endif
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

#if defined(_WIN64) && defined(_MSC_VER)

	// don't do anything because code sections are together with the pxdata sections; only delete them in destroy_all_blocks
	block = std::move(sys::MemoryBlock());
	return std::error_code();

#else

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

#endif
}

void
mem_mapper::free_block(const sys::MemoryBlock &block)
{
	// NOTE: we never uninstall the exception table when a code block is freed. This, because if we throw an exception from a helper called from the JIted
	// code, the stack frame of the caller must still be walked, and thus it needs the table

	void *addr = block.base();
	assert(block.allocatedSize() == 0);

#if defined(_WIN64) && defined(_MSC_VER)

	// don't do anything because code sections are together with the pxdata sections; only delete them in destroy_all_blocks
	return;

#else

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

#endif
}

#if defined(_WIN64) && defined(_MSC_VER)

#define PXDATA_OVERHEAD 300

uint8_t *
mem_manager::allocateCodeSection(uintptr_t Size, unsigned Alignment, unsigned SectionID, StringRef SectionName)
{
	// Windows requires that pdata sections are at an address higher than the function they refer to, and at an offset less than 2 GiB. To ensure this,
	// we will allocate extra memory for a code block so that we have enough space to store them at the top of the code section. Currently observed sizes
	// for xdata are 12, 16, 20, 24 bytes, and always 54 bytes for pdata

	if (SectionName == ".text") {
		uintptr_t aligned_size = Alignment * ((Size + PXDATA_OVERHEAD + Alignment - 1) / Alignment + 1);
		std::error_code ec;
		sys::MemoryBlock mb = g_mapper.allocateMappedMemory(AllocationPurpose::Code, aligned_size, nullptr, sys::Memory::MF_READ | sys::Memory::MF_WRITE, ec);
		uintptr_t aligned_addr = (reinterpret_cast<uintptr_t>(mb.base()) + Alignment - 1) & ~(uintptr_t)(Alignment - 1);
		g_mapper.image_base = aligned_addr;
		g_mapper.curr_pxdata_addr = reinterpret_cast<uintptr_t>(mb.base()) + mb.allocatedSize() - PXDATA_OVERHEAD;
		return reinterpret_cast<uint8_t *>(aligned_addr);
	}

	return llvm::SectionMemoryManager::allocateCodeSection(Size, Alignment, SectionID, SectionName);
}

uint8_t *
mem_manager::allocateDataSection(uintptr_t Size, unsigned Alignment, unsigned SectionID, StringRef SectionName, bool isReadOnly)
{
	if (SectionName == ".pdata") {
		assert(g_mapper.curr_pxdata_addr);
		uint8_t *pdata_addr = reinterpret_cast<uint8_t *>(g_mapper.curr_pxdata_addr);
		g_mapper.curr_pxdata_addr += (PXDATA_OVERHEAD / 2);
		return pdata_addr;
	}
	else if (SectionName == ".xdata") {
		assert(g_mapper.curr_pxdata_addr);
		uint8_t *xdata_addr = reinterpret_cast<uint8_t *>(g_mapper.curr_pxdata_addr);
		g_mapper.curr_pxdata_addr = 0;
		return xdata_addr;
	}

	return llvm::SectionMemoryManager::allocateDataSection(Size, Alignment, SectionID, SectionName, isReadOnly);
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
