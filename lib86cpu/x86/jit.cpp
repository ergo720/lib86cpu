/*
 * lib86cpu jit implementation
 *
 * ergo720                Copyright (c) 2020
 */

#include "llvm/Support/TargetSelect.h"
#include "jit.h"
#include "memory.h"


class tm_owning_simple_compiler : public SimpleCompiler {
public:
	tm_owning_simple_compiler(std::unique_ptr<TargetMachine> tm)
		: SimpleCompiler(*tm), m_tm(std::move(tm)) {}
private:
	std::shared_ptr<TargetMachine> m_tm;
};

std::unique_ptr<lc86_jit>
lc86_jit::create(cpu_t *cpu)
{
	// init llvm
	InitializeNativeTarget();
	InitializeNativeTargetAsmParser();
	InitializeNativeTargetAsmPrinter();

#if defined(_WIN32) && defined(_MSC_VER)
	// using detectHost on win32 will select a default "i686-pc-windows-msvc" triple, which is wrong since this will use
	// MM_WinCOFF mangling mode, while we want MM_WinCOFFX86 for 32 bit targets. This, in turn, will cause a function
	// name mangling failure later when we try to mangle functions which use fastcall or stdcall calling conventions in the hooks.
	// Because of this, we construct the triple ourselves instead of using the default one.
	// NOTE: I'm not sure if non-msvc compilers are affected as well.

	auto jtmb = orc::JITTargetMachineBuilder(Triple("i686-pc-windows-msvc-coff"));
#else
	auto ret = orc::JITTargetMachineBuilder::detectHost();
	if (!ret) {
		LIB86CPU_ABORT();
	}
	auto jtmb = *ret;
#endif

	SubtargetFeatures features;
	StringMap<bool> host_features;
	if (sys::getHostCPUFeatures(host_features))
		for (auto &F : host_features) {
			features.AddFeature(F.first(), F.second);
		}
	jtmb.setCPU(sys::getHostCPUName())
		.addFeatures(features.getFeatures())
		.setRelocationModel(None)
		.setCodeModel(None);
	auto dl = jtmb.getDefaultDataLayoutForTarget();
	if (!dl) {
		LIB86CPU_ABORT();
	}
	cpu->dl = new DataLayout(*dl);
	if (cpu->dl == nullptr) {
		LIB86CPU_ABORT();
	}
	auto tm = jtmb.createTargetMachine();
	if (!tm) {
		LIB86CPU_ABORT();
	}

	return std::unique_ptr<lc86_jit>(new lc86_jit(std::make_unique<ExecutionSession>(), std::move(*tm), std::move(*dl)));
}

lc86_jit::lc86_jit(std::unique_ptr<ExecutionSession> es, std::unique_ptr<TargetMachine> tm, DataLayout dl) :
	m_es(std::move(es)),
	m_sym_table(this->m_es->getMainJITDylib()),
	m_dl(std::move(dl)),
	m_obj_linking_layer(
		*this->m_es,
		[this]() { return std::make_unique<SectionMemoryManager>(&g_mem_manager); }),
	m_compile_layer(*this->m_es, m_obj_linking_layer, tm_owning_simple_compiler(std::move(tm))),
	m_ctor_runner(m_sym_table),
	m_dtor_runner(m_sym_table)
{
	m_sym_table.setGenerator(*orc::DynamicLibrarySearchGenerator::GetForCurrentProcess(m_dl));
	define_absolute(mangle("mem_read8"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mem_read8), JITSymbolFlags::Absolute));
	define_absolute(mangle("mem_read16"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mem_read16), JITSymbolFlags::Absolute));
	define_absolute(mangle("mem_read32"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mem_read32), JITSymbolFlags::Absolute));
	define_absolute(mangle("mem_read64"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mem_read64), JITSymbolFlags::Absolute));
	define_absolute(mangle("mem_write8"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mem_write8), JITSymbolFlags::Absolute));
	define_absolute(mangle("mem_write16"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mem_write16), JITSymbolFlags::Absolute));
	define_absolute(mangle("mem_write32"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mem_write32), JITSymbolFlags::Absolute));
	define_absolute(mangle("mem_write64"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mem_write64), JITSymbolFlags::Absolute));
	define_absolute(mangle("io_read8"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&io_read8), JITSymbolFlags::Absolute));
	define_absolute(mangle("io_read16"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&io_read16), JITSymbolFlags::Absolute));
	define_absolute(mangle("io_read32"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&io_read32), JITSymbolFlags::Absolute));
	define_absolute(mangle("io_write8"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&io_write8), JITSymbolFlags::Absolute));
	define_absolute(mangle("io_write16"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&io_write16), JITSymbolFlags::Absolute));
	define_absolute(mangle("io_write32"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&io_write32), JITSymbolFlags::Absolute));
	define_absolute(mangle("tc_invalidate"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&tc_invalidate), JITSymbolFlags::Absolute));
	define_absolute(mangle("cpu_update_crN"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&cpu_update_crN), JITSymbolFlags::Absolute));
	define_absolute(mangle("cpu_rdtsc_handler"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&cpu_rdtsc_handler), JITSymbolFlags::Absolute));
	define_absolute(mangle("cpu_msr_read"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&cpu_msr_read), JITSymbolFlags::Absolute));
	define_absolute(mangle("cpu_runtime_abort"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&cpu_runtime_abort), JITSymbolFlags::Absolute));

#ifdef _WIN32
	// workaround for llvm bug D65548
	m_obj_linking_layer.setOverrideObjectFlagsWithResponsibilityFlags(true);
#endif
}

void
lc86_jit::add_ir_module(ThreadSafeModule tsm)
{
	assert(tsm && "Can not add null module");

	if (apply_data_layout(*tsm.getModule())) {
		LIB86CPU_ABORT();
	}

	if (m_compile_layer.add(m_sym_table, std::move(tsm), m_es->allocateVModule())) {
		LIB86CPU_ABORT();
	}
}

Expected<JITEvaluatedSymbol>
lc86_jit::lookup_mangled(StringRef name)
{
	return m_es->lookup(JITDylibSearchList({ {&m_sym_table, true} }), m_es->intern(name));
}

std::string
lc86_jit::mangle(StringRef unmangled_name)
{
	std::string mangled_name;
	{
		raw_string_ostream mangled_name_stream(mangled_name);
		Mangler::getNameWithPrefix(mangled_name_stream, unmangled_name, m_dl);
	}

	return mangled_name;
}

Error
lc86_jit::apply_data_layout(Module &m)
{
	if (m.getDataLayout().isDefault()) {
		m.setDataLayout(m_dl);
	}

	if (m.getDataLayout() != m_dl) {
		return make_error<StringError>(
			"Added modules have incompatible data layouts",
			inconvertibleErrorCode());
	}

	return Error::success();
}

void
lc86_jit::remove_symbols(const std::vector<std::string> &names)
{
	MangleAndInterner mangle(*m_es, m_dl);
	orc::SymbolNameSet module_symbol_names;
	for (const auto &str : names) {
		module_symbol_names.insert(mangle(str));
	}
	[[maybe_unused]] auto err = m_sym_table.remove(module_symbol_names);
	assert(!err);
}

Error
lc86_jit::define_absolute(StringRef name, JITEvaluatedSymbol sym)
{
	auto interned_name = m_es->intern(name);
	SymbolMap symbols({ {interned_name, sym} });
	return m_sym_table.define(absoluteSymbols(std::move(symbols)));
}

std::string
lc86_jit::mangle(Function *func)
{
	std::string mangled;
	raw_string_ostream ss(mangled);
	m_mangler.getNameWithPrefix(ss, func, false);
	ss.flush();
	return mangled;
}

void
lc86_jit::free_code_block(void *addr)
{
	// based on the llvm sources and observed behaviour, the ptr_code of the tc is exactly the same addr that was initially allocated
	// by allocateMappedMemory, so this will work in practice. Also note that our custom pool allocator uses a fixed block size, and thus
	// it implicitly knows the size of the allocation
	g_mem_manager.free_block(sys::MemoryBlock(addr, 0));
}
