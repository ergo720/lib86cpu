/*
 * lib86cpu jit implementation
 *
 * ergo720                Copyright (c) 2020
 */

#include "jit.h"


class tm_owning_simple_compiler : public SimpleCompiler {
public:
	tm_owning_simple_compiler(std::unique_ptr<TargetMachine> tm)
		: SimpleCompiler(*tm), m_tm(std::move(tm)) {}
private:
	std::shared_ptr<TargetMachine> m_tm;
};

std::unique_ptr<lib86cpu_jit>
lib86cpu_jit::create(cpu_t *cpu) {
	auto jtmb = orc::JITTargetMachineBuilder::detectHost();
	if (!jtmb) {
		LIB86CPU_ABORT();
	}
	SubtargetFeatures features;
	StringMap<bool> host_features;
	if (sys::getHostCPUFeatures(host_features))
		for (auto &F : host_features) {
			features.AddFeature(F.first(), F.second);
		}
	jtmb->setCPU(sys::getHostCPUName())
		.addFeatures(features.getFeatures())
		.setRelocationModel(None)
		.setCodeModel(None);
	auto dl = jtmb->getDefaultDataLayoutForTarget();
	if (!dl) {
		LIB86CPU_ABORT();
	}
	cpu->dl = new DataLayout(*dl);
	if (cpu->dl == nullptr) {
		LIB86CPU_ABORT();
	}
	auto tm = jtmb->createTargetMachine();
	if (!tm) {
		LIB86CPU_ABORT();
	}

	return std::unique_ptr<lib86cpu_jit>(new lib86cpu_jit(std::make_unique<ExecutionSession>(), std::move(*tm), std::move(*dl)));
}

lib86cpu_jit::lib86cpu_jit(std::unique_ptr<ExecutionSession> es, std::unique_ptr<TargetMachine> tm, DataLayout dl) :
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

#ifdef _WIN32
	// workaround for llvm bug D65548
	m_obj_linking_layer.setOverrideObjectFlagsWithResponsibilityFlags(true);
#endif
}

void
lib86cpu_jit::add_ir_module(ThreadSafeModule tsm) {
	assert(tsm && "Can not add null module");

	if (apply_data_layout(*tsm.getModule())) {
		LIB86CPU_ABORT();
	}

	if (m_compile_layer.add(m_sym_table, std::move(tsm), m_es->allocateVModule())) {
		LIB86CPU_ABORT();
	}
}

Expected<JITEvaluatedSymbol>
lib86cpu_jit::lookup_mangled(StringRef name) {
	return m_es->lookup(JITDylibSearchList({ {&m_sym_table, true} }), m_es->intern(name));
}

std::string
lib86cpu_jit::mangle(StringRef unmangled_name) {
	std::string mangled_name;
	{
		raw_string_ostream mangled_name_stream(mangled_name);
		Mangler::getNameWithPrefix(mangled_name_stream, unmangled_name, m_dl);
	}

	return mangled_name;
}

Error
lib86cpu_jit::apply_data_layout(Module &m) {
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
lib86cpu_jit::remove_symbols(std::vector<std::string> &names)
{
	MangleAndInterner mangle(*m_es, m_dl);
	orc::SymbolNameSet module_symbol_names;
	for (const auto &str : names) {
		module_symbol_names.insert(mangle(str));
	}
	[[maybe_unused]] auto err = m_sym_table.remove(module_symbol_names);
	assert(!err);
}

void
lib86cpu_jit::free_code_block(void *addr)
{
	// based on the llvm sources and observed behaviour, the ptr_code of the tc is exactly the same addr that was initially allocated
	// by allocateMappedMemory, so this will work in practice. Also note that our custom pool allocator uses a fixed block size, and thus
	// it implicitly knows the size of the allocation
	g_mem_manager.releaseMappedMemory(sys::MemoryBlock(addr, 1));
}
