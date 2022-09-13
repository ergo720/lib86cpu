/*
 * lib86cpu jit implementation
 *
 * ergo720                Copyright (c) 2020
 */

#include "llvm/Support/TargetSelect.h"
#include "jit.h"
#include "memory.h"
#include "debugger.h"
#include "instructions.h"
#include "frontend.h"


std::unique_ptr<lc86_jit>
lc86_jit::create(cpu_t *cpu)
{
	// init llvm
	InitializeNativeTarget();
	InitializeNativeTargetAsmParser();
	InitializeNativeTargetAsmPrinter();

	// JITTargetMachineBuilder::detectHost is not reliable because of this comment in the LLVM sources: "getProcessTriple is bogus. It returns the host LLVM
	// was compiled on, rather than a valid triple for the current process.", so we always construct the triple ourselves

#if defined(_WIN64) && defined(_MSC_VER)
	auto jtmb = orc::JITTargetMachineBuilder(Triple("x86_64-pc-windows-msvc-coff"));
#elif defined(_WIN32) && defined(_MSC_VER)
	auto jtmb = orc::JITTargetMachineBuilder(Triple("i686-pc-windows-msvc-coff"));
#else
#error Unknow LLVM triple
#endif

	SubtargetFeatures features;
	StringMap<bool> host_features;
	if (sys::getHostCPUFeatures(host_features))
		for (auto &F : host_features) {
			features.AddFeature(F.first(), F.second);
		}
	jtmb.setCPU(sys::getHostCPUName().str())
		.addFeatures(features.getFeatures())
		.setRelocationModel(None)
		.setCodeModel(None);

	// We use the fast instruction selector to reduce compile time at the cost of producing poorer code
	auto opt = jtmb.getOptions();
	opt.EnableFastISel = true;
	jtmb.setOptions(opt);

	auto dl = jtmb.getDefaultDataLayoutForTarget();
	if (!dl) {
		LIB86CPU_ABORT();
	}
	cpu->dl = new DataLayout(*dl);
	if (cpu->dl == nullptr) {
		LIB86CPU_ABORT();
	}
	auto epc = SelfExecutorProcessControl::Create();
	if (!epc) {
		LIB86CPU_ABORT();
	}

	return std::unique_ptr<lc86_jit>(new lc86_jit(std::make_unique<ExecutionSession>(std::move(*epc)), jtmb, std::move(*dl)));
}

lc86_jit::lc86_jit(std::unique_ptr<ExecutionSession> es, JITTargetMachineBuilder jtmb, DataLayout dl) :
	m_es(std::move(es)),
	m_sym_table(this->m_es->createBareJITDylib("main")),
	m_dl(std::move(dl)),
	m_obj_linking_layer(
		*this->m_es,
		[this]() { return std::make_unique<mem_manager>(); }),
	m_compile_layer(*this->m_es, m_obj_linking_layer, std::make_unique<ConcurrentIRCompiler>(std::move(jtmb))),
	m_rt(m_sym_table.getDefaultResourceTracker())
{
	m_sym_table.addGenerator(std::move(*orc::DynamicLibrarySearchGenerator::GetForCurrentProcess(m_dl.getGlobalPrefix())));
	define_absolute(mangle("mem_read_helper8"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mem_read_helper<uint8_t>), JITSymbolFlags::Absolute));
	define_absolute(mangle("mem_read_helper16"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mem_read_helper<uint16_t>), JITSymbolFlags::Absolute));
	define_absolute(mangle("mem_read_helper32"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mem_read_helper<uint32_t>), JITSymbolFlags::Absolute));
	define_absolute(mangle("mem_read_helper64"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mem_read_helper<uint64_t>), JITSymbolFlags::Absolute));
	define_absolute(mangle("mem_write_helper8"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mem_write_helper<uint8_t>), JITSymbolFlags::Absolute));
	define_absolute(mangle("mem_write_helper16"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mem_write_helper<uint16_t>), JITSymbolFlags::Absolute));
	define_absolute(mangle("mem_write_helper32"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mem_write_helper<uint32_t>), JITSymbolFlags::Absolute));
	define_absolute(mangle("mem_write_helper64"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mem_write_helper<uint64_t>), JITSymbolFlags::Absolute));
	define_absolute(mangle("io_read8"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&io_read8), JITSymbolFlags::Absolute));
	define_absolute(mangle("io_read16"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&io_read16), JITSymbolFlags::Absolute));
	define_absolute(mangle("io_read32"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&io_read32), JITSymbolFlags::Absolute));
	define_absolute(mangle("io_write8"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&io_write8), JITSymbolFlags::Absolute));
	define_absolute(mangle("io_write16"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&io_write16), JITSymbolFlags::Absolute));
	define_absolute(mangle("io_write32"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&io_write32), JITSymbolFlags::Absolute));
	define_absolute(mangle("link_indirect_handler"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&link_indirect_handler), JITSymbolFlags::Absolute));
	define_absolute(mangle("update_crN_helper"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&update_crN_helper), JITSymbolFlags::Absolute));
	define_absolute(mangle("cpu_rdtsc_handler"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&cpu_rdtsc_handler), JITSymbolFlags::Absolute));
	define_absolute(mangle("msr_read_helper"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&msr_read_helper), JITSymbolFlags::Absolute));
	define_absolute(mangle("cpu_runtime_abort"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&cpu_runtime_abort), JITSymbolFlags::Absolute));
	define_absolute(mangle("dbg_update_bp_hook"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&dbg_update_exp_hook), JITSymbolFlags::Absolute));
	define_absolute(mangle("cpu_raise_exception_isInt"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&cpu_raise_exception<true>), JITSymbolFlags::Absolute));
	define_absolute(mangle("cpu_raise_exception"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&cpu_raise_exception<false>), JITSymbolFlags::Absolute));
	define_absolute(mangle("iret_pe_helper"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&lret_pe_helper<true>), JITSymbolFlags::Absolute));
	define_absolute(mangle("lret_pe_helper"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&lret_pe_helper<false>), JITSymbolFlags::Absolute));
	define_absolute(mangle("iret_real_helper"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&iret_real_helper), JITSymbolFlags::Absolute));
	define_absolute(mangle("ljmp_pe_helper"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&ljmp_pe_helper), JITSymbolFlags::Absolute));
	define_absolute(mangle("lcall_pe_helper"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&lcall_pe_helper), JITSymbolFlags::Absolute));
	define_absolute(mangle("verr_helper"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&verrw_helper<true>), JITSymbolFlags::Absolute));
	define_absolute(mangle("verw_helper"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&verrw_helper<false>), JITSymbolFlags::Absolute));
	define_absolute(mangle("mov_ds_pe_helper"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mov_sel_pe_helper<DS_idx>), JITSymbolFlags::Absolute));
	define_absolute(mangle("mov_es_pe_helper"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mov_sel_pe_helper<ES_idx>), JITSymbolFlags::Absolute));
	define_absolute(mangle("mov_ss_pe_helper"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mov_sel_pe_helper<SS_idx>), JITSymbolFlags::Absolute));
	define_absolute(mangle("mov_fs_pe_helper"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mov_sel_pe_helper<FS_idx>), JITSymbolFlags::Absolute));
	define_absolute(mangle("mov_gs_pe_helper"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&mov_sel_pe_helper<GS_idx>), JITSymbolFlags::Absolute));
	define_absolute(mangle("ltr_helper"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&ltr_helper), JITSymbolFlags::Absolute));
	define_absolute(mangle("lldt_helper"), JITEvaluatedSymbol(reinterpret_cast<uintptr_t>(&lldt_helper), JITSymbolFlags::Absolute));

#ifdef _WIN32
	// workaround for llvm bug D65548 and https://github.com/llvm/llvm-project/issues/43682
	m_obj_linking_layer.setOverrideObjectFlagsWithResponsibilityFlags(true);
	m_obj_linking_layer.setAutoClaimResponsibilityForObjectSymbols(true);
#endif
}

lc86_jit::~lc86_jit()
{
	[[maybe_unused]] auto err = m_es->endSession();
	assert(!err);
}

void
lc86_jit::add_ir_module(ThreadSafeModule tsm)
{
	assert(tsm && "Can not add null module");

	if (m_compile_layer.add(m_rt, std::move(tsm))) {
		LIB86CPU_ABORT();
	}
}

Expected<JITEvaluatedSymbol>
lc86_jit::lookup_mangled(StringRef name)
{
	return m_es->lookup(&m_sym_table, m_es->intern(name));
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

void
lc86_jit::remove_symbols(const std::string &names)
{
	MangleAndInterner mangle(*m_es, m_dl);
	orc::SymbolNameSet module_symbol_names;
	module_symbol_names.insert(mangle(names));
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
	g_mapper.free_block(sys::MemoryBlock(addr, 0));
}
