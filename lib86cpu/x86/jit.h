/*
 * lib86cpu jit class
 *
 * ergo720                Copyright (c) 2020
 */

#pragma once

#include "llvm/ExecutionEngine/Orc/CompileOnDemandLayer.h"
#include "llvm/ExecutionEngine/Orc/CompileUtils.h"
#include "llvm/ExecutionEngine/Orc/ExecutionUtils.h"
#include "llvm/ExecutionEngine/Orc/IRCompileLayer.h"
#include "llvm/ExecutionEngine/Orc/IRTransformLayer.h"
#include "llvm/ExecutionEngine/Orc/JITTargetMachineBuilder.h"
#include "llvm/ExecutionEngine/Orc/ObjectTransformLayer.h"
#include "llvm/ExecutionEngine/Orc/RTDyldObjectLinkingLayer.h"
#include "llvm/ExecutionEngine/Orc/ThreadSafeModule.h"
#include "llvm/IR/Mangler.h"
#include "lib86cpu.h"
#include "allocator.h"


using namespace orc;

class lc86_jit {
public:
	~lc86_jit();
	static std::unique_ptr<lc86_jit> create(cpu_t *cpu);
	ExecutionSession &getExecutionSession() { return *m_es; }
	JITDylib &get_main_jit_dylib() { return m_sym_table; }
	void add_ir_module(ThreadSafeModule tsm);

	Expected<JITEvaluatedSymbol> lookup_mangled(StringRef name);
	Expected<JITEvaluatedSymbol> lookup(StringRef unmangled_name) { return lookup_mangled(mangle(unmangled_name)); }
	RTDyldObjectLinkingLayer &get_obj_linking_layer() { return m_obj_linking_layer; }
	void remove_symbols(const std::vector<std::string> &names);
	void remove_symbols(const std::string &names);
	Error define_absolute(StringRef name, JITEvaluatedSymbol sym);
	std::string mangle(Function *func);
	void free_code_block(void *addr);

private:
	lc86_jit(std::unique_ptr<ExecutionSession> es, JITTargetMachineBuilder jtmb, DataLayout dl);
	std::string mangle(StringRef unmangled_name);

	std::unique_ptr<ExecutionSession> m_es;
	JITDylib &m_sym_table;
	DataLayout m_dl;
	RTDyldObjectLinkingLayer m_obj_linking_layer;
	IRCompileLayer m_compile_layer;
	Mangler m_mangler;
	ResourceTrackerSP m_rt;
};
