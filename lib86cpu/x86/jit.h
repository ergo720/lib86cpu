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
#include "lib86cpu.h"
#include "allocator.h"


using namespace orc;

class lib86cpu_jit {
public:
	static std::unique_ptr<lib86cpu_jit> create(cpu_t *cpu);
	ExecutionSession &getExecutionSession() { return *m_es; }
	JITDylib &get_main_jit_dylib() { return m_sym_table; }
	void add_ir_module(ThreadSafeModule tsm);

	Expected<JITEvaluatedSymbol> lookup_mangled(StringRef name);
	Expected<JITEvaluatedSymbol> lookup(StringRef unmangled_name) { return lookup_mangled(mangle(unmangled_name)); }
	Error run_constructors() { return m_ctor_runner.run(); }
	Error run_destructors() { return m_dtor_runner.run(); }
	RTDyldObjectLinkingLayer &get_obj_linking_layer() { return m_obj_linking_layer; }
	void remove_symbols(std::vector<std::string> &names);
	void free_code_block(void *addr);

private:
	lib86cpu_jit(std::unique_ptr<ExecutionSession> es, std::unique_ptr<TargetMachine> tm, DataLayout dl);
	std::string mangle(StringRef unmangled_name);
	Error apply_data_layout(Module &m);

	std::unique_ptr<ExecutionSession> m_es;
	JITDylib &m_sym_table;
	DataLayout m_dl;
	RTDyldObjectLinkingLayer m_obj_linking_layer;
	IRCompileLayer m_compile_layer;
	CtorDtorRunner m_ctor_runner, m_dtor_runner;
};
