/*
 * shared functions among all emitters
 *
 * ergo720                Copyright (c) 2022
 */

#include "emitter_common.h"


static const std::unordered_map<ZydisRegister, size_t> zydis_to_reg_offset_table = {
	{ ZYDIS_REGISTER_AL,          CPU_CTX_EAX() },
	{ ZYDIS_REGISTER_CL,          CPU_CTX_ECX() },
	{ ZYDIS_REGISTER_DL,          CPU_CTX_EDX() },
	{ ZYDIS_REGISTER_BL,          CPU_CTX_EBX() },
	{ ZYDIS_REGISTER_AH,          CPU_CTX_EAX() + 1 },
	{ ZYDIS_REGISTER_CH,          CPU_CTX_ECX() + 1 },
	{ ZYDIS_REGISTER_DH,          CPU_CTX_EDX() + 1 },
	{ ZYDIS_REGISTER_BH,          CPU_CTX_EBX() + 1 },
	{ ZYDIS_REGISTER_AX,          CPU_CTX_EAX() },
	{ ZYDIS_REGISTER_CX,          CPU_CTX_ECX() },
	{ ZYDIS_REGISTER_DX,          CPU_CTX_EDX() },
	{ ZYDIS_REGISTER_BX,          CPU_CTX_EBX() },
	{ ZYDIS_REGISTER_SP,          CPU_CTX_ESP() },
	{ ZYDIS_REGISTER_BP,          CPU_CTX_EBP() },
	{ ZYDIS_REGISTER_SI,          CPU_CTX_ESI() },
	{ ZYDIS_REGISTER_DI,          CPU_CTX_EDI() },
	{ ZYDIS_REGISTER_EAX,         CPU_CTX_EAX() },
	{ ZYDIS_REGISTER_ECX,         CPU_CTX_ECX() },
	{ ZYDIS_REGISTER_EDX,         CPU_CTX_EDX() },
	{ ZYDIS_REGISTER_EBX,         CPU_CTX_EBX() },
	{ ZYDIS_REGISTER_ESP,         CPU_CTX_ESP() },
	{ ZYDIS_REGISTER_EBP,         CPU_CTX_EBP() },
	{ ZYDIS_REGISTER_ESI,         CPU_CTX_ESI() },
	{ ZYDIS_REGISTER_EDI,         CPU_CTX_EDI() },
	{ ZYDIS_REGISTER_ES,          CPU_CTX_ES() },
	{ ZYDIS_REGISTER_CS,          CPU_CTX_CS() },
	{ ZYDIS_REGISTER_SS,          CPU_CTX_SS() },
	{ ZYDIS_REGISTER_DS,          CPU_CTX_DS() },
	{ ZYDIS_REGISTER_FS,          CPU_CTX_FS() },
	{ ZYDIS_REGISTER_GS,          CPU_CTX_GS() },
	{ ZYDIS_REGISTER_CR0,         CPU_CTX_CR0() },
	{ ZYDIS_REGISTER_CR1,         CPU_CTX_CR1() },
	{ ZYDIS_REGISTER_CR2,         CPU_CTX_CR2() },
	{ ZYDIS_REGISTER_CR3,         CPU_CTX_CR3() },
	{ ZYDIS_REGISTER_CR4,         CPU_CTX_CR4() },
	{ ZYDIS_REGISTER_DR0,         CPU_CTX_DR0() },
	{ ZYDIS_REGISTER_DR1,         CPU_CTX_DR1() },
	{ ZYDIS_REGISTER_DR2,         CPU_CTX_DR2() },
	{ ZYDIS_REGISTER_DR3,         CPU_CTX_DR3() },
	{ ZYDIS_REGISTER_DR4,         CPU_CTX_DR4() },
	{ ZYDIS_REGISTER_DR5,         CPU_CTX_DR5() },
	{ ZYDIS_REGISTER_DR6,         CPU_CTX_DR6() },
	{ ZYDIS_REGISTER_DR7,         CPU_CTX_DR7() },
	{ ZYDIS_REGISTER_EFLAGS,      CPU_CTX_EFLAGS() },
	{ ZYDIS_REGISTER_EIP,         CPU_CTX_EIP() },
	{ ZYDIS_REGISTER_IDTR,        CPU_CTX_IDTR() },
	{ ZYDIS_REGISTER_GDTR,        CPU_CTX_GDTR() },
	{ ZYDIS_REGISTER_LDTR,        CPU_CTX_LDTR() },
	{ ZYDIS_REGISTER_TR,          CPU_CTX_TR() },
	{ ZYDIS_REGISTER_MM0,         CPU_CTX_MM0() },
	{ ZYDIS_REGISTER_MM1,         CPU_CTX_MM1() },
	{ ZYDIS_REGISTER_MM2,         CPU_CTX_MM2() },
	{ ZYDIS_REGISTER_MM3,         CPU_CTX_MM3() },
	{ ZYDIS_REGISTER_MM4,         CPU_CTX_MM4() },
	{ ZYDIS_REGISTER_MM5,         CPU_CTX_MM5() },
	{ ZYDIS_REGISTER_MM6,         CPU_CTX_MM6() },
	{ ZYDIS_REGISTER_MM7,         CPU_CTX_MM7() },
	{ ZYDIS_REGISTER_X87STATUS,   CPU_CTX_ST() },
	{ ZYDIS_REGISTER_X87TAG,      CPU_CTX_TAG() },
};

size_t
get_reg_offset(ZydisRegister reg)
{
	if (auto it = zydis_to_reg_offset_table.find(reg); it != zydis_to_reg_offset_table.end()) {
		return it->second;
	}

	LIB86CPU_ABORT_msg("Unhandled register %d in %s", reg, __func__);
}
