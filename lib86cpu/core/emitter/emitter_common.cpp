/*
 * shared functions among all emitters
 *
 * ergo720                Copyright (c) 2022
 */

#include "emitter_common.h"


static const std::unordered_map<ZydisRegister, const std::pair<int, size_t>> zydis_to_reg_offset_table = {
	{ ZYDIS_REGISTER_AL,         { EAX_idx,       CPU_CTX_EAX     }  },
	{ ZYDIS_REGISTER_CL,         { ECX_idx,       CPU_CTX_ECX     }  },
	{ ZYDIS_REGISTER_DL,         { EDX_idx,       CPU_CTX_EDX     }  },
	{ ZYDIS_REGISTER_BL,         { EBX_idx,       CPU_CTX_EBX     }  },
	{ ZYDIS_REGISTER_AH,         { EAX_idx,       CPU_CTX_EAX + 1 }  },
	{ ZYDIS_REGISTER_CH,         { ECX_idx,       CPU_CTX_ECX + 1 }  },
	{ ZYDIS_REGISTER_DH,         { EDX_idx,       CPU_CTX_EDX + 1 }  },
	{ ZYDIS_REGISTER_BH,         { EBX_idx,       CPU_CTX_EBX + 1 }  },
	{ ZYDIS_REGISTER_AX,         { EAX_idx,       CPU_CTX_EAX     }  },
	{ ZYDIS_REGISTER_CX,         { ECX_idx,       CPU_CTX_ECX     }  },
	{ ZYDIS_REGISTER_DX,         { EDX_idx,       CPU_CTX_EDX     }  },
	{ ZYDIS_REGISTER_BX,         { EBX_idx,       CPU_CTX_EBX     }  },
	{ ZYDIS_REGISTER_SP,         { ESP_idx,       CPU_CTX_ESP     }  },
	{ ZYDIS_REGISTER_BP,         { EBP_idx,       CPU_CTX_EBP     }  },
	{ ZYDIS_REGISTER_SI,         { ESI_idx,       CPU_CTX_ESI     }  },
	{ ZYDIS_REGISTER_DI,         { EDI_idx,       CPU_CTX_EDI     }  },
	{ ZYDIS_REGISTER_EAX,        { EAX_idx,       CPU_CTX_EAX     }  },
	{ ZYDIS_REGISTER_ECX,        { ECX_idx,       CPU_CTX_ECX     }  },
	{ ZYDIS_REGISTER_EDX,        { EDX_idx,       CPU_CTX_EDX     }  },
	{ ZYDIS_REGISTER_EBX,        { EBX_idx,       CPU_CTX_EBX     }  },
	{ ZYDIS_REGISTER_ESP,        { ESP_idx,       CPU_CTX_ESP     }  },
	{ ZYDIS_REGISTER_EBP,        { EBP_idx,       CPU_CTX_EBP     }  },
	{ ZYDIS_REGISTER_ESI,        { ESI_idx,       CPU_CTX_ESI     }  },
	{ ZYDIS_REGISTER_EDI,        { EDI_idx,       CPU_CTX_EDI     }  },
	{ ZYDIS_REGISTER_ES,         { ES_idx,        CPU_CTX_ES      }  },
	{ ZYDIS_REGISTER_CS,         { CS_idx,        CPU_CTX_CS      }  },
	{ ZYDIS_REGISTER_SS,         { SS_idx,        CPU_CTX_SS      }  },
	{ ZYDIS_REGISTER_DS,         { DS_idx,        CPU_CTX_DS      }  },
	{ ZYDIS_REGISTER_FS,         { FS_idx,        CPU_CTX_FS      }  },
	{ ZYDIS_REGISTER_GS,         { GS_idx,        CPU_CTX_GS      }  },
	{ ZYDIS_REGISTER_CR0,        { CR0_idx,       CPU_CTX_CR0     }  },
	{ ZYDIS_REGISTER_CR1,        { CR1_idx,       CPU_CTX_CR1     }  },
	{ ZYDIS_REGISTER_CR2,        { CR2_idx,       CPU_CTX_CR2     }  },
	{ ZYDIS_REGISTER_CR3,        { CR3_idx,       CPU_CTX_CR3     }  },
	{ ZYDIS_REGISTER_CR4,        { CR4_idx,       CPU_CTX_CR4     }  },
	{ ZYDIS_REGISTER_DR0,        { DR0_idx,       CPU_CTX_DR0     }  },
	{ ZYDIS_REGISTER_DR1,        { DR1_idx,       CPU_CTX_DR1     }  },
	{ ZYDIS_REGISTER_DR2,        { DR2_idx,       CPU_CTX_DR2     }  },
	{ ZYDIS_REGISTER_DR3,        { DR3_idx,       CPU_CTX_DR3     }  },
	{ ZYDIS_REGISTER_DR4,        { DR4_idx,       CPU_CTX_DR4     }  },
	{ ZYDIS_REGISTER_DR5,        { DR5_idx,       CPU_CTX_DR5     }  },
	{ ZYDIS_REGISTER_DR6,        { DR6_idx,       CPU_CTX_DR6     }  },
	{ ZYDIS_REGISTER_DR7,        { DR7_idx,       CPU_CTX_DR7     }  },
	{ ZYDIS_REGISTER_EFLAGS,     { EFLAGS_idx,    CPU_CTX_EFLAGS  }  },
	{ ZYDIS_REGISTER_EIP,        { EIP_idx,       CPU_CTX_EIP     }  },
	{ ZYDIS_REGISTER_IDTR,       { IDTR_idx,      CPU_CTX_IDTR    }  },
	{ ZYDIS_REGISTER_GDTR,       { GDTR_idx,      CPU_CTX_GDTR    }  },
	{ ZYDIS_REGISTER_LDTR,       { LDTR_idx,      CPU_CTX_LDTR    }  },
	{ ZYDIS_REGISTER_TR,         { TR_idx,        CPU_CTX_TR      }  },
	{ ZYDIS_REGISTER_MM0,        { R0_idx,        CPU_CTX_R0      }  },
	{ ZYDIS_REGISTER_MM1,        { R1_idx,        CPU_CTX_R1      }  },
	{ ZYDIS_REGISTER_MM2,        { R2_idx,        CPU_CTX_R2      }  },
	{ ZYDIS_REGISTER_MM3,        { R3_idx,        CPU_CTX_R3      }  },
	{ ZYDIS_REGISTER_MM4,        { R4_idx,        CPU_CTX_R4      }  },
	{ ZYDIS_REGISTER_MM5,        { R5_idx,        CPU_CTX_R5      }  },
	{ ZYDIS_REGISTER_MM6,        { R6_idx,        CPU_CTX_R6      }  },
	{ ZYDIS_REGISTER_MM7,        { R7_idx,        CPU_CTX_R7      }  },
	{ ZYDIS_REGISTER_XMM0,       { XMM0_idx,      CPU_CTX_XMM0    }  },
	{ ZYDIS_REGISTER_XMM1,       { XMM1_idx,      CPU_CTX_XMM1    }  },
	{ ZYDIS_REGISTER_XMM2,       { XMM2_idx,      CPU_CTX_XMM2    }  },
	{ ZYDIS_REGISTER_XMM3,       { XMM3_idx,      CPU_CTX_XMM3    }  },
	{ ZYDIS_REGISTER_XMM4,       { XMM4_idx,      CPU_CTX_XMM4    }  },
	{ ZYDIS_REGISTER_XMM5,       { XMM5_idx,      CPU_CTX_XMM5    }  },
	{ ZYDIS_REGISTER_XMM6,       { XMM6_idx,      CPU_CTX_XMM6    }  },
	{ ZYDIS_REGISTER_XMM7,       { XMM7_idx,      CPU_CTX_XMM7    }  },
};


size_t
get_reg_offset(ZydisRegister reg)
{
	if (auto it = zydis_to_reg_offset_table.find(reg); it != zydis_to_reg_offset_table.end()) {
		return it->second.second;
	}

	LIB86CPU_ABORT_msg("Unhandled register %d in %s", reg, __func__);
}

int
get_reg_idx(ZydisRegister reg)
{
	if (auto it = zydis_to_reg_offset_table.find(reg); it != zydis_to_reg_offset_table.end()) {
		return it->second.first;
	}

	LIB86CPU_ABORT_msg("Unhandled register %d in %s", reg, __func__);
}

const std::pair<int, size_t>
get_reg_pair(ZydisRegister reg)
{
	if (auto it = zydis_to_reg_offset_table.find(reg); it != zydis_to_reg_offset_table.end()) {
		return it->second;
	}

	LIB86CPU_ABORT_msg("Unhandled register %d in %s", reg, __func__);
}

size_t
get_seg_prfx_offset(ZydisDecodedInstruction *instr)
{
	// This is to be used for instructions that have hidden operands, for which zydis does not guarantee
	// their position in the operand array

	if (!(instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT)) {
		return CPU_CTX_DS;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_CS) {
		return CPU_CTX_CS;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_SS) {
		return CPU_CTX_SS;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_DS) {
		return CPU_CTX_DS;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_ES) {
		return CPU_CTX_ES;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_FS) {
		return CPU_CTX_FS;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_GS) {
		return CPU_CTX_GS;
	}
	else {
		LIB86CPU_ABORT();
	}
}

uint128_t::uint128_t()
{
	this->low = 0;
	this->high = 0;
}

uint128_t::uint128_t(uint64_t val)
{
	this->low = val;
	this->high = 0;
}

uint128_t::operator uint8_t()
{
	return this->low & 0xFF;
}

uint128_t &
uint128_t::operator|=(const uint128_t &rhs)
{
	this->low |= rhs.low;
	this->high |= rhs.high;
	return *this;
}

uint80_t::uint80_t()
{
	this->low = 0;
	this->high = 0;
}

uint80_t::uint80_t(uint64_t val)
{
	this->low = val;
	this->high = 0;
}

uint80_t::operator uint8_t()
{
	return this->low & 0xFF;
}

uint80_t::operator uint128_t()
{
	uint128_t converted;
	converted.low = this->low;
	converted.high = this->high;
	return converted;
}

uint80_t &
uint80_t::operator|=(const uint80_t &rhs)
{
	this->low |= rhs.low;
	this->high |= rhs.high;
	return *this;
}

uint80_t
uint80_t::operator>>(int shift)
{
	uint128_t val = static_cast<uint128_t>(*this) >> shift;
	this->low = val.low;
	this->high = val.high;
	return *this;
}

uint80_t
uint80_t::operator<<(int shift)
{
	uint128_t val = static_cast<uint128_t>(*this) << shift;
	this->low = val.low;
	this->high = val.high;
	return *this;
}
