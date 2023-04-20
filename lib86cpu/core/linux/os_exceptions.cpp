/*
 * linux exception support
 *
 * ergo720                Copyright (c) 2023
 */

#include "lib86cpu_priv.h"
#ifdef LIB86CPU_X64_EMITTER
#include "x64/jit.h"
#endif

#define CIE_ID                     0
#define CIE_VERSION                1
#define DWARF_RAX                  0
#define DWARF_RBX                  3
#define DWARF_RSP                  7
#define DWARF_RET_ADDR             16
#define DW_EH_PE_udata8            4
#define DW_EH_PE_absptr            0
#define DW_CFA_def_cfa             0xC
#define DW_CFA_def_cfa_off         0xE
#define DW_CFA_advance_loc(delta)  ((1 << 6) | (delta & 0x3F))
#define DW_CFA_offset(reg_id)      ((2 << 6) | (reg_id & 0x3F))
#define DW_CFA_register            ((0 << 6) | 9)
#define DW_CFA_nop                 0


// NOTE: some of the fields of cie and fde are (S|U)LEB128 types. However, since the corresponding values are single bytes smaller than 128 or larger
// than -128, we can write them by simply writing single bytes
PACKED(struct cie_t {
	uint32_t length;
	int32_t id;
	uint8_t version;
	char augmentation_str[3];
	uint8_t code_align;
	int8_t data_align;
	uint8_t ret_addr_reg;
	uint8_t augmentation_data_length;
	uint8_t augmentation_data;
	uint8_t def_cfa_rule[3];
	uint8_t cfa_off_rule[2];
	uint8_t nop_rule[2];
});

static_assert((sizeof(cie_t) % sizeof(void *)) == 0);

PACKED(struct fde_t {
 	uint32_t length;
 	int32_t cie_off;
 	uint64_t code_start;
 	uint64_t code_size;
 	uint8_t augmentation_data_length;
 	uint8_t adv_loc_rule1;
	uint8_t def_cfa_off_rule1[2];
	uint8_t cfa_off_rule[2];
	uint8_t adv_loc_rule2;
	uint8_t def_cfa_off_rule2[2];
	uint8_t nop_rule[7];
});

static_assert((sizeof(fde_t) % sizeof(void *)) == 0);

extern "C" {
	void __register_frame(void *);
	void __deregister_frame(void *);
}


// These two functions are currently not used, they are here just for reference
[[maybe_unused]] static void
write_ULEB128(uint8_t *ptr, uint32_t val)
{
	while (true) {
		if (val < 128) {
			*ptr = val;
			break;
		}
		else {
			*ptr = ((val & 0x7f) | 0x80);
			val >>= 7;
		}
	}
}

[[maybe_unused]] static void
write_SLEB128(uint8_t *ptr, int32_t val)
{
	if (val >= 0) {
		write_ULEB128(ptr, val);
	}
	else {
		while (true) {
			if (val > -128) {
				*ptr = (val & 0x7f);
				break;
			}
			else {
				*ptr = val;
				val >>= 7;
			}
		}
	}
}

static void
write_cie(cie_t *cie)
{
	cie->length = sizeof(cie_t) - sizeof(cie->length);
	cie->id = CIE_ID;
	cie->version = CIE_VERSION;
	cie->augmentation_str[0] = 'z'; // size of augmentation field
	cie->augmentation_str[1] = 'R'; // encoding used by fde
	cie->augmentation_str[2] = 0;
	cie->code_align = 1; // code alignment factor used in the dwarf rules
	cie->data_align = (-8 & 0x7f); // data alignment factor used in the dwarf rules
	cie->ret_addr_reg = DWARF_RET_ADDR;
	cie->augmentation_data_length = 1; // size of cie augmentation data
	cie->augmentation_data = (DW_EH_PE_absptr << 4) | (DW_EH_PE_udata8 & 0xF); // fde uses 8 byte absolute pointers
	cie->def_cfa_rule[0] = DW_CFA_def_cfa; // specify Canonical Frame Address (CFA) -> stack position where the CALL return address is stored
	cie->def_cfa_rule[1] = DWARF_RSP;
	cie->def_cfa_rule[2] = 8;
	cie->cfa_off_rule[0] = DW_CFA_offset(DWARF_RET_ADDR); // specify return addr register in terms of CFA -> (1 * -8)
	cie->cfa_off_rule[1] = 1;
	std::fill(cie->nop_rule, cie->nop_rule + sizeof(cie->nop_rule), DW_CFA_nop);
}

static void
write_fde(fde_t *fde, uint8_t *code_ptr, size_t code_size)
{
	fde->length = sizeof(fde_t) - sizeof(fde->length);
	fde->cie_off = sizeof(cie_t) + sizeof(fde->length); // offset to the cie this fde refers to
	fde->code_start = reinterpret_cast<uint64_t>(code_ptr); // addr where the function specified by this fde starts
	fde->code_size = reinterpret_cast<uint64_t>(code_size); // size of the function specified by this fde
	fde->augmentation_data_length = 0; // size of fde augmentation data
	fde->adv_loc_rule1 = DW_CFA_advance_loc(1); // location after push rbx
	fde->def_cfa_off_rule1[0] = DW_CFA_def_cfa_off; // offset of CFA after push rbx
	fde->def_cfa_off_rule1[1] = 16;
	fde->cfa_off_rule[0] = DW_CFA_offset(DWARF_RBX); // specify rbx in terms of CFA -> (2 * -8)
	fde->cfa_off_rule[1] = 2;
	fde->adv_loc_rule2 = DW_CFA_advance_loc(4); // location after sub rsp, stack_size
	fde->def_cfa_off_rule2[0] = DW_CFA_def_cfa_off; // offset of CFA after sub rsp, stack_size
	fde->def_cfa_off_rule2[1] = 112;
	std::fill(fde->nop_rule, fde->nop_rule + sizeof(fde->nop_rule), DW_CFA_nop);
}

static void
write_eh_frame(cie_t *cie, uint8_t *code_ptr, size_t code_size)
{
	write_cie(cie);
	fde_t *fde = reinterpret_cast<fde_t *>(cie + 1);
	write_fde(fde, code_ptr, code_size);
	*reinterpret_cast<uint32_t*>(fde + 1) = 0;
	__register_frame(cie);
}

void
lc86_jit::gen_exception_info(uint8_t *code_ptr, size_t code_size)
{
	size_t aligned_code_size = (code_size + sizeof(void *) - 1) & ~(sizeof(void *) - 1);
	cie_t *cie = reinterpret_cast<cie_t *>(code_ptr + aligned_code_size);
	write_eh_frame(cie, code_ptr, code_size);
	m_mem.eh_frames.emplace(code_ptr, cie);
}

void
os_delete_exp_info(void *addr)
{
	__deregister_frame(addr);
}
