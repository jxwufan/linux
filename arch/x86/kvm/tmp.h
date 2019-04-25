static inline unsigned long hyp_register_read(struct kvm_vcpu *vcpu,
											  enum kvm_reg reg)
{
	//if (!test_bit(reg, (unsigned long *)&vcpu->arch.regs_avail))
		//kvm_x86_ops->cache_reg(vcpu, reg);

	return vcpu->arch.regs[reg];
}

static inline void hyp_register_write(struct kvm_vcpu *vcpu,
									  enum kvm_reg reg,
									  unsigned long val)
{
	vcpu->arch.regs[reg] = val;
	// these two lines may be useless for our simple implementation
	__set_bit(reg, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(reg, (unsigned long *)&vcpu->arch.regs_avail);
}

int hyp_skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	//unsigned long rflags = kvm_x86_ops->get_rflags(vcpu);
	int r = EMULATE_DONE;
	u64 rip;

	rip = hyp_register_read(vcpu, VCPU_REGS_RIP);
	rip += vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	hyp_register_write(vcpu, VCPU_REGS_RIP, rip);

	return r == EMULATE_DONE;
}


void hypx86_set_up_vmcs(void) {
	int err;

	err = alloc_loaded_vmcs(&kernel_vmx.vmcs01);

	/* start to set up vmcs */

	/* first load vmcs */
	loaded_vmcs_clear(&kernel_vmx.vmcs01);
	vmcs_load(kernel_vmx.vmcs01.vmcs);
	/* second config vmcs */

    hypx86_init_vmcs_host_state();
    hypx86_init_vmcs_guest_state();
    hypx86_init_vmcs_control_fields();
}

void hypx86_print_debug(void) {
	//unsigned long cr0, cr3, cr4;
	//pr_info("[HYP-PRINT-DEBUG] GUEST_CR0 : %lx\n", vmcs_readl(GUEST_CR0));
	//pr_info("[HYP-PRINT-DEBUG] GUEST_CR4 : %lx\n", vmcs_readl(GUEST_CR4));

	//pr_info("[HYP-PRINT-DEBUG] VM_ENTRY_CONTROLS : %x\n", vmcs_read32(VM_ENTRY_CONTROLS));

	// IA32_PERF_GLOBAL_CTRL MSR, IA32_PAT MSR, IA32_EFER MSR, IA32_BNDCFGS MSR
	pr_info("[HYP-PRINT-DEBUG] IA32_PERF_GLOBAL_CTRL : %llx\n", vmcs_read64(GUEST_IA32_PERF_GLOBAL_CTRL));
	pr_info("[HYP-PRINT-DEBUG] IA32_EFER : %llx\n", vmcs_read64(GUEST_IA32_EFER));
	pr_info("[HYP-PRINT-DEBUG] GUEST_IA32_PAT : %llx\n", vmcs_read64(GUEST_IA32_PAT));

}

int check_bit(unsigned long src_val, int bit, unsigned long tar_val) {
	// src_val : the value to be checked
	// bit : from 0 to 63.
	// tar_val : bit shoule be 1 or 0

	if (((src_val >> bit) & 1) == tar_val)
		return 1;
	return 0;
}

int check_bits(unsigned long src_val, int st, int ed, unsigned long tar_val) {
	for ( ; st < ed; st++) {
		if (!check_bit(src_val, st, tar_val))
			return 0;
	}
	return 1;
}

unsigned long get_bit(unsigned long src_val, int bit) {
	return (src_val >> bit) & 1;
}

bool hypx86_is_canonical_address(u64 la) {
	int64_t tmp = la;
	return ((u64)((tmp << 16) >> 16)) == la;
}


void hypx86_check_guest_part1(void) {
	//26.3.1.1 Checks on Guest Control Registers, Debug Registers, and MSRs
	u64 cr0 = vmcs_readl(GUEST_CR0);
	u64 cr3 = vmcs_readl(GUEST_CR3);
	u64 cr4 = vmcs_readl(GUEST_CR4);
	u64 dr7 = vmcs_readl(GUEST_DR7);
	u64 tmp64;//tar64;
	u32 vmentry_ctl = vmcs_read32(VM_ENTRY_CONTROLS);


	pr_info("[OUR-VMCS-LOG] enter hypx86_check_guest_part1");

	// TODO : The CR0 field must not set any bit to a value not supported in VMX operation (see Section 23.8).

	if (get_bit(cr0, 31) == 1) {
		tmp64 = cr0 & 1;
		if (!check_bit(tmp64, 0, 1))
			pr_info("[OUR-VMCS-ERROR] 1.1\n");
	}

	// TODO : The CR4 field must not set any bit to a value not supported in VMX operation (see Section 23.8).

	if (!check_bit(vmentry_ctl, 2, 1) || vmcs_read64(GUEST_IA32_DEBUGCTL) != 0)
		//LOAD_DEBUG_CONTROLS is 2 bit
		pr_info("[OUR-VMCS-ERROR] 1.2\n");

	if (get_bit(vmentry_ctl, 9) == 1) {
		// IA-32e mode guest 9 bit
		if (!check_bit(cr0, 31, 1) || !check_bit(cr4, 5, 1))
			pr_info("[OUR-VMCS-ERROR] 1.3\n");
	} else {
		if (check_bit(cr4, 17, 1))
			pr_info("[OUR-VMCS-ERROR] 1.4\n");
	}

	if ((cr3 >> 32) != 0) {
		pr_info("[OUR-VMCS-WARNING] 1.5\n");
	}

	if (check_bit(vmentry_ctl, 2, 1) && (dr7 >> 32) != 0) {
		//Load debug control
		pr_info("[OUR-VMCS-ERROR] 1.6\n");
	}

	if (!hypx86_is_canonical_address(vmcs_readl(GUEST_SYSENTER_ESP)) || !hypx86_is_canonical_address(vmcs_readl(GUEST_SYSENTER_EIP))) {
	pr_info("[OUR-VMCS-ERROR-CANONICAL] 1.7 : GUEST_SYSENTER_ESP : %016lx, GUEST_SYSENTER_EIP : %016lx\n", vmcs_readl(GUEST_SYSENTER_ESP), vmcs_readl(GUEST_SYSENTER_EIP));
	}

	if (check_bit(vmentry_ctl, 13, 1)) {
		//Load IA32_PERF_GLOB AL_CTRL, bit 12
		pr_info("[OUR-VMCS-INFO-reserved-0] GUEST_IA32_PERF_GLOBAL_CTRL : %016llx\n", vmcs_read64(GUEST_IA32_PERF_GLOBAL_CTRL));
	}

	if (check_bit(vmentry_ctl, 14, 1)) {
		//LOAD_IA32_PAT
		pr_info("[OUR-VMCS-INFO-special-check] GUEST_IA32_PAT MSR : %016llx\n", vmcs_read64(GUEST_IA32_PAT));
	}

	if (check_bit(vmentry_ctl, 15, 1)) {
		//load IA32_EFER
		pr_info("[OUR-VMCS-INFO-special-check] GUEST_IA32_EFER MSR : %016llx\n", vmcs_read64(GUEST_IA32_EFER));
	}

	if (check_bit(vmentry_ctl, 16, 1)) {
		//load IA32_BNDCFGS
		if (!hypx86_is_canonical_address(vmcs_read64(GUEST_BNDCFGS) >> 12)) {
			pr_info("[OUR-VMCS-ERROR-CANONICAL] 1.11 : GUEST_IA32_BNDCFGS MSR : %016llx\n", vmcs_read64(GUEST_BNDCFGS));
		}
	}
}

void hypx86_check_guest_part3(void) {
	// 26.3.1.3
	// Checks on Guest Descriptor-Table Registers
	// GDTR and IDTR
	u64 gdtr_base = vmcs_readl(GUEST_GDTR_BASE);
	u64 idtr_base = vmcs_readl(GUEST_IDTR_BASE);
	u32 gdtr_limit = vmcs_read32(GUEST_GDTR_LIMIT);
	u32 idtr_limit = vmcs_read32(GUEST_IDTR_LIMIT);

	if (!hypx86_is_canonical_address(gdtr_base) ||
			!hypx86_is_canonical_address(idtr_base)) {
		pr_info("[OUR-VMCS-ERROR] 3.1\n");
	}

	if (gdtr_limit >> 16 || idtr_limit >> 16) {
		pr_info("[OUR-VMCS-ERROR] 3.2\n");
	}
}

void hypx86_check_guest_part4(void) {
	// 26.3.1.4 Checks on Guest RIP and RFLAGS
	// RIP, RFLAGS
	u64 rip = vmcs_readl(GUEST_RIP);
	u64 rflags = vmcs_readl(GUEST_RFLAGS);
	u64 cr0 = vmcs_readl(GUEST_CR0);
	u32 vmentry_ctl = vmcs_read32(VM_ENTRY_CONTROLS);
	u32 cs_ar = vmcs_read32(GUEST_CS_AR_BYTES);
	u32 vmentry_intr_info = vmcs_read32(VM_ENTRY_INTR_INFO_FIELD);

	if (check_bit(cs_ar, 13, 0) || check_bit(vmentry_ctl, 9, 0)) {
		// IA-32e mode guest 9 bit of vmentry_ctl
		if (rip >> 32) {
			pr_info("[OUR-VMCS-ERROR] 4.1\n");
		}
	} else {
		// If the processor supports N < 64 linear-address bits, bits 63:N must be identical
		// ???
	}

	if ((rflags >> 22) || get_bit(rflags, 15) || get_bit(rflags, 5) || get_bit(rflags, 3) || check_bit(rflags, 1, 0)) {
		pr_info("[OUR-VMCS-ERROR] 4.2\n");
	}

	if (check_bit(vmentry_ctl, 9, 1) || check_bit(cr0, 0, 0)) {
		if (check_bit(rflags, 17, 1)) {
			pr_info("[OUR-VMCS-ERROR] 4.3\n");
		}
	}

	if (check_bit(vmentry_intr_info, 31, 1) && ((vmentry_intr_info >> 8) & 0x7) == 0) {
		// 10:8 -> 0, external interrupt
		if (check_bit(rflags, 9, 0)) {
			pr_info("[OUR-VMCS-ERROR] 4.4\n");
		}
	}
}

void hypx86_check_guest_part5(void) {
	//26.3.1.5 Checks on Guest Non-Register State
	//
	u32 activity_state = vmcs_read32(GUEST_ACTIVITY_STATE);
	u32 ss_ar = vmcs_read32(GUEST_SS_AR_BYTES);
	u32 interruptibility = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	u32 vm_entry_intr_info = vmcs_read32(VM_ENTRY_INTR_INFO_FIELD);
	u32 vm_entry_ctrl = vmcs_read32(VM_ENTRY_CONTROLS);
	u64 rflags = vmcs_readl(GUEST_RFLAGS);
	u32 pin_based_exec_ctrl = vmcs_read32(PIN_BASED_VM_EXEC_CONTROL);
	u64 pending_debug_except = vmcs_readl(GUEST_PENDING_DBG_EXCEPTIONS);
	u64 ia32_debug_ctl = vmcs_read64(GUEST_IA32_DEBUGCTL);
	u64 vmcs_link_pointer = vmcs_read64(VMCS_LINK_POINTER);

	pr_info("[OUR-VMCS-LOG] enter hypx86_check_guest_part5");

	// Activity state.
	if (activity_state >= 4) {
		pr_info("[OUR-VMCS-ERROR] 5.1\n");
	}

	if ((ss_ar >> 5) & 0x3) {
		if (activity_state == GUEST_ACTIVITY_HLT) {
			pr_info("[OUR-VMCS-ERROR] 5.2\n");
		}
	}

	if ((interruptibility & 0x1) || (interruptibility & 0x2)) {
		if (activity_state != GUEST_ACTIVITY_ACTIVE) {
			pr_info("[OUR-VMCS-ERROR] 5.3\n");
		}
	}

	if (check_bit(vm_entry_intr_info, 31, 1)) {
		if (activity_state != GUEST_ACTIVITY_ACTIVE) {
			pr_info("[OUR-VMCS-WARNING] 5.4\n");
		}
	}

	if (check_bit(vm_entry_ctrl, 10, 1)) {
		if (activity_state == 3) {
			// wait-for-sipi
			pr_info("[OUR-VMCS-ERROR] 5.5\n");
		}
	}

	//Interruptibility state
	if ((interruptibility >> 5) != 0) {
		pr_info("[OUR-VMCS-ERROR] 5,6\n");
	}

	if ((interruptibility & 0x3) == 3) {
		pr_info("[OUR-VMCS-ERROR] 5.7\n");
	}

	if (check_bit(rflags, 9, 0)) {
		if (check_bit(interruptibility, 0, 1)) {
			pr_info("[OUR-VMCS-ERROR] 5.8\n");
		}
	}

	if (check_bit(vm_entry_intr_info, 31, 1) &&
		((vm_entry_intr_info >> 8) & 0x7) == 0) {
		if (check_bit(interruptibility, 0, 1) || check_bit(interruptibility, 1, 1)) {
			pr_info("[OUR-VMCS-ERROR] 5.9\n");
		}
	}

	if (check_bit(vm_entry_intr_info, 31, 1) &&
		((vm_entry_intr_info >> 8) & 0x7) == 2) {
		if (check_bit(interruptibility, 1, 1)) {
			pr_info("[OUR-VMCS-ERROR] 5.10\n");
		}
	}

	if (check_bit(interruptibility, 2, 1)) {
		//Bit 2 (blocking by SMI)
		pr_info("[OUR-VMCS-WARNING] 5.11 : Bit 2 (blocking by SMI) must be 0 if the processor is not in SMM. now the bit is 1, so we have to make sure whether the cpu is in SMM\n");
	}

	// Bit 2 (blocking by SMI) must be 1 if the “entry to SMM” VM-entry control is 1.
	if (check_bit(vm_entry_ctrl, 10, 1)) {
		// entry to SMM
		if (check_bit(interruptibility, 2, 0)) {
			pr_info("[OUR-VMCS-ERROR] 5.12\n");
		}
	}

	if (check_bit(vm_entry_intr_info, 31, 1) &&
		((vm_entry_intr_info >> 8) & 0x7) == 2) {
		if (check_bit(interruptibility, 0, 1)) {
			pr_info("[OUR-VMCS-WARNING] 5.13\n");
		}
	}


	if (check_bit(vm_entry_intr_info, 31, 1) &&
		((vm_entry_intr_info >> 8) & 0x7) == 2 &&
		(check_bit(pin_based_exec_ctrl, 3, 1))) {
		if (check_bit(interruptibility, 3, 1)) {
			//Bit 3 (blocking by NMI)
			pr_info("[OUR-VMCS-ERROR] 5.14\n");
		}
	}

	if (check_bit(interruptibility, 4, 1)) {
		// bit 4 (enclave interruption)
		if (check_bit(interruptibility, 1, 1)) {
			pr_info("[OUR-VMCS-ERROR] 5.15\n");
		}
		// If bit 4 (enclave interruption) is 1, bit 1 (blocking by MOV-SS) must be 0 and the processor must support for SGX by enumerating CPUID.(EAX=07H,ECX=0):EBX.SGX[bit 2] as 1.

		pr_info("[OUR-VMCS-WARNING] 5.16\n");
	}

	// Pending debug exceptions
	//pending_debug_except
	if (check_bit(pending_debug_except, 13, 1) ||
		check_bit(pending_debug_except, 15, 1) ||
		(pending_debug_except & 0xff0) ||
		(pending_debug_except >> 17)) {
		pr_info("[OUR-VMCS-ERROR] 5.17\n");
	}

	if (check_bit(interruptibility, 0, 1) ||
		check_bit(interruptibility, 1, 1) ||
		activity_state == GUEST_ACTIVITY_HLT) {
		if (check_bit(rflags, 8, 1) && check_bit(ia32_debug_ctl, 1, 0)) {
			if (check_bit(pending_debug_except, 14, 0)) {
				pr_info("[OUR-VMCS-ERROR] 5.18\n");
			}
		} else {
			if (check_bit(pending_debug_except, 14, 1)) {
				pr_info("[OUR-VMCS-ERROR] 5.19\n");
			}
		}
	}

	if (check_bit(pending_debug_except, 16, 1)) {
		if ((pending_debug_except & 0xfffffffffffeefff) ||
				check_bit(pending_debug_except, 12, 0)) {
			pr_info("[OUR-VMCS-ERROR] 5.20\n");
		}
		if (check_bit(interruptibility, 1, 1)) {
			pr_info("[OUR-VMCS-ERROR] 5.21\n");
		}
		pr_info("[OUR-VMCS-WARNING] The processor must support for RTM by enumerating CPUID.(EAX=07H,ECX=0):EBX[bit 11] as 1\n");
	}

	// VMCS_LINK_POINTER
	if (vmcs_link_pointer != -1ul) {
		if (vmcs_link_pointer & 0xfff) {
			pr_info("[OUR-VMCS-ERROR] 5.22\n");
		}

		pr_info("[OUR-VMCS-WARNING] we still left some field for this to check\n");
	}
}

inline bool hypx86_is_noncanonical_address(u64 la)
{
#ifdef CONFIG_X86_64
	return get_canonical(la, 48) != la;
#else
	return false;
#endif
}

void perr(int x, int y)
{
	pr_info("[OUR-VMCS-ERROR] %d.%d\n", x, y);
}

unsigned long get_type(unsigned long src_val) {
	unsigned long ret_val = 0;
	int st = 3;
	int ed = 0;
	for ( ; st >= ed; st--) {
		ret_val = (ret_val << 1) | get_bit(src_val, st);
	}
	return ret_val;
}

unsigned long get_DPL(unsigned long src_val) {
	unsigned long ret_val = 0;
	int st = 6;
	int ed = 5;
	for ( ; st >= ed; st--) {
		ret_val = (ret_val << 1) | get_bit(src_val, st);
	}
	return ret_val;
}

unsigned long get_RPL(unsigned long src_val) {
	unsigned long ret_val = 0;
	int st = 1;
	int ed = 0;
	for ( ; st >= ed; st--) {
		ret_val = (ret_val << 1) | get_bit(src_val, st);
	}
	return ret_val;
}

unsigned long get_reserved_0(unsigned long src_val) {
	unsigned long ret_val = 0;
	int st = 8;
	int ed = 12;
	for ( ; st < ed; st++) {
		ret_val = (ret_val << 1) | get_bit(src_val, st);
	}
	return ret_val;
}

unsigned long get_reserved_1(unsigned long src_val) {
	unsigned long ret_val = 0;
	int st = 17;
	int ed = 32;
	for ( ; st < ed; st++) {
		ret_val = (ret_val << 1) | get_bit(src_val, st);
	}
	return ret_val;
}

int hypx86_is_usable(unsigned long src) {
	if (check_bit(src, 16, 0))
		return 1;
	else
		return 0;
}

void hypx86_check_guest_part6(void) {
	u64 cr0 = vmcs_readl(GUEST_CR0);
	u64 cr4 = vmcs_readl(GUEST_CR4);
	u32 vmentry_ctl = vmcs_read32(VM_ENTRY_CONTROLS);

	if (check_bit(cr0, 31, 1) && check_bit(cr4, 5, 1) && check_bit(vmentry_ctl, 9, 0)) {
		pr_info("[OUR-VMCS-WARNING] 6.1 : plz make a check on sth (go to look it up in intel manual)\n");
	}
}

void hypx86_check_guest_part2(void) {
	int tmp_type;//cnt = 0, tmp_DPL;
	int is_virtual_8086;

	u64 cr0 = vmcs_readl(GUEST_CR0);
	unsigned long LDTR_SELECTOR, TR_SELECTOR;
	unsigned long CS_SELECTOR, SS_SELECTOR, DS_SELECTOR;
	unsigned long ES_SELECTOR, FS_SELECTOR, GS_SELECTOR;
	unsigned long CS_BASE, SS_BASE, DS_BASE, ES_BASE, FS_BASE, GS_BASE, TR_BASE, LDTR_BASE;
	unsigned long CS_AR, SS_AR, DS_AR, ES_AR, FS_AR, GS_AR, LDTR_AR, TR_AR;
	unsigned long CS_LIMIT, SS_LIMIT, DS_LIMIT, ES_LIMIT;
	unsigned long FS_LIMIT, GS_LIMIT, LDTR_LIMIT, TR_LIMIT;
	unsigned long RFLAGS;

	RFLAGS = vmcs_readl(GUEST_RFLAGS);
	TR_SELECTOR = vmcs_read16(GUEST_TR_SELECTOR);
	LDTR_SELECTOR = vmcs_read16(GUEST_LDTR_SELECTOR);
	CS_SELECTOR = vmcs_read16(GUEST_CS_SELECTOR);
	SS_SELECTOR = vmcs_read16(GUEST_SS_SELECTOR);
	DS_SELECTOR = vmcs_read16(GUEST_DS_SELECTOR);
	ES_SELECTOR = vmcs_read16(GUEST_ES_SELECTOR);
	FS_SELECTOR = vmcs_read16(GUEST_FS_SELECTOR);
	GS_SELECTOR = vmcs_read16(GUEST_GS_SELECTOR);
	TR_BASE = vmcs_readl(GUEST_TR_BASE);
	LDTR_BASE = vmcs_readl(GUEST_LDTR_BASE);
	CS_BASE = vmcs_readl(GUEST_CS_BASE);
	SS_BASE = vmcs_readl(GUEST_SS_BASE);
	DS_BASE = vmcs_readl(GUEST_DS_BASE);
	ES_BASE = vmcs_readl(GUEST_ES_BASE);
	FS_BASE = vmcs_readl(GUEST_FS_BASE);
	GS_BASE = vmcs_readl(GUEST_GS_BASE);
	TR_AR = vmcs_read32(GUEST_TR_AR_BYTES);
	LDTR_AR = vmcs_read32(GUEST_LDTR_AR_BYTES);
	CS_AR = vmcs_read32(GUEST_CS_AR_BYTES);
	SS_AR = vmcs_read32(GUEST_SS_AR_BYTES);
	DS_AR = vmcs_read32(GUEST_DS_AR_BYTES);
	ES_AR = vmcs_read32(GUEST_ES_AR_BYTES);
	FS_AR = vmcs_read32(GUEST_FS_AR_BYTES);
	GS_AR = vmcs_read32(GUEST_GS_AR_BYTES);
	TR_LIMIT = vmcs_read32(GUEST_TR_LIMIT);
	LDTR_LIMIT = vmcs_read32(GUEST_LDTR_LIMIT);
	CS_LIMIT = vmcs_read32(GUEST_CS_LIMIT);
	SS_LIMIT = vmcs_read32(GUEST_SS_LIMIT);
	DS_LIMIT = vmcs_read32(GUEST_DS_LIMIT);
	ES_LIMIT = vmcs_read32(GUEST_ES_LIMIT);
	FS_LIMIT = vmcs_read32(GUEST_FS_LIMIT);
	GS_LIMIT = vmcs_read32(GUEST_GS_LIMIT);


	// get some terms
	is_virtual_8086 = check_bit(RFLAGS, 17, 1);

	// selector fields
	if (!check_bit(TR_SELECTOR, 2, 0)) {
		perr(2, 1);
	}
	if (check_bit(LDTR_AR, 16, 0)) {
		if (!check_bit(LDTR_SELECTOR, 2, 0)) {
			perr(2, 2);
		}
	}
	if (!is_virtual_8086) {
		if (!(check_bit(SS_SELECTOR, 0, get_bit(CS_SELECTOR, 0)) &&
		      check_bit(SS_SELECTOR, 1, get_bit(CS_SELECTOR, 1)))) {
			perr(2, 3);
		}
	}

	// Base-address fields
	if (is_virtual_8086) {
		if (CS_BASE != 16 * CS_SELECTOR ||
		    DS_BASE != 16 * DS_SELECTOR ||
		    SS_BASE != 16 * SS_SELECTOR ||
		    ES_BASE != 16 * ES_SELECTOR ||
		    FS_BASE != 16 * FS_SELECTOR ||
		    GS_BASE != 16 * GS_SELECTOR) {
			perr(2, 4);
		}
	}
	if (hypx86_is_noncanonical_address(TR_BASE) ||
	    hypx86_is_noncanonical_address(FS_BASE) ||
	    hypx86_is_noncanonical_address(GS_BASE) ||
	    (check_bit(LDTR_AR, 16, 0) && hypx86_is_noncanonical_address(LDTR_BASE)) ||
	    !check_bits(CS_BASE, 32, 64, 0) ||
	    (check_bit(SS_AR, 16, 0) && !check_bits(SS_BASE, 32, 64, 0)) ||
	    (check_bit(DS_AR, 16, 0) && !check_bits(DS_BASE, 32, 64, 0)) ||
	    (check_bit(ES_AR, 16, 0) && !check_bits(ES_BASE, 32, 64, 0))) {
		perr(2, 5);
	}
	// TODO: Limit fields for CS, SS, DS, ES, FS, GS. If the guest will be virtual-8086, the field must be 0000FFFFH.
	// Access-rights fields
	// Access-rights fileds: CS, SS, DS, ES, FS, GS.
	if (is_virtual_8086) {
		pr_info("IT IS VIRTUAL 8086");
	} else {
		// Bits 3:0 (Type)
		tmp_type = get_type(CS_AR);
		if (tmp_type != 9 && tmp_type != 11 &&
		    tmp_type != 13 && tmp_type != 15)
			perr(2, 6);

		if (hypx86_is_usable(SS_AR)) {
			tmp_type = get_type(SS_AR);
			if (tmp_type != 3 && tmp_type != 7)
				perr(2, 7);
		}

		if (hypx86_is_usable(DS_AR)) {
			if (!check_bit(DS_AR, 0, 1)) {
				perr(2, 8);
			}
			if (check_bit(DS_AR, 3, 1) && !check_bit(DS_AR, 1, 1)) {
				perr(2, 9);
			}
		}

		if (hypx86_is_usable(ES_AR)) {
			if (!check_bit(ES_AR, 0, 1)) {
				perr(2, 10);
			}
			if (check_bit(ES_AR, 3, 1) && !check_bit(ES_AR, 1, 1)) {
				perr(2, 11);
			}
		}

		if (hypx86_is_usable(FS_AR)) {
			if (!check_bit(FS_AR, 0, 1)) {
				perr(2, 12);
			}
			if (check_bit(FS_AR, 3, 1) && !check_bit(FS_AR, 1, 1)) {
				perr(2, 13);
			}
		}

		if (hypx86_is_usable(GS_AR)) {
			if (!check_bit(GS_AR, 0, 1)) {
				perr(2, 14);
			}
			if (check_bit(GS_AR, 3, 1) && !check_bit(GS_AR, 1, 1)) {
				perr(2, 15);
			}
		}

		// Bits 4 (S)
		if (!check_bit(CS_AR, 4, 1)) {
			perr(2, 16);
		}
		if (hypx86_is_usable(SS_AR) && !check_bit(SS_AR, 4, 1)) {
			perr(2, 17);
		}
		if (hypx86_is_usable(DS_AR) && !check_bit(DS_AR, 4, 1)) {
			perr(2, 18);
		}
		if (hypx86_is_usable(ES_AR) && !check_bit(ES_AR, 4, 1)) {
			perr(2, 19);
		}
		if (hypx86_is_usable(FS_AR) && !check_bit(FS_AR, 4, 1)) {
			perr(2, 20);
		}
		if (hypx86_is_usable(GS_AR) && !check_bit(GS_AR, 4, 1)) {
			perr(2, 21);
		}

		// Bits 6:5 (DPL)
		if (get_type(CS_AR) == 3 && get_DPL(CS_AR) != 0) {
			perr(2, 22);
		}
		if (get_type(CS_AR) == 9 || get_type(CS_AR) == 11) {
			if (get_DPL(CS_AR) != get_DPL(SS_AR)) {
				perr(2, 23);
			}
		}
		if (get_type(CS_AR) == 13 || get_type(CS_AR) == 15) {
			if (get_DPL(CS_AR) > get_DPL(SS_AR)) {
				perr(2, 24);
			}
		}

		if (get_DPL(SS_AR) != get_RPL(SS_SELECTOR)) {
			perr(2, 25);
		}
		if (get_type(CS_AR) == 3 || get_bit(cr0, 0) == 0) {
			if (get_DPL(SS_AR) != 0) {
				perr(2, 26);
			}
		}

		if (hypx86_is_usable(DS_AR) && get_type(DS_AR) >= 0 &&
		    get_type(DS_AR) <= 11) {
			if (get_DPL(DS_AR) < get_RPL(DS_SELECTOR)) {
				perr(2, 27);
			}
		}
		if (hypx86_is_usable(ES_AR) && get_type(ES_AR) >= 0 &&
		    get_type(ES_AR) <= 11) {
			if (get_DPL(ES_AR) < get_RPL(ES_SELECTOR)) {
				perr(2, 28);
			}
		}
		if (hypx86_is_usable(FS_AR) && get_type(FS_AR) >= 0 &&
		    get_type(FS_AR) <= 11) {
			if (get_DPL(FS_AR) < get_RPL(FS_SELECTOR)) {
				perr(2, 29);
			}
		}
		if (hypx86_is_usable(GS_AR) && get_type(GS_AR) >= 0 &&
		    get_type(GS_AR) <= 11) {
			if (get_DPL(GS_AR) < get_RPL(GS_SELECTOR)) {
				perr(2, 30);
			}
		}

		// Bits 7 (P)
		if (!check_bit(CS_AR, 7, 1)) {
			perr(2, 31);
		}
		if (hypx86_is_usable(SS_AR) && !check_bit(SS_AR, 7, 1)) {
			perr(2, 32);
		}
		if (hypx86_is_usable(DS_AR) && !check_bit(DS_AR, 7, 1)) {
			perr(2, 33);
		}
		if (hypx86_is_usable(ES_AR) && !check_bit(ES_AR, 7, 1)) {
			perr(2, 34);
		}
		if (hypx86_is_usable(FS_AR) && !check_bit(FS_AR, 7, 1)) {
			perr(2, 35);
		}
		if (hypx86_is_usable(GS_AR) && !check_bit(GS_AR, 7, 1)) {
			perr(2, 36);
		}

		// Bits 11:8 (reserved)
		if (get_reserved_0(CS_AR)) {
			perr(2, 37);
		}
		if (hypx86_is_usable(SS_AR) && get_reserved_0(SS_AR)) {
			perr(2, 38);
		}
		if (hypx86_is_usable(DS_AR) && get_reserved_0(DS_AR)) {
			perr(2, 39);
		}
		if (hypx86_is_usable(ES_AR) && get_reserved_0(ES_AR)) {
			perr(2, 40);
		}
		if (hypx86_is_usable(FS_AR) && get_reserved_0(FS_AR)) {
			perr(2, 41);
		}
		if (hypx86_is_usable(GS_AR) && get_reserved_0(GS_AR)) {
			perr(2, 42);
		}

		// TODO: Bits 14 (D/B)

		// Bit 15 (G):
		if (!check_bits(CS_LIMIT, 0, 12, 1) && !check_bit(CS_AR, 15, 0)) {
			perr(2, 43);
		}
		if (!check_bits(CS_LIMIT, 20, 32, 0) && !check_bit(CS_AR, 15, 1)) {
			perr(2, 44);
		}
		if (hypx86_is_usable(SS_AR)) {
			if (!check_bits(SS_LIMIT, 0, 12, 1) &&
			    !check_bit(SS_AR, 15, 0)) {
				perr(2, 45);
			}
			if (!check_bits(SS_LIMIT, 20, 32, 0) &&
			    !check_bit(SS_AR, 15, 1)) {
				perr(2, 46);
			}
		}
		if (hypx86_is_usable(DS_AR)) {
			if (!check_bits(DS_LIMIT, 0, 12, 1) &&
			    !check_bit(DS_AR, 15, 0)) {
				perr(2, 47);
			}
			if (!check_bits(DS_LIMIT, 20, 32, 0) &&
			    !check_bit(DS_AR, 15, 1)) {
				perr(2, 48);
			}
		}
		if (hypx86_is_usable(ES_AR)) {
			if (!check_bits(ES_LIMIT, 0, 12, 1) &&
			    !check_bit(ES_AR, 15, 0)) {
				perr(2, 49);
			}
			if (!check_bits(ES_LIMIT, 20, 32, 0) &&
			    !check_bit(ES_AR, 15, 1)) {
				perr(2, 50);
			}
		}
		if (hypx86_is_usable(FS_AR)) {
			if (!check_bits(FS_LIMIT, 0, 12, 1) &&
			    !check_bit(FS_AR, 15, 0)) {
				perr(2, 51);
			}
			if (!check_bits(FS_LIMIT, 20, 32, 0) &&
			    !check_bit(FS_AR, 15, 1)) {
				perr(2, 52);
			}
		}
		if (hypx86_is_usable(GS_AR)) {
			if (!check_bits(GS_LIMIT, 0, 12, 1) &&
			    !check_bit(GS_AR, 15, 0)) {
				perr(2, 53);
			}
			if (!check_bits(GS_LIMIT, 20, 32, 0) &&
			    !check_bit(GS_AR, 15, 1)) {
				perr(2, 54);
			}
		}

		// Bits 31:17 (reserved)
		if (get_reserved_1(CS_AR)) {
			perr(2, 55);
		}
		if (hypx86_is_usable(SS_AR) && get_reserved_1(SS_AR)) {
			perr(2, 56);
		}
		if (hypx86_is_usable(DS_AR) && get_reserved_1(DS_AR)) {
			perr(2, 57);
		}
		if (hypx86_is_usable(ES_AR) && get_reserved_1(ES_AR)) {
			perr(2, 58);
		}
		if (hypx86_is_usable(FS_AR) && get_reserved_1(FS_AR)) {
			perr(2, 59);
		}
		if (hypx86_is_usable(GS_AR) && get_reserved_1(GS_AR)) {
			perr(2, 60);
		}
	}

	// Access-rights fileds: TR
	// TODO: Bits 3:0 (Type).
	if (!check_bit(TR_AR, 4, 0)) {
		perr(2, 61);
	}
	if (!check_bit(TR_AR, 7, 1)) {
		perr(2, 62);
	}
	if (get_reserved_0(TR_AR)) {
		perr(2, 63);
	}
	if (!check_bits(TR_LIMIT, 0, 12, 1) &&
	    !check_bit(TR_AR, 15, 0)) {
		perr(2, 64);
	}
	if (!check_bits(TR_LIMIT, 20, 32, 0) &&
	    !check_bit(TR_AR, 15, 1)) {
		perr(2, 65);
	}
	if (!check_bit(TR_AR, 16, 0)) {
		perr(2, 66);
	}
	if (get_reserved_1(TR_AR)) {
		perr(2, 67);
	}

	// Access-rights fields: LDTR
	if (hypx86_is_usable(LDTR_AR)) {
		if (get_type(LDTR_AR) != 2) {
			perr(2, 68);
		}
		if (!check_bit(LDTR_AR, 4, 0)) {
			perr(2, 69);
		}
		if (!check_bit(LDTR_AR, 7, 1)) {
			perr(2, 70);
		}
		if (!check_bits(LDTR_LIMIT, 0, 12, 1) &&
		    !check_bit(LDTR_AR, 15, 0)) {
			perr(2, 71);
		}
		if (!check_bits(LDTR_LIMIT, 20, 32, 0) &&
		    !check_bit(LDTR_AR, 15, 1)) {
			perr(2, 72);
		}
		if (get_reserved_1(LDTR_AR)) {
			perr(2, 73);
		}
	}
}

void hypx86_check_guest_state_field(void) {
// 26.3.1 Checks on the Guest State Area
	pr_info("[OUR-VMCS-LOG] enter hypx86_check_guest_state_field");
	hypx86_check_guest_part1();
	hypx86_check_guest_part2();
	hypx86_check_guest_part3();
	hypx86_check_guest_part4();
	hypx86_check_guest_part5();
	hypx86_check_guest_part6();
}

void hypx86_switch_to_nonroot(void) {
	volatile int exit_reason;
	volatile int vm_inst_error;
	volatile unsigned long exit_qualification;
	volatile bool always_true = true;
	volatile u64 latest_guest_rip;

  	asm(
		__ex(ASM_VMX_VMWRITE_RSP_RDX) "\n\t"
			: : "d"((unsigned long)HOST_RSP)
		);
	dump_vmcs();
	hypx86_check_guest_state_field();
  	// asm(
	// 	__ex(ASM_VMX_VMWRITE_RSP_RDX) "\n\t"
	// 	__ex(ASM_VMX_VMLAUNCH) "\n\t"
	// 	"2: "
	// 	".pushsection .rodata \n\t"
	// 	".global hypx86_return \n\t"
	// 	"hypx86_return: " _ASM_PTR " 2b \n\t"
	// 	".popsection"
	//       : : "d"((unsigned long)GUEST_RSP)
	//       : "cc", "memory"
	//       );

	pr_info("[HYP-DEBUG] back in root! lowvisor\n");
	exit_reason = vmcs_read32(VM_EXIT_REASON);
	pr_info("[HYP-DEBUG] vm exit reason: %x\n", exit_reason);
	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	pr_info("[HYP-DEBUG] vm qualification reason: %lx\n", exit_qualification);
	vm_inst_error = vmcs_read32(VM_INSTRUCTION_ERROR);
	pr_info("[HYP-DEBUG] vm instruction error: %u\n", vm_inst_error);
	latest_guest_rip = vmcs_readl(GUEST_RIP);
	pr_info("[HYP-DEBUG] latest_guest_rip : %llx\n", latest_guest_rip);
	if (always_true)
		goto skip_nonroot;

	// asm volatile(
	// 	"1: "
	// 	".pushsection .rodata \n\t"
	// 	".global highvisor_return \n\t"
	// 	"highvisor_return: " _ASM_PTR " 1b \n\t"
	// 	".popsection"
	// 	);

	// printk("[NON-ROOT-printk] I am in non-root world! highvisor\n");
	// pr_info("I am in non-root world! highvisor\n");
skip_nonroot:
	return;
}



/*
 * void hypx86_init_vmcs_guest_state(void)
 *
 * Initialize the guest state fields essentially as a clone of
 * the host state fields. Some host state fields have fixed
 * values, and we set the corresponding guest state fields accordingly.
 *
 * we need some changes here.
 *
 * Learn from "tools/testing/selftests/kvm/lib/vmx.c"
 */
void hypx86_init_vmcs_guest_state(void) {
	u32 low32, high32;
	unsigned long tmpl;
	struct desc_ptr dt;
	unsigned long cr0, cr3, cr4;
	int cpu = raw_smp_processor_id();
	void *gdt = get_current_gdt_ro();
	unsigned long sysenter_esp;
	volatile u64 tmp_rip;

	/* control registers */
	cr0 = read_cr0();
	WARN_ON(cr0 & X86_CR0_TS);
	vmcs_writel(GUEST_CR0, cr0);

	cr3 = __read_cr3();
	vmcs_writel(GUEST_CR3, cr3);

	cr4 = cr4_read_shadow();
	cr4 &= ~((u64)1 << 17);
	vmcs_writel(GUEST_CR4, cr4);

	/* TODO : Debug register : DR7 */
	vmcs_writel(GUEST_DR7, 0x400);

	// /* TODO : RSP, RIP and RFLAGS */
	// vmcs_writel(GUEST_RSP, initial_kernel_rsp); // use original RSP, should be set right before vmlaunch?
	// vmcs_writel(GUEST_RIP, highvisor_return); // use address of next function after vmx_init (may be another function)

	tmp_rip = vmcs_readl(GUEST_RIP);
	pr_info("[HYP-DEBUG] GUEST_RIP : %llx\n", tmp_rip);
	// vmcs_writel(GUEST_RFLAGS, get_rflags()); // I think we can use the host rflags. we can only read it using asm code. look at my picture.
	vmcs_writel(GUEST_RFLAGS, get_rflags());
	pr_info("[HYP-DEBUG] RFLAGS : %llx\n", get_rflags());

	/* following fields of CS, SS, DS, ES, FS, GS, LDTR, and TR
	 *	selector (16 bits)
	 *	Base address (64 bits)
	 *	Segment limit (32 bits)
	 *	Access rights (32 bits)
	 */

	/* selector */
	vmcs_write16(GUEST_CS_SELECTOR, __KERNEL_CS);
	vmcs_write16(GUEST_SS_SELECTOR, __KERNEL_DS);
#ifndef CONFIG_X86_64
	vmcs_write16(GUEST_DS_SELECTOR, get_ds());
	vmcs_write16(GUEST_ES_SELECTOR, get_es());
	vmcs_write16(GUEST_FS_SELECTOR, get_fs());
	vmcs_write16(GUEST_GS_SELECTOR, get_gs());
	vmcs_write16(GUEST_LDTR_SELECTOR, 0);	// not sure
	vmcs_write16(GUEST_TR_SELECTOR, get_tr());
#endif
	/* base */
	vmcs_writel(GUEST_CS_BASE, 0);
	vmcs_writel(GUEST_SS_BASE, 0);
	vmcs_writel(GUEST_DS_BASE, 0);
	vmcs_writel(GUEST_ES_BASE, 0);

	// two ways for GUEST_FS_BASE, GUEST_GS_BASE. not sure am I right.
	/*
	if (likely(is_64bit_mm(current->mm))) {
		fs_base = current->thread.fsbase;
		kernel_gs_base = current->thread.gsbase;
		vmcs_writel(GUEST_FS_BASE, fs_base);
		vmcs_writel(GUEST_GS_BASE, cpu_kernelmode_gs_base(cpu));
		pr_info("[OUR-DEB-INFO-init_vmcs_guest_state] kernel_gs_base : %lu, cpu_kernelmode_gs_base : %lu\n", kernel_gs_base, cpu_kernelmode_gs_base(cpu));
	}*/
	rdmsrl(MSR_FS_BASE, tmpl);
	vmcs_writel(GUEST_FS_BASE, tmpl);
	rdmsrl(MSR_GS_BASE, tmpl);
	vmcs_writel(GUEST_GS_BASE, tmpl);

	vmcs_writel(GUEST_LDTR_BASE, 0);	// not sure. should read from host as well?
	vmcs_writel(GUEST_TR_BASE,
			(unsigned long)&get_cpu_entry_area(cpu)->tss.x86_tss);

	/* segment limit : not so important? not sure at all*/
	vmcs_write32(GUEST_CS_LIMIT, -1);
	vmcs_write32(GUEST_SS_LIMIT, -1);
	vmcs_write32(GUEST_DS_LIMIT, -1);
	vmcs_write32(GUEST_ES_LIMIT, -1);
	vmcs_write32(GUEST_FS_LIMIT, -1);
	vmcs_write32(GUEST_GS_LIMIT, -1);
	vmcs_write32(GUEST_LDTR_LIMIT, -1);
	vmcs_write32(GUEST_TR_LIMIT, 0x67);

	/* access rights, not sure */
	// please see the intel manual table
	vmcs_write32(GUEST_CS_AR_BYTES, 0xa09b);
	vmcs_write32(GUEST_SS_AR_BYTES, 0xc093);
	vmcs_write32(GUEST_DS_AR_BYTES,
		vmcs_read16(GUEST_DS_SELECTOR) == 0 ? 0x10000 : 0xc093);
	vmcs_write32(GUEST_ES_AR_BYTES,
		vmcs_read16(GUEST_ES_SELECTOR) == 0 ? 0x10000 : 0xc093);
	vmcs_write32(GUEST_FS_AR_BYTES,
		vmcs_read16(GUEST_FS_SELECTOR) == 0 ? 0x10000 : 0xc093);
	vmcs_write32(GUEST_GS_AR_BYTES,
		vmcs_read16(GUEST_GS_SELECTOR) == 0 ? 0x10000 : 0xc093);
	//vmcs_write32(GUEST_LDTR_AR_BYTES, 0x10000);
	vmcs_write32(GUEST_LDTR_AR_BYTES, 0x8082);
	vmcs_write32(GUEST_TR_AR_BYTES, 0x8b);



	/* following fields of GDTR and IDTR
	 *	Base address (64 bits)
	 *	Segment limit (32 bits)
	 */

	/* base address */
	vmcs_writel(GUEST_GDTR_BASE, (unsigned long)gdt);
	store_idt(&dt);
	vmcs_writel(GUEST_IDTR_BASE, dt.address);

	/* segment limit */
	vmcs_write32(GUEST_GDTR_LIMIT, 0xffff); // not sure, likely(right)
	vmcs_write32(GUEST_IDTR_LIMIT, 0xffff); // not sure, likely(right)


	/* the following MSRs
	 * IA32_DEBUGCTL (64 bits)
	 * IA32_SYSENTER_CS (32 bits)
	 * IA32_SYSENTER_ESP and IA32_SYSENTER_EIP (64 bits)
	 * IA32_PERF_GLOBAL_CTRL (64 bits)
	 * IA32_PAT (64 bits)
	 * IA32_EFER (64 bits)
	 * IA32_BNDCFGS (64 bits), didn't find this
	 */
	vmcs_write64(GUEST_IA32_DEBUGCTL, 0);
	rdmsr(MSR_IA32_SYSENTER_CS, low32, high32);
	vmcs_write32(GUEST_SYSENTER_CS, low32);
	rdmsrl(MSR_IA32_SYSENTER_EIP, tmpl);
	vmcs_writel(GUEST_SYSENTER_EIP, tmpl);
	rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
	vmcs_writel(GUEST_SYSENTER_ESP, sysenter_esp);

	if (vmcs_config.vmexit_ctrl & VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL) {
		rdmsr(MSR_CORE_PERF_GLOBAL_CTRL, low32, high32);
		vmcs_write64(GUEST_IA32_PERF_GLOBAL_CTRL, low32 | ((u64) high32 << 32));
	}
	if (vmcs_config.vmexit_ctrl & VM_EXIT_LOAD_IA32_PAT) {
		rdmsr(MSR_IA32_CR_PAT, low32, high32);
		vmcs_write64(GUEST_IA32_PAT, low32 | ((u64) high32 << 32));
	}
	if (vmcs_config.vmexit_ctrl & VM_EXIT_LOAD_IA32_EFER) {
		rdmsr(MSR_EFER, low32, high32);
		vmcs_write64(GUEST_IA32_EFER, low32 | ((u64) high32 << 32));
	}
	if (kvm_mpx_supported()) {
	//if (boot_cpu_has(X86_FEATURE_MPX)) {
	//	rdmsrl(MSR_IA32_BNDCFGS, tmpl);
	//	vmcs_write64(GUEST_BNDCFGS, tmpl);
		vmcs_write64(GUEST_BNDCFGS, 0);
		// not sure
	}


	/* SMBASE register (32 bits) */


	/* Guest Non-Register States, not sure
	 *	1. Activity state (32 bits)
	 *	2. Interruptibility state (32 bits)
	 *	3. Pending debug exceptions (64 bits)
	 *	4. VMCS link pointer (64 bits)
	 *	5. VMX-preemption timer value (32 bits)
	 *	6. Page-directory-pointer-table entries (PDPTEs; 64 bits each)
	 *	7. Guest interrupt status (16 bits)
	 *		a. Requesting virtual interrupt (RVI)
	 *		b. Servicing virtual interrupt (SVI)
	 *	8. PML index (16 bits)
	 */
	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS, 0);
	//vmcs_write64(VMCS_LINK_POINTER, 0xffffffffffffffff);
	vmcs_write64(VMCS_LINK_POINTER, -1ul);
		// we don't have shadow vmcs?
	vmcs_write32(VMX_PREEMPTION_TIMER_VALUE, 0);
	vmcs_write32(GUEST_PDPTR0, 0);
	vmcs_write32(GUEST_PDPTR0_HIGH, 0);
	vmcs_write32(GUEST_PDPTR1, 0);
	vmcs_write32(GUEST_PDPTR1_HIGH, 0);
	vmcs_write32(GUEST_PDPTR2, 0);
	vmcs_write32(GUEST_PDPTR2_HIGH, 0);
	vmcs_write32(GUEST_PDPTR3, 0);
	vmcs_write32(GUEST_PDPTR3_HIGH, 0);
		// if we enable EPT then we need to change PDPTR
	vmcs_write16(GUEST_INTR_STATUS, 0);
	vmcs_write16(GUEST_PML_INDEX, 0);
}

/*
 * void hypx86_init_vmcs_host_state(void)
 *
 * Initialize the host state fields based on the current host state, with
 * the exception of HOST_RSP and HOST_RIP, which should be set by
 * vmlaunch or vmresume.
 *
 * we need some changes here.
 *
 * Learn from
 *	tools/testing/selftests/kvm/lib/vmx.c
 *	arch/x86/kvm/vmx.c - vmx_set_constant_host_state
 *	arch/x86/kvm/vmx.c - vmx_save_host_state
 *	arch/x86/kvm/vmx.c - vmx_vcpu_load
 *
 * Potential Bugs
 *	1. some registers can't be initiated in this function. should be later?
 */
void hypx86_init_vmcs_host_state(void) {
	u32 low32, high32;
	unsigned long tmpl;
	struct desc_ptr dt;
	unsigned long cr0, cr3, cr4;
	unsigned long fs_base, kernel_gs_base;	// probably these two should be init later than this function.
	int cpu = raw_smp_processor_id();
	void *gdt = get_current_gdt_ro();
	unsigned long sysenter_esp;

	/* control registers */
	cr0 = read_cr0();
	//cr0 = get_cr0();
	WARN_ON(cr0 & X86_CR0_TS);
	vmcs_writel(HOST_CR0, cr0);

	cr3 = __read_cr3();
	//cr3 = get_cr3();
	vmcs_writel(HOST_CR3, cr3);

	cr4 = cr4_read_shadow();
	//cr4 = get_cr4();
	vmcs_writel(HOST_CR4, cr4);


	/* RSP, RIP*/
	vmcs_writel(HOST_RSP, (u64)&lowvisor_stack[LOW_VISOR_STACK_SIZE]);
	vmcs_writel(HOST_RIP, hypx86_return);


	/* Selector fields of CS, SS, DS, ES, FS, GS, and TR */
	vmcs_write16(HOST_CS_SELECTOR, __KERNEL_CS);

	vmcs_write16(HOST_SS_SELECTOR, __KERNEL_DS);

	vmcs_write16(HOST_DS_SELECTOR, 0); // not sure
	vmcs_write16(HOST_ES_SELECTOR, 0); // not sure

	vmcs_write16(HOST_FS_SELECTOR, 0); // not sure
	vmcs_write16(HOST_GS_SELECTOR, 0); // not sure

	vmcs_write16(HOST_TR_SELECTOR, GDT_ENTRY_TSS*8);

	/* Base-address fields for FS, GS, TR, GDTR, and IDTR (64 bits) */
	/* maybe FS, GS, TR and GDTR should be inited later than this func */
	fs_base = current->thread.fsbase;
	kernel_gs_base = current->thread.gsbase;

	vmcs_writel(HOST_FS_BASE, fs_base);
	vmcs_writel(HOST_GS_BASE, cpu_kernelmode_gs_base(cpu));
	pr_info("[OUR-DEB-INFO] kernel_gs_base : %lu, cpu_kernelmode_gs_base : %lu\n", kernel_gs_base, cpu_kernelmode_gs_base(cpu));

	vmcs_writel(HOST_TR_BASE,
			(unsigned long)&get_cpu_entry_area(cpu)->tss.x86_tss);
	vmcs_writel(HOST_GDTR_BASE, (unsigned long)gdt);

	store_idt(&dt);
	vmcs_writel(HOST_IDTR_BASE, dt.address);

	/* following MSRs
	 * IA32_SYSENTER_CS (32 bits)
	 * IA32_SYSENTER_ESP and IA32_SYSENTER_EIP (64 bits)
	 * IA32_PERF_GLOBAL_CTRL (64 bits)
	 * IA32_PAT (64 bits)
	 * IA32_EFER (64 bits)
	 *
	 * maybe IA32_SYSENTER_ESP should be set later than this funciton.
	 */
	rdmsr(MSR_IA32_SYSENTER_CS, low32, high32);
	vmcs_write32(HOST_IA32_SYSENTER_CS, low32);
	rdmsrl(MSR_IA32_SYSENTER_EIP, tmpl);
	vmcs_writel(HOST_IA32_SYSENTER_EIP, tmpl);

	rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
	vmcs_writel(HOST_IA32_SYSENTER_ESP, sysenter_esp);

	//IA32_PERF_GLOBAL_CTRL, IA32_PAT, IA32_EFER don't know how to set
}

void hypx86_init_vmcs_control_fields(void) {
	//u32 vmx_msr_low, vmx_msr_high;
	u32 min = 0, opt = 0;
	//u32 tmp = 0;
	u64 pin_based_vm_exec_control = 0;
    //u32 pin_based_high32 = 0;
	u64 cpu_based_exec_control = 0;
	//u32 cpu_based_2nd_exec_control = 0;
	//u32 _vmexit_control = 0;
	//u32 _vmentry_control = 0;
	/* VM-execution control fields
	 *	1. Pin-Based VM-Execution Controls (32 bits)
	 *	2. Processor-Based VM-Execution Controls (32 bits)
	 *	3. Exception Bitmap (32 bits)
	 *	4. I/O-Bitmap Addresses (64 bits * 2 ?)
	 *	5. CR3_TARGET_COUNT (32 bits)
	 *	6. TPR_THRESHOLD (32 bits)
	 *	7. SECONDARY_VM_EXEC_CONTROL?
	 *	8. Guest/Host Masks and Read Shadows for CR0 and CR4 (64 bits)
	 *	9. others seem like are not necessary?
	 */
	min = PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING;
	opt = PIN_BASED_VIRTUAL_NMIS | PIN_BASED_POSTED_INTR |
			PIN_BASED_VMX_PREEMPTION_TIMER;
	pin_based_vm_exec_control = get_control_field_value(min, 0, MSR_IA32_VMX_PINBASED_CTLS);
	pr_info("pin_based_vm_ctl from rdmsr: %llx\n", pin_based_vm_exec_control);
	//vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, get_control_field_value(0, 0, MSR_IA32_VMX_PINBASED_CTLS));
    pin_based_vm_exec_control &= ~PIN_BASED_EXT_INTR_MASK;
    pin_based_vm_exec_control &= ~PIN_BASED_NMI_EXITING;
    pin_based_vm_exec_control &= ~PIN_BASED_VIRTUAL_NMIS;
    pin_based_vm_exec_control &= ~PIN_BASED_VMX_PREEMPTION_TIMER;
    pin_based_vm_exec_control &= ~PIN_BASED_POSTED_INTR;
    vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, pin_based_vm_exec_control);


    rdmsrl(MSR_IA32_VMX_PROCBASED_CTLS, cpu_based_exec_control);
	// bit 28 use MSR bitmaps
	cpu_based_exec_control |= (1 << 28);
    vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_exec_control);
	vmcs_write32(EXCEPTION_BITMAP, 0);	// we can control page-fault here
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, 0);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, -1); /* never match, I don't know what is this */
	vmcs_write32(CR3_TARGET_COUNT, 0);
	vmcs_write32(TPR_THRESHOLD, 0);

	//cpu_based_exec_control = 0x80; // Unrestricted guest
	vmcs_write32(SECONDARY_VM_EXEC_CONTROL, 0);
	//vmcs_write32(SECONDARY_VM_EXEC_CONTROL, cpu_based_exec_control);
	vmcs_writel(CR0_GUEST_HOST_MASK, 0);
	vmcs_writel(CR4_GUEST_HOST_MASK, 0);
	vmcs_writel(CR0_READ_SHADOW, get_cr0());
	vmcs_writel(CR4_READ_SHADOW, get_cr4());

	/* VM-exit control fields (basic)
	 *	1. VM-Exit Controls
	 *	2. VM_EXIT_MSR_STORE_COUNT, VM_EXIT_MSR_LOAD_COUNT
	 */
	min = VM_EXIT_SAVE_DEBUG_CONTROLS | VM_EXIT_ACK_INTR_ON_EXIT | VM_EXIT_HOST_ADDR_SPACE_SIZE;
	opt = VM_EXIT_SAVE_IA32_PAT | VM_EXIT_LOAD_IA32_PAT | VM_EXIT_CLEAR_BNDCFGS;
	vmcs_write32(VM_EXIT_CONTROLS, get_control_field_value(min, opt, MSR_IA32_VMX_EXIT_CTLS));
	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, 0);

	/* VM-entry control fields (basic)
	 *	1. VM-Entry Controls
	 *	2. VM_ENTRY_MSR_LOAD_COUNT
	 *	3. VM-Entry Controls for MSRs (VM-entry MSR-load count, address)
	 *	4. VM-Entry Controls for Event Injection (VM-entry interruption-information field (32 bits))
	 */
	min = VM_ENTRY_LOAD_DEBUG_CONTROLS;
	opt = VM_ENTRY_LOAD_IA32_PAT | VM_ENTRY_LOAD_BNDCFGS;
	// it looks like we must open IA-32e mode guest
	vmcs_write32(VM_ENTRY_CONTROLS, 0x200 | get_control_field_value(min, opt, MSR_IA32_VMX_ENTRY_CTLS));
	//vmcs_write32(VM_ENTRY_CONTROLS, get_control_field_value(min, opt, MSR_IA32_VMX_ENTRY_CTLS));
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);

	/* VM-exit information fields */
}



int hyp_handle_cpuid(struct kvm_vcpu *vcpu)
{
	u32 eax, ebx, ecx, edx;
	u64 rip;

	eax = hyp_register_read(vcpu, VCPU_REGS_RAX);
	ecx = hyp_register_read(vcpu, VCPU_REGS_RCX);
	native_cpuid(&eax, &ebx, &ecx, &edx);
	kvm_register_write(vcpu, VCPU_REGS_RAX, eax);
	kvm_register_write(vcpu, VCPU_REGS_RBX, ebx);
	kvm_register_write(vcpu, VCPU_REGS_RCX, ecx);
	kvm_register_write(vcpu, VCPU_REGS_RDX, edx);

	return hyp_skip_emulated_instruction(vcpu);
}

/* handlers jump table */
int (*const hyp_exit_handlers[])(struct kvm_vcpu *vcpu) = {
	[EXIT_REASON_CPUID] = hyp_handle_cpuid,
};

void run_hyp_kernel(void) {

/* brutally change stack , TODO: should reserve space for local vars */
asm volatile("mov %0, %%" _ASM_SP " \n\t": : "c"(lowvisor_stack_end));
	volatile int exit_reason;
	volatile int vm_inst_error;
	volatile unsigned long exit_qualification;
	volatile bool always_true = true;
	volatile u64 latest_guest_rip;
resume_kernel:
	vmcs_writel(GUEST_RSP, kernel_vmx.vcpu.arch.regs[VCPU_REGS_RSP]);
	vmcs_writel(GUEST_RIP, kernel_vmx.vcpu.arch.regs[VCPU_REGS_RIP]);


	kernel_vmx.__launched = kernel_vmx.vmcs01.launched;



	pr_info("[HYP-DEBUG] launch into nonroot kernel\n");
	asm(
		/* Store host registers */
		"push %%" _ASM_DX "; push %%" _ASM_BP ";"
		"push %%" _ASM_CX " \n\t" /* placeholder for guest rcx */
		"push %%" _ASM_CX " \n\t"
		"2: \n\t"
		__ex(ASM_VMX_VMWRITE_RSP_RDX) "\n\t"
		"1: \n\t"
		/* Check if vmlaunch of vmresume is needed */
		"cmpl $0, %c[launched](%0) \n\t"
		/* Load guest registers.  Don't clobber flags. */
		"mov %c[rax](%0), %%" _ASM_AX " \n\t"
		"mov %c[rbx](%0), %%" _ASM_BX " \n\t"
		"mov %c[rdx](%0), %%" _ASM_DX " \n\t"
		"mov %c[rsi](%0), %%" _ASM_SI " \n\t"
		"mov %c[rdi](%0), %%" _ASM_DI " \n\t"
		"mov %c[rbp](%0), %%" _ASM_BP " \n\t"
#ifdef CONFIG_X86_64
		"mov %c[r8](%0),  %%r8  \n\t"
		"mov %c[r9](%0),  %%r9  \n\t"
		"mov %c[r10](%0), %%r10 \n\t"
		"mov %c[r11](%0), %%r11 \n\t"
		"mov %c[r12](%0), %%r12 \n\t"
		"mov %c[r13](%0), %%r13 \n\t"
		"mov %c[r14](%0), %%r14 \n\t"
		"mov %c[r15](%0), %%r15 \n\t"
#endif
		"mov %c[rcx](%0), %%" _ASM_CX " \n\t" /* kills %0 (ecx) */

		/* Enter guest mode */
		"jne 1f \n\t"
		__ex(ASM_VMX_VMLAUNCH) "\n\t"
		"jmp 2f \n\t"
		"1: " __ex(ASM_VMX_VMRESUME) "\n\t"
		"2: "
		/* Save guest registers, load host registers, keep flags */
		"mov %0, %c[wordsize](%%" _ASM_SP ") \n\t"
		"pop %0 \n\t"
		"setbe %c[fail](%0)\n\t"
		"mov %%" _ASM_AX ", %c[rax](%0) \n\t"
		"mov %%" _ASM_BX ", %c[rbx](%0) \n\t"
		__ASM_SIZE(pop) " %c[rcx](%0) \n\t"
		"mov %%" _ASM_DX ", %c[rdx](%0) \n\t"
		"mov %%" _ASM_SI ", %c[rsi](%0) \n\t"
		"mov %%" _ASM_DI ", %c[rdi](%0) \n\t"
		"mov %%" _ASM_BP ", %c[rbp](%0) \n\t"
#ifdef CONFIG_X86_64
		"mov %%r8,  %c[r8](%0) \n\t"
		"mov %%r9,  %c[r9](%0) \n\t"
		"mov %%r10, %c[r10](%0) \n\t"
		"mov %%r11, %c[r11](%0) \n\t"
		"mov %%r12, %c[r12](%0) \n\t"
		"mov %%r13, %c[r13](%0) \n\t"
		"mov %%r14, %c[r14](%0) \n\t"
		"mov %%r15, %c[r15](%0) \n\t"
		"xor %%r8d,  %%r8d \n\t"
		"xor %%r9d,  %%r9d \n\t"
		"xor %%r10d, %%r10d \n\t"
		"xor %%r11d, %%r11d \n\t"
		"xor %%r12d, %%r12d \n\t"
		"xor %%r13d, %%r13d \n\t"
		"xor %%r14d, %%r14d \n\t"
		"xor %%r15d, %%r15d \n\t"
#endif
		"mov %%cr2, %%" _ASM_AX "   \n\t"
		"mov %%" _ASM_AX ", %c[cr2](%0) \n\t"

		"xor %%eax, %%eax \n\t"
		"xor %%ebx, %%ebx \n\t"
		"xor %%esi, %%esi \n\t"
		"xor %%edi, %%edi \n\t"
		"pop  %%" _ASM_BP "; pop  %%" _ASM_DX " \n\t"
		".pushsection .rodata \n\t"
		".global hypx86_return \n\t"
		"hypx86_return: " _ASM_PTR " 2b \n\t"
		".popsection"
	      : : "c"(&kernel_vmx), "d"((unsigned long)HOST_RSP),
		[launched]"i"(offsetof(struct vcpu_vmx, __launched)),
		[fail]"i"(offsetof(struct vcpu_vmx, fail)),
		[host_rsp]"i"(offsetof(struct vcpu_vmx, host_rsp)),
		[rax]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RAX])),
		[rbx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RBX])),
		[rcx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RCX])),
		[rdx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RDX])),
		[rsi]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RSI])),
		[rdi]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RDI])),
		[rbp]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RBP])),
#ifdef CONFIG_X86_64
		[r8]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R8])),
		[r9]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R9])),
		[r10]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R10])),
		[r11]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R11])),
		[r12]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R12])),
		[r13]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R13])),
		[r14]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R14])),
		[r15]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R15])),
#endif
		[cr2]"i"(offsetof(struct vcpu_vmx, vcpu.arch.cr2)),
		[wordsize]"i"(sizeof(ulong))
	      : "cc", "memory"
#ifdef CONFIG_X86_64
		, "rax", "rbx", "rdi"
		, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
#else
		, "eax", "ebx", "edi"
#endif
	      );

	pr_info("[HYP-DEBUG] back in root! lowvisor\n");
	exit_reason = vmcs_read32(VM_EXIT_REASON);
	pr_info("[HYP-DEBUG] vm exit reason: %x\n", exit_reason);
	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	pr_info("[HYP-DEBUG] vm qualification reason: %lx\n", exit_qualification);
	vm_inst_error = vmcs_read32(VM_INSTRUCTION_ERROR);
	pr_info("[HYP-DEBUG] vm instruction error: %u\n", vm_inst_error);
	latest_guest_rip = vmcs_readl(GUEST_RIP);
	pr_info("[HYP-DEBUG] latest_guest_rip : %llx\n", latest_guest_rip);


	kernel_vmx.vmcs01.launched = 1;
	/* handle exits */
	hyp_exit_handlers[exit_reason](&kernel_vmx.vcpu);

	if (always_true)
		goto resume_kernel;
}

void resume_hyp_kernel(void) {

}
