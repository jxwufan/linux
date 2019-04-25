#include <asm/msr.h>
#define LOW_VISOR_STACK_SIZE 4096

typedef unsigned short u16;

typedef unsigned char u8;
typedef unsigned int u32;

unsigned long low_visor_stack[LOW_VISOR_STACK_SIZE];
extern const unsigned long hypx86_return; // TODO: we need a to add a label called hypx86_return like "vm_return" in assembly code as the entrance of our ilowvisor handler.
extern const unsigned long highvisor_return;


void hypx86_set_up_vmcs(void);
void hypx86_init_vmcs_guest_state(void);
void hypx86_init_vmcs_host_state(void);
void hypx86_init_vmcs_control_fields(void);
void hypx86_switch_to_nonroot(void);

/* learn from tools/testing/selftests/kvm/include/x86.h */
static inline u16 get_es(void)
{
	u16 es;

	__asm__ __volatile__("mov %%es, %[es]"
			     : /* output */ [es]"=rm"(es));
	return es;
}

static inline u16 get_cs(void)
{
	u16 cs;

	__asm__ __volatile__("mov %%cs, %[cs]"
			     : /* output */ [cs]"=rm"(cs));
	return cs;
}

static inline u16 get_ss(void)
{
	u16 ss;

	__asm__ __volatile__("mov %%ss, %[ss]"
			     : /* output */ [ss]"=rm"(ss));
	return ss;
}

static inline u16 get_ds(void)
{
	u16 ds;

	__asm__ __volatile__("mov %%ds, %[ds]"
			     : /* output */ [ds]"=rm"(ds));
	return ds;
}

static inline u16 get_fs(void)
{
	u16 fs;

	__asm__ __volatile__("mov %%fs, %[fs]"
			     : /* output */ [fs]"=rm"(fs));
	return fs;
}

static inline u16 get_gs(void)
{
	u16 gs;

	__asm__ __volatile__("mov %%gs, %[gs]"
			     : /* output */ [gs]"=rm"(gs));
	return gs;
}

static inline u16 get_tr(void)
{
	u16 tr;

	__asm__ __volatile__("str %[tr]"
			     : /* output */ [tr]"=rm"(tr));
	return tr;
}


static inline u64 get_cr0(void)
{
	u64 cr0;

	__asm__ __volatile__("mov %%cr0, %[cr0]"
			     : /* output */ [cr0]"=r"(cr0));
	return cr0;
}

static inline u64 get_cr3(void)
{
	u64 cr3;

	__asm__ __volatile__("mov %%cr3, %[cr3]"
			     : /* output */ [cr3]"=r"(cr3));
	return cr3;
}

static inline u64 get_cr4(void)
{
	u64 cr4;

	__asm__ __volatile__("mov %%cr4, %[cr4]"
			     : /* output */ [cr4]"=r"(cr4));
	return cr4;
}

static inline void set_cr4(u64 val)
{
	__asm__ __volatile__("mov %0, %%cr4" : : "r" (val) : "memory");
}

static inline u64 get_rflags(void)
{
	u64 rflags;

	__asm__ __volatile__("push %%rax \n\t"
						 "pushf \n\t"
						 "pop %%rax \n\t"
						 "mov %%rax, %[rflags]\n\t"
						 "pop %%rax \n\t"
			: [rflags]"=r"(rflags)
			: : "rax", "memory");
	return rflags;
}


static u32 get_control_field_value(u32 ctl_min, u32 ctl_opt, u32 msr) {
	u32 vmx_msr_low, vmx_msr_high;
	u32 ctl = ctl_min | ctl_opt;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);
	ctl &= vmx_msr_high;	/* bit == 0 in high word ==> must be zero */
	ctl |= vmx_msr_low;		/* bit == 1 in low word ==> must be one */

	/* Ensure minimum (required) set of control bits are supported */
	pr_info("[HYPX86-DEBUG] ctl : %x, ctl_min : %x\n", ctl, ctl_min);
	if (ctl_min & ~ctl) {
		pr_info("[HYPE-X86-BUG] control field setting went wrong");
		return -1;
	}

	return ctl;
}
