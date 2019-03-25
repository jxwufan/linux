#define LOW_VISOR_STACK_SIZE 128
unsigned long low_visor_stack[LOW_VISOR_STACK_SIZE];
extern const ulong hypx86_return; // TODO: we need a to add a label called hypx86_return like "vm_return" in assembly code as the entrance of our ilowvisor handler.



void hypx86_set_up_vmcs(void);
static void hypx86_init_vmcs_guest_state(void);
static void hypx86_init_vmcs_host_state(void);
static void hypx86_init_vmcs_control_fields(void);


/* learn from tools/testing/selftests/kvm/include/x86.h */
static inline uint16_t get_es(void)
{
	uint16_t es;

	__asm__ __volatile__("mov %%es, %[es]"
			     : /* output */ [es]"=rm"(es));
	return es;
}

static inline uint16_t get_cs(void)
{
	uint16_t cs;

	__asm__ __volatile__("mov %%cs, %[cs]"
			     : /* output */ [cs]"=rm"(cs));
	return cs;
}

static inline uint16_t get_ss(void)
{
	uint16_t ss;

	__asm__ __volatile__("mov %%ss, %[ss]"
			     : /* output */ [ss]"=rm"(ss));
	return ss;
}

static inline uint16_t get_ds(void)
{
	uint16_t ds;

	__asm__ __volatile__("mov %%ds, %[ds]"
			     : /* output */ [ds]"=rm"(ds));
	return ds;
}

static inline uint16_t get_fs(void)
{
	uint16_t fs;

	__asm__ __volatile__("mov %%fs, %[fs]"
			     : /* output */ [fs]"=rm"(fs));
	return fs;
}

static inline uint16_t get_gs(void)
{
	uint16_t gs;

	__asm__ __volatile__("mov %%gs, %[gs]"
			     : /* output */ [gs]"=rm"(gs));
	return gs;
}

static inline uint16_t get_tr(void)
{
	uint16_t tr;

	__asm__ __volatile__("str %[tr]"
			     : /* output */ [tr]"=rm"(tr));
	return tr;
}


static inline uint64_t get_cr0(void)
{
	uint64_t cr0;

	__asm__ __volatile__("mov %%cr0, %[cr0]"
			     : /* output */ [cr0]"=r"(cr0));
	return cr0;
}

static inline uint64_t get_cr3(void)
{
	uint64_t cr3;

	__asm__ __volatile__("mov %%cr3, %[cr3]"
			     : /* output */ [cr3]"=r"(cr3));
	return cr3;
}

static inline uint64_t get_cr4(void)
{
	uint64_t cr4;

	__asm__ __volatile__("mov %%cr4, %[cr4]"
			     : /* output */ [cr4]"=r"(cr4));
	return cr4;
}

static inline void set_cr4(uint64_t val)
{
	__asm__ __volatile__("mov %0, %%cr4" : : "r" (val) : "memory");
}

static inline uint64_t get_gdt_base(void)
{
	struct desc_ptr gdt;
	__asm__ __volatile__("sgdt %[gdt]"
			     : /* output */ [gdt]"=m"(gdt));
	return gdt.address;
}

static inline uint64_t get_idt_base(void)
{
	struct desc_ptr idt;
	__asm__ __volatile__("sidt %[idt]"
			     : /* output */ [idt]"=m"(idt));
	return idt.address;
}

