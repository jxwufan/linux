#define LOW_VISOR_STACK_SIZE 128
unsigned long low_visor_stack[LOW_VISOR_STACK_SIZE];
extern const ulong hypx86_return; // TODO: we need a to add a label called hypx86_return like "vm_return" in assembly code as the entrance of our ilowvisor handler.



void hypx86_set_up_vmcs(void);
static void hypx86_init_vmcs_guest_state(void);
static void hypx86_init_vmcs_host_state(void);
