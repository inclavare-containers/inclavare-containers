#include <stdbool.h>
#include <pthread.h>

#include <linux/types.h>
#include <linux/err.h>

#include "kvm/kvm.h"
#include "kvm/term.h"
#include "kvm/kvm-cpu.h"
#include "kvm/virtio-9p.h"
#include "kvm/util-init.h"

#include "libvmm.h"

bool do_debug_print = false;

__thread struct kvm_cpu *current_kvm_cpu;

struct kvm *libvmm_create_vm(void)
{
    struct kvm *vm;

    vm = kvm__new();
    if (IS_ERR(vm))
        return NULL;

    vm->cfg.custom_rootfs_name = "default";
    vm->cfg.dev = "/dev/kvm" /* DEFAULT_KVM_DEV */;
    vm->cfg.console = "serial" /* DEFAULT_CONSOLE */;
    vm->cfg.active_console = CONSOLE_8250;
    vm->cfg.no_net = 1;

    return vm;
}

int libvmm_vm_set_memory(struct kvm *vm, size_t memsize /* MB */)
{
    vm->cfg.ram_size = (memsize <<= 20/* MB_SHIFT */);
    return 0;
}

int libvmm_vm_set_cpus(struct kvm *vm, int nrcpus)
{
    vm->cfg.nrcpus = nrcpus;
    return 0;
}

int libvmm_vm_set_kernel(struct kvm *vm, const char *kernel, const char *initrd)
{
    vm->cfg.kernel_filename = kernel;
    vm->cfg.initrd_filename = initrd;
    return 0;
}

int libvmm_vm_set_rootfs(struct kvm *vm, const char *rootfs)
{
    int ret;

    ret = virtio_9p__register(vm, rootfs, "/dev/root");
    if (ret < 0)
        return ret;

    ret = virtio_9p__register(vm, "/", "hostfs");
    if (ret < 0) {
        /* TODO: clean */
    }

    vm->cfg.custom_rootfs = 1;

    return ret;
}

int libvmm_vm_set_init(struct kvm *vm, const char *init)
{
    vm->cfg.real_init = init;
    return 0;
}

int libvmm_vm_set_vsock(struct kvm *vm, u64 vsock_cid)
{
    vm->cfg.vsock_cid = vsock_cid;
    return 0;
}

/* TODO
int libvmm_vm_set_share_dir(struct kvm *vm, const char *path, const char *tag)
{
    return -EINVAL;
}
*/

#define KERNEL_COMMANDLINE_COMMON \
            "noapic noacpi pci=conf1 reboot=k panic=1" \
            " i8042.direct=1 i8042.dumbkbd=1 i8042.nopnp=1" \
            " earlyprintk=serial i8042.noaux=1" \
            " console=tty0 console=ttyS0,115200n8"

int libvmm_vm_init(struct kvm *vm)
{
    static char cmdline[BUFSIZ];
    int ret;

    strncat(cmdline, KERNEL_COMMANDLINE_COMMON, sizeof(cmdline) - 1);
    if (vm->cfg.custom_rootfs) {
        strncat(cmdline,
                    " rw"
                    " rootflags=trans=virtio,version=9p2000.L,cache=loose"
                    " rootfstype=9p",
                    sizeof(cmdline) - 1);
    } else if (vm->cfg.initrd_filename) {
        strncat(cmdline, " root=/dev/vda rw", sizeof(cmdline) - 1);
    } else {
        return -EINVAL;
    }

    if (vm->cfg.real_init) {
        strncat(cmdline, " init=", sizeof(cmdline) - 1);
        strncat(cmdline, vm->cfg.real_init, sizeof(cmdline) - 1);
    }
    cmdline[sizeof(cmdline) - 1] = '\0';

    vm->cfg.real_cmdline = cmdline;

    ret = init_list__init(vm);
    if (ret < 0)
        return ret;

    return 0;
}

static void *kvm_cpu_thread(void *arg)
{
	char name[16];

	current_kvm_cpu = arg;

	sprintf(name, "kvm-vcpu-%lu", current_kvm_cpu->cpu_id);
	kvm__set_thread_name(name);

	if (kvm_cpu__start(current_kvm_cpu))
		goto panic_kvm;

	return (void *) (intptr_t) 0;

panic_kvm:
	fprintf(stderr, "KVM exit reason: %u (\"%s\")\n",
		current_kvm_cpu->kvm_run->exit_reason,
		kvm_exit_reasons[current_kvm_cpu->kvm_run->exit_reason]);
	if (current_kvm_cpu->kvm_run->exit_reason == KVM_EXIT_UNKNOWN)
		fprintf(stderr, "KVM exit code: 0x%llu\n",
			(unsigned long long)current_kvm_cpu->kvm_run->hw.hardware_exit_reason);

	kvm_cpu__set_debug_fd(STDOUT_FILENO);
	kvm_cpu__show_registers(current_kvm_cpu);
	kvm_cpu__show_code(current_kvm_cpu);
	kvm_cpu__show_page_tables(current_kvm_cpu);

	return (void *) (intptr_t) 1;
}

int libvmm_vm_run(struct kvm *vm)
{
    int i;
    int ret;

    for (i = 0; i < vm->nrcpus; i++) {
        ret = pthread_create(&vm->cpus[i]->thread, NULL,
                            kvm_cpu_thread, vm->cpus[i]);
        if (ret) {
            /* TODO */
            return ret;
        }
    }

    pthread_join(vm->cpus[0]->thread, NULL);

    return kvm_cpu__exit(vm);
}

int libvmm_vm_kill(struct kvm *vm)
{
    pthread_kill(vm->cpus[0]->thread, SIGKVMEXIT);
    return 0;
}

int libvmm_vm_exit(struct kvm *vm)
{
    init_list__exit(vm);
    return 0;
}
