#include <stdio.h>
#include "libvmm.h"

int main(int argc, char *argv[])
{
    struct kvm *vm;
    const char *rootfs = "default";

    if (argc > 1)
        rootfs = argv[1];

    vm = libvmm_create_vm();
    libvmm_vm_set_memory(vm, 512);
    libvmm_vm_set_cpus(vm, 1);
    libvmm_vm_set_kernel(vm, "bzImage", NULL);
    libvmm_vm_set_rootfs(vm, rootfs);
    libvmm_vm_set_vsock(vm, 3);

    libvmm_vm_init(vm);
    libvmm_vm_run(vm);
    libvmm_vm_exit(vm);

    return 0;
}
