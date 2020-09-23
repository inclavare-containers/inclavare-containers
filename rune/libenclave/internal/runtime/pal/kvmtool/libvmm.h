#ifndef LIBVMM_HEADER_H
#define LIBVMM_HEADER_H

#include <linux/types.h>

struct kvm;

/* vm create */
struct kvm *libvmm_create_vm(void);

/* vm config */
int libvmm_vm_set_memory(struct kvm *vm, size_t memsize /* MB */);
int libvmm_vm_set_cpus(struct kvm *vm, int nrcpus);
int libvmm_vm_set_kernel(struct kvm *vm, const char *kernel, const char *initrd);
int libvmm_vm_set_rootfs(struct kvm *vm, const char *rootfs);
int libvmm_vm_set_init(struct kvm *vm, const char *init);
int libvmm_vm_set_vsock(struct kvm *vm, u64 vsock_cid);

/* vm control */
int libvmm_vm_init(struct kvm *vm);
int libvmm_vm_run(struct kvm *vm);
int libvmm_vm_kill(struct kvm *vm);
int libvmm_vm_exit(struct kvm *vm);

#endif /* ! LIBVMM_HEADER_H */
