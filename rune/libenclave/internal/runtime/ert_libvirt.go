package runtime

import (
	"fmt"
	libvirt "libvirt.org/libvirt-go"
	"os"
)

type EnclaveRuntimeLibvirt struct {
}

func (rt *EnclaveRuntimeLibvirt) Version() int32 {
	return 1
}

func (rt *EnclaveRuntimeLibvirt) Capability() uint32 {
	return 0
}

/* cpus, memory, kernel, rootfs, init, vsock, ..., qemu cmdline set in args */
func (rt *EnclaveRuntimeLibvirt) Create(loglevel string, args string) (string, error) {
	conn, err := libvirt.NewConnect("qemu://system")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	/* native cmdline to xml desc */
	xmldesc, err := conn.DomainXMLFromNative("qemu-argv", args, 0)
	if err != nil {
		return "", err
	}

	/* create domain from xml */
	domain, err := conn.DomainDefineXML(xmldesc)
	if err != nil {
		return "", err
	}
	defer domain.Free()

	/* UUID as enclave ID */
	uuid, err := domain.GetUUIDString()
	if err != nil {
		return "", err
	}

	return uuid, nil
}

func (rt *EnclaveRuntimeLibvirt) Delete(id string) error {
	conn, err := libvirt.NewConnect("qemu://system")
	if err != nil {
		return err
	}
	defer conn.Close()

	domain, err := conn.LookupDomainByUUIDString(id)
	if err != nil {
		return err
	}
	defer domain.Free()

	domain.Destroy()
	domain.Undefine()

	return nil
}

func (rt *EnclaveRuntimeLibvirt) Init(id string) error {
	return fmt.Errorf("Not implemented for libvirt init")
}

func (rt *EnclaveRuntimeLibvirt) Spawn(id string, args string) (int, error) {
	return -1, fmt.Errorf("Not implemented for libvirt spawn")
}

func (rt *EnclaveRuntimeLibvirt) Exec(id string, pid int, args []string, envp []string, stdio [3]*os.File) error {
	conn, err := libvirt.NewConnect("qemu://system")
	if err != nil {
		return err
	}
	defer conn.Close()

	domain, err := conn.LookupDomainByUUIDString(id)
	if err != nil {
		return err
	}
	defer domain.Free()

	/* launch it */
	return domain.Create()
}

func (rt *EnclaveRuntimeLibvirt) Kill(id string, pid int, sig int) error {
	conn, err := libvirt.NewConnect("qemu://system")
	if err != nil {
		return err
	}
	defer conn.Close()

	domain, err := conn.LookupDomainByUUIDString(id)
	if err != nil {
		return err
	}
	defer domain.Free()

	return domain.Shutdown()
}

func (rt *EnclaveRuntimeLibvirt) Attest(id string) error {
	return fmt.Errorf("Not implemented for libvirt attest")
}

/* ctor, register qemu-based enclave */
func init() {
	RuntimeRegister("libvirt", &EnclaveRuntimeLibvirt{})
}
