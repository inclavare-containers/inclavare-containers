package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

const configTemplate = `{"ociVersion":"1.0.1-dev","process":{"user":{"uid":0,"gid":0},"args":["/pause"],"env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","ENCLAVE_TYPE=intelSgx"],"cwd":"/","capabilities":{"bounding":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"effective":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"inheritable":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"permitted":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"]},"noNewPrivileges":true,"oomScoreAdj":-998},"root":{"path":"rootfs","readonly":true},"mounts":[{"destination":"/proc","type":"proc","source":"proc","options":["nosuid","noexec","nodev"]},{"destination":"/dev","type":"tmpfs","source":"tmpfs","options":["nosuid","strictatime","mode=755","size=65536k"]},{"destination":"/dev/pts","type":"devpts","source":"devpts","options":["nosuid","noexec","newinstance","ptmxmode=0666","mode=0620","gid=5"]},{"destination":"/dev/shm","type":"tmpfs","source":"shm","options":["nosuid","noexec","nodev","mode=1777","size=65536k"]},{"destination":"/dev/mqueue","type":"mqueue","source":"mqueue","options":["nosuid","noexec","nodev"]},{"destination":"/sys","type":"sysfs","source":"sysfs","options":["nosuid","noexec","nodev","ro"]},{"destination":"/dev/shm","type":"bind","source":"/run/containerd/io.containerd.grpc.v1.cri/sandboxes/8e5f48047dfc52c9ee043129580d5df9b70f6c0828d96fbb396fb269e114fbfd/shm","options":["rbind","ro"]}],"annotations":{"io.kubernetes.cri.container-type":"sandbox","io.kubernetes.cri.sandbox-id":"8e5f48047dfc52c9ee043129580d5df9b70f6c0828d96fbb396fb269e114fbfd","io.kubernetes.cri.sandbox-log-directory":"/var/log/pods/default_curl-test_3feed600-56cb-4a73-857f-87b27bb65771"},"linux":{"resources":{"devices":[{"allow":false,"access":"rwm"}],"cpu":{"shares":2}},"cgroupsPath":"kubepods-besteffort-pod3feed600_56cb_4a73_857f_87b27bb65771.slice:cri-containerd:8e5f48047dfc52c9ee043129580d5df9b70f6c0828d96fbb396fb269e114fbfd","namespaces":[{"type":"pid"},{"type":"ipc"},{"type":"mount"}],"maskedPaths":["/proc/acpi","/proc/asound","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/sys/firmware","/proc/scsi"],"readonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"]}}`

func TestUpdateEnvs(t *testing.T) {
	path := filepath.Join("/tmp", "config.json")
	defer os.Remove(path)

	err := ioutil.WriteFile(path, []byte(configTemplate), 0644)
	assert.Nil(t, err)
	spec, err := LoadSpec(path)
	assert.Nil(t, err)
	m := map[string]string{"k1": "v1", "k2": "v2"}
	err = UpdateEnvs(spec, m, false)
	assert.Nil(t, err)
	v1, ok := GetEnv(spec, "k1")
	assert.Equal(t, true, ok)
	assert.Equal(t, "v1", v1)
	v2, ok := GetEnv(spec, "k2")
	assert.Equal(t, true, ok)
	assert.Equal(t, "v2", v2)
	v3, ok := GetEnv(spec, "ENCLAVE_TYPE")
	assert.Equal(t, true, ok)
	assert.Equal(t, "intelSgx", v3)
	err = SaveSpec(path, spec)
	assert.Nil(t, err)

	spec, err = LoadSpec(path)
	v1, ok = GetEnv(spec, "k1")
	assert.Equal(t, true, ok)
	assert.Equal(t, "v1", v1)
	v2, ok = GetEnv(spec, "k2")
	assert.Equal(t, true, ok)
	assert.Equal(t, "v2", v2)
	v3, ok = GetEnv(spec, "ENCLAVE_TYPE")
	assert.Equal(t, true, ok)
	assert.Equal(t, "intelSgx", v3)

	fmt.Printf("spec=%++v", spec.Process.Env)
}
