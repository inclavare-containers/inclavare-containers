package occlum

import (
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	EnvUserSpaceSize        = "OCCLUM_USER_SPACE_SIZE"
	EnvKernelSpaceHeapSize  = "OCCLUM_KERNEL_SPACE_HEAP_SIZE"
	EnvKernelSpaceStackSize = "OCCLUM_KERNEL_SPACE_STACK_SIZE"
	EnvMaxNumOfThreads      = "OCCLUM_MAX_NUM_OF_THREADS"
	EnvDefaultStackSize     = "OCCLUM_DEFAULT_STACK_SIZE"
	EnvDefaultHeapSize      = "OCCLUM_DEFAULT_HEAP_SIZE"
	EnvDefaultMmapSize      = "OCCLUM_DEFAULT_MMAP_SIZE"
	EnvProductId            = "OCCLUM_PRODUCT_ID"
	EnvVersionNumber        = "OCCLUM_VERSION_NUMBER"
	EnvDebuggable           = "OCCLUM_DEBUGGABLE"
)

type OcclumConfig struct {
	ResourceLimits ResourceLimits `json:"resource_limits"`
	Process        Process        `json:"process"`
	EntryPoints    []string       `json:"entry_points"`
	Env            Env            `json:"env"`
	Metadata       Metadata       `json:"metadata"`
	Mount          []Mount        `json:"mount"`
}

type ResourceLimits struct {
	UserSpaceSize        string `json:"user_space_size"`
	KernelSpaceHeapSize  string `json:"kernel_space_heap_size"`
	KernelSpaceStackSize string `json:"kernel_space_stack_size"`
	MaxNumOfThreads      int64  `json:"max_num_of_threads"`
}

type Process struct {
	DefaultStackSize string `json:"default_stack_size"`
	DefaultHeapSize  string `json:"default_heap_size"`
	DefaultMmapSize  string `json:"default_mmap_size"`
}

type Env struct {
	Default   []string `json:"default"`
	Untrusted []string `json:"untrusted"`
}

type Metadata struct {
	ProductId     int64 `json:"product_id"`
	VersionNumber int64 `json:"version_number"`
	Debuggable    bool  `json:"debuggable"`
}

type Mount struct {
	Target  string                 `json:"target"`
	Type    string                 `json:"type"`
	Source  string                 `json:"source,omitempty"`
	Options map[string]interface{} `json:"options,omitempty"`
}

func (c *OcclumConfig) ApplyEnvs(envs []string) {
	for _, env := range envs {
		items := strings.SplitN(env, "=", 2)
		if len(items) != 2 {
			continue
		}
		k := items[0]
		v := items[1]
		switch k {
		case EnvUserSpaceSize:
			c.ResourceLimits.UserSpaceSize = v
			break
		case EnvKernelSpaceHeapSize:
			c.ResourceLimits.KernelSpaceHeapSize = v
			break
		case EnvKernelSpaceStackSize:
			c.ResourceLimits.KernelSpaceStackSize = v
			break
		case EnvMaxNumOfThreads:
			i, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				logrus.Error("ApplyEnvs: parse environment variable %s failed. error: %++v", k, err)
			}
			c.ResourceLimits.MaxNumOfThreads = i
			break
		case EnvDefaultStackSize:
			c.Process.DefaultStackSize = v
			break
		case EnvDefaultHeapSize:
			c.Process.DefaultHeapSize = v
			break
		case EnvDefaultMmapSize:
			c.Process.DefaultMmapSize = v
			break
		case EnvProductId:
			i, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				logrus.Error("ApplyEnvs: parse environment variable %s failed. error: %++v", k, err)
			}
			c.Metadata.ProductId = i
			break
		case EnvVersionNumber:
			i, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				logrus.Error("ApplyEnvs: parse environment variable %s failed. error: %++v", k, err)
			}
			c.Metadata.VersionNumber = i
			break
		case EnvDebuggable:
			i, err := strconv.ParseBool(v)
			if err != nil {
				logrus.Error("ApplyEnvs: parse environment variable %s failed. error: %++v", k, err)
			}
			c.Metadata.Debuggable = i
			break
		}
	}
}

func GetDefaultOcclumConfig() *OcclumConfig {
	return &OcclumConfig{
		ResourceLimits: ResourceLimits{
			UserSpaceSize:        "256MB",
			KernelSpaceHeapSize:  "32MB",
			KernelSpaceStackSize: "1MB",
			MaxNumOfThreads:      32},
		Process: Process{
			DefaultStackSize: "4MB",
			DefaultHeapSize:  "32MB",
			DefaultMmapSize:  "80MB",
		},
		EntryPoints: []string{"/bin"},
		Env: Env{
			Default:   []string{"OCCLUM=yes"},
			Untrusted: []string{"EXAMPLE"},
		},
		Metadata: Metadata{
			ProductId:     0,
			VersionNumber: 0,
			Debuggable:    true,
		},
		Mount: []Mount{
			{
				Target:  "/",
				Type:    "sefs",
				Source:  "./image",
				Options: map[string]interface{}{"integrity_only": true},
			},
			{
				Target: "/root",
				Type:   "sefs",
			},
			{
				Target: "/host",
				Type:   "hostfs",
				Source: ".",
			},
			{
				Target: "/tmp",
				Type:   "ramfs",
			},
		},
	}
}
