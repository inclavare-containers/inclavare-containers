package occlum

import (
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	UserSpaceSize           = "OCCLUM_USER_SPACE_SIZE"
	KernelSpaceHeapSize     = "OCCLUM_KERNEL_SPACE_HEAP_SIZE"
	KernelSpaceStackSize    = "OCCLUM_KERNEL_SPACE_STACK_SIZE"
	MaxNumOfThreads         = "OCCLUM_MAX_NUM_OF_THREADS"
	ProcessDefaultStackSize = "OCCLUM_PROCESS_DEFAULT_STACK_SIZE"
	ProcessDefaultHeapSize  = "OCCLUM_PROCESS_DEFAULT_HEAP_SIZE"
	ProcessDefaultMmapSize  = "OCCLUM_PROCESS_DEFAULT_MMAP_SIZE"
	ProductId               = "OCCLUM_PRODUCT_ID"
	VersionNumber           = "OCCLUM_VERSION_NUMBER"
	Debuggable              = "OCCLUM_DEBUGGABLE"
	DefalutEnv              = "OCCLUM_DEFAULT_ENV"
	UntrustedEnv            = "OCCLUM_UNTRUSTED_ENV"
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
		case UserSpaceSize:
			c.ResourceLimits.UserSpaceSize = v
			break
		case KernelSpaceHeapSize:
			c.ResourceLimits.KernelSpaceHeapSize = v
			break
		case KernelSpaceStackSize:
			c.ResourceLimits.KernelSpaceStackSize = v
			break
		case MaxNumOfThreads:
			i, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				logrus.Error("ApplyEnvs: parse environment variable %s failed. error: %++v", k, err)
			}
			c.ResourceLimits.MaxNumOfThreads = i
			break
		case ProcessDefaultStackSize:
			c.Process.DefaultStackSize = v
			break
		case ProcessDefaultHeapSize:
			c.Process.DefaultHeapSize = v
			break
		case ProcessDefaultMmapSize:
			c.Process.DefaultMmapSize = v
			break
		case ProductId:
			i, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				logrus.Error("ApplyEnvs: parse environment variable %s failed. error: %++v", k, err)
			}
			c.Metadata.ProductId = i
			break
		case VersionNumber:
			i, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				logrus.Error("ApplyEnvs: parse environment variable %s failed. error: %++v", k, err)
			}
			c.Metadata.VersionNumber = i
			break
		case Debuggable:
			i, err := strconv.ParseBool(v)
			if err != nil {
				logrus.Error("ApplyEnvs: parse environment variable %s failed. error: %++v", k, err)
			}
			c.Metadata.Debuggable = i
			break
		case DefalutEnv:
			if len(v) > 0 {
				c.Env.Default = strings.Split(v, ",")
			}
			break
		case UntrustedEnv:
			if len(v) > 0 {
				c.Env.Untrusted = strings.Split(v, ",")
			}
			break
		}
	}
}

func (c *OcclumConfig) ApplyEntrypoints(entrypoints []string) {
	c.EntryPoints = entrypoints
}

func GetDefaultOcclumConfig() *OcclumConfig {
	return &OcclumConfig{
		ResourceLimits: ResourceLimits{
			UserSpaceSize:        "300MB",
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
				Target: "/",
				Type:   "unionfs",
				Source: "./build/mount/__ROOT",
				Options: map[string]interface{}{"layers": []Mount{
					{
						Target:  "/",
						Type:    "sefs",
						Source:  "./build/mount/__ROOT",
						Options: map[string]interface{}{"MAC": ""},
					},
					{
						Target: "/",
						Type:   "sefs",
						Source: "./run/mount/__ROOT",
					},
				}},
			},
			{
				Target: "/host",
				Type:   "hostfs",
				Source: ".",
			},
			{
				Target:  "/tmp",
				Type:    "sefs",
				Source:  "./run/mount/tmp",
				Options: map[string]interface{}{"temporary": true},
			},
			{
				Target: "/proc",
				Type:   "procfs",
			},

			{
				Target: "/dev",
				Type:   "devfs",
			},
		},
	}
}
