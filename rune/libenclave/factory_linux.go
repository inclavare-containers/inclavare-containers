// The codebase is inherited from runc with the modifications.

// +build linux

package libenclave // import "github.com/inclavare-containers/rune/libenclave"

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"unsafe"

	securejoin "github.com/cyphar/filepath-securejoin"
	enclaveConfigs "github.com/inclavare-containers/rune/libenclave/configs"
	"github.com/moby/sys/mountinfo"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fs"
	"github.com/opencontainers/runc/libcontainer/cgroups/fs2"
	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/configs/validate"
	"github.com/opencontainers/runc/libcontainer/intelrdt"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/pkg/errors"

	"golang.org/x/sys/unix"
)

const (
	stateFilename    = "state.json"
	execFifoFilename = "exec.fifo"
)

var idRegex = regexp.MustCompile(`^[\w+-\.]+$`)

// InitArgs returns an options func to configure a LinuxEnclaveFactory with the
// provided init binary path and arguments.
func InitArgs(args ...string) func(*LinuxEnclaveFactory) error {
	return func(l *LinuxEnclaveFactory) (err error) {
		if len(args) > 0 {
			// Resolve relative paths to ensure that its available
			// after directory changes.
			if args[0], err = filepath.Abs(args[0]); err != nil {
				return newGenericError(err, libcontainer.ConfigInvalid)
			}
		}

		l.InitArgs = args
		return nil
	}
}

func getUnifiedPath(paths map[string]string) string {
	path := ""
	for k, v := range paths {
		if path == "" {
			path = v
		} else if v != path {
			panic(errors.Errorf("expected %q path to be unified path %q, got %q", k, path, v))
		}
	}
	// can be empty
	if path != "" {
		if filepath.Clean(path) != path || !filepath.IsAbs(path) {
			panic(errors.Errorf("invalid dir path %q", path))
		}
	}

	return path
}

func systemdCgroupV2(l *LinuxEnclaveFactory, rootless bool) error {
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return systemd.NewUnifiedManager(config, getUnifiedPath(paths), rootless)
	}
	return nil
}

// SystemdCgroups is an options func to configure a LinuxEnclaveFactory to return
// containers that use systemd to create and manage cgroups.
func SystemdCgroups(l *LinuxEnclaveFactory) error {
	if !systemd.IsRunningSystemd() {
		return fmt.Errorf("systemd not running on this host, can't use systemd as cgroups manager")
	}

	if cgroups.IsCgroup2UnifiedMode() {
		return systemdCgroupV2(l, false)
	}

	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return systemd.NewLegacyManager(config, paths)
	}

	return nil
}

// RootlessSystemdCgroups is rootless version of SystemdCgroups.
func RootlessSystemdCgroups(l *LinuxEnclaveFactory) error {
	if !systemd.IsRunningSystemd() {
		return fmt.Errorf("systemd not running on this host, can't use systemd as cgroups manager")
	}

	if !cgroups.IsCgroup2UnifiedMode() {
		return fmt.Errorf("cgroup v2 not enabled on this host, can't use systemd (rootless) as cgroups manager")
	}
	return systemdCgroupV2(l, true)
}

func cgroupfs2(l *LinuxEnclaveFactory, rootless bool) error {
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		m, err := fs2.NewManager(config, getUnifiedPath(paths), rootless)
		if err != nil {
			panic(err)
		}
		return m
	}
	return nil
}

func cgroupfs(l *LinuxEnclaveFactory, rootless bool) error {
	if cgroups.IsCgroup2UnifiedMode() {
		return cgroupfs2(l, rootless)
	}
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return fs.NewManager(config, paths, rootless)
	}
	return nil
}

// Cgroupfs is an options func to configure a LinuxEnclaveFactory to return containers
// that use the native cgroups filesystem implementation to create and manage
// cgroups.
func Cgroupfs(l *LinuxEnclaveFactory) error {
	return cgroupfs(l, false)
}

// RootlessCgroupfs is an options func to configure a LinuxEnclaveFactory to return
// containers that use the native cgroups filesystem implementation to create
// and manage cgroups. The difference between RootlessCgroupfs and Cgroupfs is
// that RootlessCgroupfs can transparently handle permission errors that occur
// during rootless container (including euid=0 in userns) setup (while still allowing cgroup usage if
// they've been set up properly).
func RootlessCgroupfs(l *LinuxEnclaveFactory) error {
	return cgroupfs(l, true)
}

// IntelRdtfs is an options func to configure a LinuxEnclaveFactory to return
// containers that use the Intel RDT "resource control" filesystem to
// create and manage Intel RDT resources (e.g., L3 cache, memory bandwidth).
func IntelRdtFs(l *LinuxEnclaveFactory) error {
	if !intelrdt.IsCATEnabled() && !intelrdt.IsMBAEnabled() {
		l.NewIntelRdtManager = nil
	} else {
		l.NewIntelRdtManager = func(config *configs.Config, id string, path string) intelrdt.Manager {
			return intelrdt.NewManager(config, id, path)
		}
	}
	return nil
}

// TmpfsRoot is an option func to mount LinuxEnclaveFactory.Root to tmpfs.
func TmpfsRoot(l *LinuxEnclaveFactory) error {
	mounted, err := mountinfo.Mounted(l.Root)
	if err != nil {
		return err
	}
	if !mounted {
		if err := unix.Mount("tmpfs", l.Root, "tmpfs", 0, ""); err != nil {
			return err
		}
	}
	return nil
}

// CriuPath returns an option func to configure a LinuxEnclaveFactory with the
// provided criupath
func CriuPath(criupath string) func(*LinuxEnclaveFactory) error {
	return func(l *LinuxEnclaveFactory) error {
		l.CriuPath = criupath
		return nil
	}
}

// New returns a linux based container factory based in the root directory and
// configures the factory with the provided option funcs.
func New(root string, enclaveConfig *enclaveConfigs.EnclaveConfig, detached bool, options ...func(*LinuxEnclaveFactory) error) (libcontainer.Factory, error) {
	if root != "" {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return nil, newGenericError(err, libcontainer.SystemError)
		}
	}
	l := &LinuxEnclaveFactory{
		LinuxFactory: libcontainer.LinuxFactory{
			Root:      root,
			InitPath:  "/proc/self/exe",
			InitArgs:  []string{os.Args[0], "init"},
			Validator: validate.New(),
			CriuPath:  "criu",
		},
		enclaveConfig: enclaveConfig,
		detached:      detached,
	}

	if err := Cgroupfs(l); err != nil {
		return nil, err
	}

	for _, opt := range options {
		if opt == nil {
			continue
		}
		if err := opt(l); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// LinuxEnclaveFactory implements the default factory interface for linux based systems.
type LinuxEnclaveFactory struct {
	libcontainer.LinuxFactory
	enclaveConfig *enclaveConfigs.EnclaveConfig
	detached      bool
}

func (l *LinuxEnclaveFactory) Create(id string, config *configs.Config) (libcontainer.Container, error) {
	if l.Root == "" {
		return nil, newGenericError(fmt.Errorf("invalid root"), libcontainer.ConfigInvalid)
	}
	if err := l.validateID(id); err != nil {
		return nil, err
	}
	lf := (*libcontainer.LinuxFactory)(unsafe.Pointer(l))
	lc, err := lf.Create(id, config)
	if err != nil {
		return nil, err
	}
	containerRoot, err := securejoin.SecureJoin(l.Root, id)
	if err != nil {
		return nil, err
	}

	c := &linuxEnclaveContainer{
		id:            lc.ID(),
		root:          containerRoot,
		config:        config,
		enclaveConfig: l.enclaveConfig,
		detached:      l.detached,
		initPath:      l.InitPath,
		initArgs:      l.InitArgs,
		criuPath:      l.CriuPath,
		newuidmapPath: l.NewuidmapPath,
		newgidmapPath: l.NewgidmapPath,
		cgroupManager: l.NewCgroupsManager(config.Cgroups, nil),
	}
	if l.NewIntelRdtManager != nil {
		c.intelRdtManager = l.NewIntelRdtManager(config, id, "")
	}
	c.state = &stoppedState{c: c}
	return c, nil
}

func (l *LinuxEnclaveFactory) Load(id string) (libcontainer.Container, error) {
	if l.Root == "" {
		return nil, newGenericError(fmt.Errorf("invalid root"), libcontainer.ConfigInvalid)
	}
	// when load, we need to check id is valid or not.
	if err := l.validateID(id); err != nil {
		return nil, err
	}
	containerRoot, err := securejoin.SecureJoin(l.Root, id)
	if err != nil {
		return nil, err
	}
	state, err := l.loadState(containerRoot, id)
	if err != nil {
		return nil, err
	}
	r := &nonChildProcess{
		processPid:       state.InitProcessPid,
		processStartTime: state.InitProcessStartTime,
		fds:              state.ExternalDescriptors,
	}
	c := &linuxEnclaveContainer{
		initProcess:          r,
		initProcessStartTime: state.InitProcessStartTime,
		id:                   id,
		config:               &state.Config,
		initPath:             l.InitPath,
		initArgs:             l.InitArgs,
		criuPath:             l.CriuPath,
		newuidmapPath:        l.NewuidmapPath,
		newgidmapPath:        l.NewgidmapPath,
		cgroupManager:        l.NewCgroupsManager(state.Config.Cgroups, state.CgroupPaths),
		root:                 containerRoot,
		created:              state.Created,
	}
	if l.NewIntelRdtManager != nil {
		c.intelRdtManager = l.NewIntelRdtManager(&state.Config, id, state.IntelRdtPath)
	}
	if state.EnclaveConfig.Enclave != nil {
		c.enclaveConfig = &state.EnclaveConfig
	}

	c.state = &loadedState{c: c}
	if err := c.refreshState(); err != nil {
		return nil, err
	}
	return c, nil
}

func (l *LinuxEnclaveFactory) Type() string {
	return "libenclave"
}

// StartInitialization loads a container by opening the pipe fd from the parent to read the configuration and state
// This is a low level implementation detail of the reexec and should not be consumed externally
func (l *LinuxEnclaveFactory) StartInitialization() (err error) {
	var (
		agentPipe    *os.File
		envLogLevel  = os.Getenv("_LIBCONTAINER_LOGLEVEL")
		envAgentPipe = os.Getenv("_LIBENCLAVE_AGENTPIPE")
	)

	// Get the INITPIPE.
	envInitPipe := os.Getenv("_LIBCONTAINER_INITPIPE")
	pipefd, err := strconv.Atoi(envInitPipe)
	if err != nil {
		return fmt.Errorf("unable to convert _LIBCONTAINER_INITPIPE=%s to int: %s", envInitPipe, err)
	}
	pipe := os.NewFile(uintptr(pipefd), "pipe")
	defer pipe.Close()

	// Only init processes have FIFOFD.
	fifofd := -1
	envInitType := os.Getenv("_LIBCONTAINER_INITTYPE")
	it := initType(envInitType)
	if it == initStandard {
		envFifoFd := os.Getenv("_LIBCONTAINER_FIFOFD")
		if fifofd, err = strconv.Atoi(envFifoFd); err != nil {
			return fmt.Errorf("unable to convert _LIBCONTAINER_FIFOFD=%s to int: %s", envFifoFd, err)
		}
	}

	var consoleSocket *os.File
	if envConsole := os.Getenv("_LIBCONTAINER_CONSOLE"); envConsole != "" {
		console, err := strconv.Atoi(envConsole)
		if err != nil {
			return fmt.Errorf("unable to convert _LIBCONTAINER_CONSOLE=%s to int: %s", envConsole, err)
		}
		consoleSocket = os.NewFile(uintptr(console), "console-socket")
		defer consoleSocket.Close()
	}

	logPipeFdStr := os.Getenv("_LIBCONTAINER_LOGPIPE")
	logPipeFd, err := strconv.Atoi(logPipeFdStr)
	if err != nil {
		return fmt.Errorf("unable to convert _LIBCONTAINER_LOGPIPE=%s to int: %s", logPipeFdStr, err)
	}

	if envAgentPipe != "" {
		agent, err := strconv.Atoi(envAgentPipe)
		if err != nil {
			return fmt.Errorf("unable to convert _LIBENCLAVE_AGENTSOCK=%s to int: %s", envAgentPipe, err)
		}
		agentPipe = os.NewFile(uintptr(agent), "agent-pipe")
		defer agentPipe.Close()
	}

	// clear the current process's environment to clean any libenclave
	// specific env vars.
	os.Clearenv()

	defer func() {
		// We have an error during the initialization of the container's init,
		// send it back to the parent process in the form of an initError.
		if werr := utils.WriteJSON(pipe, syncT{procError}); werr != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if werr := utils.WriteJSON(pipe, newSystemError(err)); werr != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}()
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("panic from initialization: %v, %v", e, string(debug.Stack()))
		}
	}()

	i, err := newContainerInit(it, pipe, consoleSocket, fifofd, logPipeFd, envLogLevel, agentPipe)
	if err != nil {
		return err
	}

	// If Init succeeds, syscall.Exec will not return, hence none of the defers will be called.
	return i.Init()
}

func (l *LinuxEnclaveFactory) loadState(root, id string) (*EnclaveState, error) {
	stateFilePath, err := securejoin.SecureJoin(root, stateFilename)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(stateFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, newGenericError(fmt.Errorf("container %q does not exist", id), libcontainer.ContainerNotExists)
		}
		return nil, newGenericError(err, libcontainer.SystemError)
	}
	defer f.Close()
	var state *EnclaveState
	if err := json.NewDecoder(f).Decode(&state); err != nil {
		return nil, newGenericError(err, libcontainer.SystemError)
	}
	return state, nil
}

func (l *LinuxEnclaveFactory) validateID(id string) error {
	if !idRegex.MatchString(id) || string(os.PathSeparator)+id != utils.CleanPath(string(os.PathSeparator)+id) {
		return newGenericError(fmt.Errorf("invalid id format: %v", id), libcontainer.InvalidIdFormat)
	}

	return nil
}

// NewuidmapPath returns an option func to configure a LinuxEnclaveFactory with the
// provided ..
func NewuidmapPath(newuidmapPath string) func(*LinuxEnclaveFactory) error {
	return func(l *LinuxEnclaveFactory) error {
		l.NewuidmapPath = newuidmapPath
		return nil
	}
}

// NewgidmapPath returns an option func to configure a LinuxEnclaveFactory with the
// provided ..
func NewgidmapPath(newgidmapPath string) func(*LinuxEnclaveFactory) error {
	return func(l *LinuxEnclaveFactory) error {
		l.NewgidmapPath = newgidmapPath
		return nil
	}
}
