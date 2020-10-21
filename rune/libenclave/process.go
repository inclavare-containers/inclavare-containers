package libenclave // import "github.com/inclavare-containers/rune/libenclave"

import (
	"io"
	"os"

	"github.com/opencontainers/runc/libcontainer/configs"
)

type processOperations interface {
	wait() (*os.ProcessState, error)
	signal(sig os.Signal) error
	pid() int
}

// Process specifies the configuration and IO for a process inside
// a container.
type EnclaveProcess struct {
	// The command to be run followed by any arguments.
	Args []string

	// Env specifies the environment variables for the process.
	Env []string

	// User will set the uid and gid of the executing process running inside the container
	// local to the container's user and group configuration.
	User string

	// AdditionalGroups specifies the gids that should be added to supplementary groups
	// in addition to those that the user belongs to.
	AdditionalGroups []string

	// Cwd will change the processes current working directory inside the container's rootfs.
	Cwd string

	// Stdin is a pointer to a reader which provides the standard input stream.
	Stdin io.Reader

	// Stdout is a pointer to a writer which receives the standard output stream.
	Stdout io.Writer

	// Stderr is a pointer to a writer which receives the standard error stream.
	Stderr io.Writer

	// ExtraFiles specifies additional open files to be inherited by the container
	ExtraFiles []*os.File

	// Initial sizings for the console
	ConsoleWidth  uint16
	ConsoleHeight uint16

	// Capabilities specify the capabilities to keep when executing the process inside the container
	// All capabilities not specified will be dropped from the processes capability mask
	Capabilities *configs.Capabilities

	// AppArmorProfile specifies the profile to apply to the process and is
	// changed at the time the process is execed
	AppArmorProfile string

	// Label specifies the label to apply to the process.  It is commonly used by selinux
	Label string

	// NoNewPrivileges controls whether processes can gain additional privileges.
	NoNewPrivileges *bool

	// Rlimits specifies the resource limits, such as max open files, to set in the container
	// If Rlimits are not set, the container will inherit rlimits from the parent process
	Rlimits []configs.Rlimit

	// ConsoleSocket provides the masterfd console.
	ConsoleSocket *os.File

	// Init specifies whether the process is the first process in the container.
	Init bool

	ops processOperations

	LogLevel string

	AgentPipe *os.File
}
