// The codebase is inherited from runc with the modifications.

// +build linux

package libenclave // import "github.com/inclavare-containers/rune/libenclave"

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func newStateTransitionError(from, to containerState) error {
	return &stateTransitionError{
		From: from.status().String(),
		To:   to.status().String(),
	}
}

// stateTransitionError is returned when an invalid state transition happens from one
// state to another.
type stateTransitionError struct {
	From string
	To   string
}

func (s *stateTransitionError) Error() string {
	return fmt.Sprintf("invalid state transition from %s to %s", s.From, s.To)
}

type containerState interface {
	transition(containerState) error
	destroy() error
	status() libcontainer.Status
}

func destroy(c *linuxEnclaveContainer) error {
	if !c.config.Namespaces.Contains(configs.NEWPID) ||
		c.config.Namespaces.PathOf(configs.NEWPID) != "" {
		if err := signalAllProcesses(c.cgroupManager, unix.SIGKILL); err != nil {
			logrus.Warn(err)
		}
	}
	err := c.cgroupManager.Destroy()
	if c.intelRdtManager != nil {
		if ierr := c.intelRdtManager.Destroy(); err == nil {
			err = ierr
		}
	}
	if rerr := os.RemoveAll(c.root); err == nil {
		err = rerr
	}
	c.initProcess = nil
	if herr := runPoststopHooks(c); err == nil {
		err = herr
	}
	c.state = &stoppedState{c: c}
	return err
}

func runPoststopHooks(c *linuxEnclaveContainer) error {
	hooks := c.config.Hooks
	if hooks == nil {
		return nil
	}

	s, err := c.currentOCIState()
	if err != nil {
		return err
	}
	s.Status = specs.StateStopped

	if err := hooks[configs.Poststop].RunHooks(s); err != nil {
		return err
	}

	return nil
}

// stoppedState represents a container is a stopped/destroyed state.
type stoppedState struct {
	c *linuxEnclaveContainer
}

func (b *stoppedState) status() libcontainer.Status {
	return libcontainer.Stopped
}

func (b *stoppedState) transition(s containerState) error {
	switch s.(type) {
	case *runningState, *restoredState:
		b.c.state = s
		return nil
	case *stoppedState:
		return nil
	}
	return newStateTransitionError(b, s)
}

func (b *stoppedState) destroy() error {
	return destroy(b.c)
}

// runningState represents a container that is currently running.
type runningState struct {
	c *linuxEnclaveContainer
}

func (r *runningState) status() libcontainer.Status {
	return libcontainer.Running
}

func (r *runningState) transition(s containerState) error {
	switch s.(type) {
	case *stoppedState:
		if r.c.runType() == libcontainer.Running {
			return newGenericError(fmt.Errorf("container still running"), libcontainer.ContainerNotStopped)
		}
		r.c.state = s
		return nil
	case *pausedState:
		r.c.state = s
		return nil
	case *runningState:
		return nil
	}
	return newStateTransitionError(r, s)
}

func (r *runningState) destroy() error {
	if r.c.runType() == libcontainer.Running {
		return newGenericError(fmt.Errorf("container is not destroyed"), libcontainer.ContainerNotStopped)
	}
	return destroy(r.c)
}

type createdState struct {
	c *linuxEnclaveContainer
}

func (i *createdState) status() libcontainer.Status {
	return libcontainer.Created
}

func (i *createdState) transition(s containerState) error {
	switch s.(type) {
	case *runningState, *pausedState, *stoppedState:
		i.c.state = s
		return nil
	case *createdState:
		return nil
	}
	return newStateTransitionError(i, s)
}

func (i *createdState) destroy() error {
	_ = i.c.initProcess.signal(unix.SIGKILL)
	return destroy(i.c)
}

// pausedState represents a container that is currently pause.  It cannot be destroyed in a
// paused state and must transition back to running first.
type pausedState struct {
	c *linuxEnclaveContainer
}

func (p *pausedState) status() libcontainer.Status {
	return libcontainer.Paused
}

func (p *pausedState) transition(s containerState) error {
	switch s.(type) {
	case *runningState, *stoppedState:
		p.c.state = s
		return nil
	case *pausedState:
		return nil
	}
	return newStateTransitionError(p, s)
}

func (p *pausedState) destroy() error {
	t := p.c.runType()
	if t != libcontainer.Running && t != libcontainer.Created {
		if err := p.c.cgroupManager.Freeze(configs.Thawed); err != nil {
			return err
		}
		return destroy(p.c)
	}
	return newGenericError(fmt.Errorf("container is paused"), libcontainer.ContainerPaused)
}

// restoredState is the same as the running state but also has associated checkpoint
// information that maybe need destroyed when the container is stopped and destroy is called.
type restoredState struct {
	imageDir string
	c        *linuxEnclaveContainer
}

func (r *restoredState) status() libcontainer.Status {
	return libcontainer.Running
}

func (r *restoredState) transition(s containerState) error {
	switch s.(type) {
	case *stoppedState, *runningState:
		return nil
	}
	return newStateTransitionError(r, s)
}

func (r *restoredState) destroy() error {
	if _, err := os.Stat(filepath.Join(r.c.root, "checkpoint")); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	}
	return destroy(r.c)
}

// loadedState is used whenever a container is restored, loaded, or setting additional
// processes inside and it should not be destroyed when it is exiting.
type loadedState struct {
	c *linuxEnclaveContainer
	s libcontainer.Status
}

func (n *loadedState) status() libcontainer.Status {
	return n.s
}

func (n *loadedState) transition(s containerState) error {
	n.c.state = s
	return nil
}

func (n *loadedState) destroy() error {
	if err := n.c.refreshState(); err != nil {
		return err
	}
	return n.c.state.destroy()
}
