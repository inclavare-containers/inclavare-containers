package libenclave // import "github.com/opencontainers/runc/libenclave"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/opencontainers/runc/libcontainer/stacktrace"
	pb "github.com/opencontainers/runc/libenclave/proto"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

// ErrorCode is the API error code type.
type ErrorCode int

type genericError struct {
	Timestamp time.Time
	ECode     ErrorCode
	Err       error `json:"-"`
	Cause     string
	Message   string
	Stack     stacktrace.Stacktrace
}

func (e *genericError) Error() string {
	if e.Cause == "" {
		return e.Message
	}
	frame := e.Stack.Frames[0]
	return fmt.Sprintf("%s:%d: %s caused %q", frame.File, frame.Line, e.Cause, e.Message)
}

func stageFd(env string, f interface{}) (err error) {
	var fd int
	switch f := f.(type) {
	case *os.File:
		fd = int(f.Fd())
	case int:
		fd = f
	default:
		return fmt.Errorf("unsupported type of environment variable %s", env)
	}

	flags, err := unix.FcntlInt(uintptr(fd), syscall.F_GETFD, 0)
	if err != nil {
		return err
	}
	if flags&syscall.FD_CLOEXEC == syscall.FD_CLOEXEC {
		flags &^= syscall.FD_CLOEXEC
		_, err := unix.FcntlInt(uintptr(fd), syscall.F_SETFD, flags)
		if err != nil {
			return err
		}
	}

	err = os.Setenv(env, strconv.Itoa(fd))
	if err != nil {
		return err
	}

	return nil
}

func unstageFd(env string) {
	f := os.Getenv(env)
	os.Unsetenv(env)
	if f != "" {
		fd, err := strconv.Atoi(f)
		if err == nil {
			unix.Close(fd)
		}
	}
}

func protoBufRead(conn net.Conn, unmarshaled interface{}) error {
	var sz uint32
	data := make([]byte, unsafe.Sizeof(sz))
	_, err := conn.Read(data)
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer(data)
	sz = uint32(len(data))
	if err := binary.Read(buf, binary.LittleEndian, &sz); err != nil {
		return err
	}

	data = make([]byte, sz)
	if _, err := conn.Read(data); err != nil {
		return err
	}

	switch unmarshaled := unmarshaled.(type) {
	case *pb.AgentServiceRequest:
		err = proto.Unmarshal(data, unmarshaled)
	case *pb.AgentServiceResponse:
		err = proto.Unmarshal(data, unmarshaled)
	default:
		return fmt.Errorf("invalid type of unmarshaled data")
	}
	return err
}

func protoBufWrite(conn io.Writer, marshaled interface{}) (err error) {
	var data []byte
	switch marshaled := marshaled.(type) {
	case *pb.AgentServiceRequest:
		data, err = proto.Marshal(marshaled)
	case *pb.AgentServiceResponse:
		data, err = proto.Marshal(marshaled)
	default:
		return fmt.Errorf("invalid type of marshaled data")
	}
	if err != nil {
		return err
	}

	sz := uint32(len(data))
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, &sz)
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}
	return nil
}
