// The codebase is inherited from runc with the modifications.

package libenclave // import "github.com/inclavare-containers/rune/libenclave"

import (
	"bytes"
	"encoding/binary"

	"fmt"
	"github.com/golang/protobuf/proto"
	pb "github.com/inclavare-containers/rune/libenclave/proto"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/stacktrace"
	"io"
	"text/template"
	"time"
	"unsafe"
)

var errorTemplate = template.Must(template.New("error").Parse(`Timestamp: {{.Timestamp}}
Code: {{.ECode}}
{{if .Message }}
Message: {{.Message}}
{{end}}
Frames:{{range $i, $frame := .Stack.Frames}}
---
{{$i}}: {{$frame.Function}}
Package: {{$frame.Package}}
File: {{$frame.File}}@{{$frame.Line}}{{end}}
`))

func newGenericError(err error, c libcontainer.ErrorCode) libcontainer.Error {
	if le, ok := err.(libcontainer.Error); ok {
		return le
	}
	gerr := &genericError{
		Timestamp: time.Now(),
		Err:       err,
		ECode:     c,
		Stack:     stacktrace.Capture(1),
	}
	if err != nil {
		gerr.Message = err.Error()
	}
	return gerr
}

func newSystemError(err error) libcontainer.Error {
	return createSystemError(err, "")
}

func newSystemErrorWithCausef(err error, cause string, v ...interface{}) libcontainer.Error {
	return createSystemError(err, fmt.Sprintf(cause, v...))
}

func newSystemErrorWithCause(err error, cause string) libcontainer.Error {
	return createSystemError(err, cause)
}

// createSystemError creates the specified error with the correct number of
// stack frames skipped. This is only to be called by the other functions for
// formatting the error.
func createSystemError(err error, cause string) libcontainer.Error {
	gerr := &genericError{
		Timestamp: time.Now(),
		Err:       err,
		ECode:     libcontainer.SystemError,
		Cause:     cause,
		Stack:     stacktrace.Capture(2),
	}
	if err != nil {
		gerr.Message = err.Error()
	}
	return gerr
}

type genericError struct {
	Timestamp time.Time
	ECode     libcontainer.ErrorCode
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
	return fmt.Sprintf("%s:%d: %s caused: %s", frame.File, frame.Line, e.Cause, e.Message)
}

func (e *genericError) Code() libcontainer.ErrorCode {
	return e.ECode
}

func (e *genericError) Detail(w io.Writer) error {
	return errorTemplate.Execute(w, e)
}

func protoBufRead(conn io.Reader, unmarshaled interface{}) error {
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
