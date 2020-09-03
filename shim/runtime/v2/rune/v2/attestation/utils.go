package attestation

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/golang/protobuf/proto"
	pb "github.com/opencontainers/runc/libenclave/proto"
	"io"
	"unsafe"
)

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

	return nil
}
