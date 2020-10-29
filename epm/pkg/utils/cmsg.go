package utils

import (
	"net"
	"syscall"
)

func RecvFd(socksPath string) (int, error) {
	var fds []int

	laddr, err := net.ResolveUnixAddr("unix", socksPath)
	if err != nil {
		panic(err)
	}

	l, err := net.ListenUnix("unix", laddr)
	if err != nil {
		panic(err)
	}

	conn, err := l.AcceptUnix()
	if err != nil {
		panic(err)
	}
	// Part msg into both datas
	buf := make([]byte, 32)
	oob := make([]byte, 32)
	_, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		panic(err)
	}
	// ParseSocketControlMessage Array
	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		panic(err)
	}
	if len(scms) > 0 {
		// Get UnixRights from SocketControlMessage
		fds, err = syscall.ParseUnixRights(&(scms[0]))
		if err != nil {
			panic(err)
		}
	}

	err = conn.Close()
	if err != nil {
		panic(err)
	}
	// Delete original unixSock by unlink
	syscall.Unlink(socksPath)
	return fds[0], err
}

func SendFd(socksPath string, fd int) error {
	data := syscall.UnixRights(fd)
	raddr, err := net.ResolveUnixAddr("unix", socksPath)
	if err != nil {
		panic(err)
	}
	// Connect UnixSock
	conn, err := net.DialUnix("unix", nil, raddr)
	if err != nil {
		panic(err)
	}
	// Send Msg
	_, _, err = conn.WriteMsgUnix(nil, data, nil)
	if err != nil {
		panic(err)
	}
	return err
}
