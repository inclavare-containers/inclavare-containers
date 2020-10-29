package epm

import (
	"net"
	"syscall"

	"github.com/sirupsen/logrus"
)

func sendFd(socksPath string, fd int) {
	data := syscall.UnixRights(fd)
	raddr, err := net.ResolveUnixAddr("unix", socksPath)
	if err != nil {
		logrus.Fatal(err)
	}
	// Connect UnixSock
	conn, err := net.DialUnix("unix", nil, raddr)
	if err != nil {
		logrus.Fatal(err)
	}
	// Send msg
	_, _, err = conn.WriteMsgUnix(nil, data, nil)
	if err != nil {
		logrus.Fatal(err)
	}
}

func recvFd(socksPath string, fd *int) {
	laddr, err := net.ResolveUnixAddr("unix", socksPath)
	if err != nil {
		logrus.Fatal(err)
	}
	l, err := net.ListenUnix("unix", laddr)
	if err != nil {
		logrus.Fatal(err)
	}
	conn, err := l.AcceptUnix()
	if err != nil {
		logrus.Fatal(err)
	}

	// Part msg into both datas
	buf := make([]byte, 32)
	oob := make([]byte, 32)
	_, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		logrus.Fatal(err)
	}
	// ParseSocketControlMessage Array
	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		logrus.Fatal(err)
	}
	if len(scms) > 0 {
		// Get UnixRights from SocketControlMessage
		fds, err := syscall.ParseUnixRights(&(scms[0]))
		if err != nil {
			logrus.Fatal(err)
		}
		*fd = fds[0]
	}
	err = conn.Close()
	if err != nil {
		logrus.Fatal(err)
	}
	// Delete original unixSock by unlink
	syscall.Unlink(socksPath)
}
