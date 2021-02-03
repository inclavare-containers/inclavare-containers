package epm

import (
	"net"
	"syscall"

	"github.com/sirupsen/logrus"
)

func sendFd(socksPath string, fd int) error {
	data := syscall.UnixRights(fd)
	raddr, err := net.ResolveUnixAddr("unix", socksPath)
	if err != nil {
		logrus.Warnf("In sendFd resolveUnixAddr error: %v", err)
		return err
	}
	// Connect UnixSock
	conn, err := net.DialUnix("unix", nil, raddr)
	if err != nil {
		logrus.Warnf("In sendFd DailUnix error: %v", err)
		return err
	}
	// Send msg
	_, _, err = conn.WriteMsgUnix(nil, data, nil)
	if err != nil {
		logrus.Warnf("In sendFd WriteMsgUnix error: %v", err)
		return err
	}
	return nil
}

func recvFd(socksPath string, fd *int) error {
	laddr, err := net.ResolveUnixAddr("unix", socksPath)
	if err != nil {
		logrus.Warnf("In recvFd ResolveUnixAddr error: %v", err)
		return err
	}
	defer syscall.Unlink(socksPath)

	l, err := net.ListenUnix("unix", laddr)
	if err != nil {
		logrus.Warnf("In recvFd ListenUnix error: %v", err)
		return err
	}
	conn, err := l.AcceptUnix()
	if err != nil {
		logrus.Warnf("In recvFd AcceptUnix error: %v", err)
		return err
	}

	// Part msg into both datas
	buf := make([]byte, 32)
	oob := make([]byte, 32)
	_, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		logrus.Warnf("In recvFd ReadMsgUnix error: %v", err)
		return err
	}
	// ParseSocketControlMessage Array
	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		logrus.Warnf("In recvFd ParseSCM error: %v", err)
		return err
	}
	if len(scms) > 0 {
		// Get UnixRights from SocketControlMessage
		fds, err := syscall.ParseUnixRights(&(scms[0]))
		if err != nil {
			logrus.Warnf("In recvFd ParseUnixRights error: %v", err)
			return err
		}
		*fd = fds[0]
	}
	err = conn.Close()
	if err != nil {
		logrus.Warnf("In recvFd connection close error: %v", err)
		return err
	}
	epmchan <- nil

	return nil
}
