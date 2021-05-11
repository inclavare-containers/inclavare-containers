package remoteattestation

/*
#cgo CFLAGS: -I/opt/enclave-tls/include -std=gnu11
#cgo LDFLAGS: -L/opt/enclave-tls/lib -lenclave_tls -Wl,-rpath,/opt/enclave-tls/lib -lm
#include <enclave-tls/api.h>
extern int ra_tls_echo(int, enclave_tls_log_level_t, char *, char *, char *, char *, bool);
*/
import "C"
import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	defaultSockAddress = "/run/enclave-tls/tls.sock"
	defaultIpAddress   = "127.0.0.1"
	defaultPort        = "1234"
)

//for local tcp connection
func EnclaveTlsSetupTcpSock(ipaddress string, port string, logLevelInit string, attester string, verifier string, tls string, crypto string, mutual bool) error {
	mediumstring := ":"
	var bt bytes.Buffer
	if ipaddress != "" && port != "" {
		bt.WriteString(ipaddress)
		bt.WriteString(mediumstring)
		bt.WriteString(port)
	} else if ipaddress != "" && port == "" {
		bt.WriteString(ipaddress)
		bt.WriteString(mediumstring)
		bt.WriteString(defaultPort)
	} else if ipaddress == "" && port != "" {
		bt.WriteString(defaultIpAddress)
		bt.WriteString(mediumstring)
		bt.WriteString(port)
	} else if ipaddress == "" && port == "" {
		bt.WriteString(defaultIpAddress)
		bt.WriteString(mediumstring)
		bt.WriteString(defaultPort)
	}
	addr := bt.String()
	bt.Reset()
	fmt.Printf("tcp sock address is %s\n", addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp connection failed with err %s.\n", err)
	}
	defer conn.Close()

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("casting to tcp socket connection failed.\n")
	}

	sockfd, err := tcpConn.File()
	if err != nil {
		return err
	}
	logLevel := C.ENCLAVE_TLS_LOG_LEVEL_DEFAULT
	if strings.EqualFold(logLevelInit, "debug") {
		logLevel = C.ENCLAVE_TLS_LOG_LEVEL_DEBUG
	} else if strings.EqualFold(logLevelInit, "info") {
		logLevel = C.ENCLAVE_TLS_LOG_LEVEL_INFO
	} else if strings.EqualFold(logLevelInit, "warn") {
		logLevel = C.ENCLAVE_TLS_LOG_LEVEL_WARN
	} else if strings.EqualFold(logLevelInit, "error") {
		logLevel = C.ENCLAVE_TLS_LOG_LEVEL_ERROR
	} else if strings.EqualFold(logLevelInit, "fatal") {
		logLevel = C.ENCLAVE_TLS_LOG_LEVEL_FATAL
	} else if strings.EqualFold(logLevelInit, "off") {
		logLevel = C.ENCLAVE_TLS_LOG_LEVEL_NONE
	}
	ret := C.ra_tls_echo(C.int(sockfd.Fd()), C.enclave_tls_log_level_t(logLevel), C.CString(attester), C.CString(verifier), C.CString(tls), C.CString(crypto), C.bool(mutual))
	if ret != 0 {
		var err error = errors.New("Remote attestation failed.\n")
		return err
	}
	return nil

}

//for local unix socket connection
func EnclaveTlsSetupUnixSock(address string, logLevelInit string, attester string, verifier string, tls string, crypto string, mutual bool) error {
	addr := address
	if addr == "" {
		addr = defaultSockAddress
	}

	conn, err := net.Dial("unix", addr)
	if err != nil {
		return fmt.Errorf("unix connection failed with err %s.\n", err)
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("casting to unix socket connection failed.\n")
	}

	sockfd, err := unixConn.File()
	if err != nil {
		return err
	}
	logLevel := C.ENCLAVE_TLS_LOG_LEVEL_DEFAULT
	if strings.EqualFold(logLevelInit, "debug") {
		logLevel = C.ENCLAVE_TLS_LOG_LEVEL_DEBUG
	} else if strings.EqualFold(logLevelInit, "info") {
		logLevel = C.ENCLAVE_TLS_LOG_LEVEL_INFO
	} else if strings.EqualFold(logLevelInit, "warn") {
		logLevel = C.ENCLAVE_TLS_LOG_LEVEL_WARN
	} else if strings.EqualFold(logLevelInit, "error") {
		logLevel = C.ENCLAVE_TLS_LOG_LEVEL_ERROR
	} else if strings.EqualFold(logLevelInit, "fatal") {
		logLevel = C.ENCLAVE_TLS_LOG_LEVEL_FATAL
	} else if strings.EqualFold(logLevelInit, "off") {
		logLevel = C.ENCLAVE_TLS_LOG_LEVEL_NONE
	}
	ret := C.ra_tls_echo(C.int(sockfd.Fd()), C.enclave_tls_log_level_t(logLevel), C.CString(attester), C.CString(verifier), C.CString(tls), C.CString(crypto), C.bool(mutual))
	if ret != 0 {
		var err error = errors.New("Remote attestation failed.\n")
		return err
	}
	return nil
}
