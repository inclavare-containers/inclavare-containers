// +build epid

package main

/*
#cgo CFLAGS: -I../build/include -I/opt/intel/sgxsdk/include -I../sgx-ra-tls -I../wolfssl
#cgo LDFLAGS: -L../build/lib -l:libra-challenger.a -l:libwolfssl.a -lsgx_urts -lm

extern int ra_tls_echo(int sockfd);
*/
import "C"

func ratlsEcho(fd uintptr) {
	C.ra_tls_echo(C.int(fd))
}
