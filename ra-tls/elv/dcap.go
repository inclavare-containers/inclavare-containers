// +build dcap

package main

/*
#cgo CFLAGS: -DRATLS_ECDSA=1
#cgo CFLAGS: -I../build/include -I/opt/intel/sgxsdk/include -I../sgx-ra-tls -I../wolfssl
#cgo LDFLAGS: -L../build/lib -l:libra-challenger.a -l:libwolfssl.a -lsgx_urts -lm
#cgo LDFLAGS: -lsgx_dcap_quoteverify -lpthread -ldl -lsgx_dcap_ql

extern int ra_tls_echo(int sockfd);
*/
import "C"

func ratlsEcho(fd uintptr) {
        C.ra_tls_echo(C.int(fd))
}
