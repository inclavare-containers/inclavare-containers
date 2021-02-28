// +build dcap

package main

/*
#cgo CFLAGS: -DRATLS_ECDSA=1
#cgo LDFLAGS: -L../build/lib -Llib -lra-tls-server -l:libcurl-wolfssl.a -l:libwolfssl.a -lsgx_uae_service -lsgx_urts -lz -lm
#cgo LDFLAGS: -lsgx_dcap_ql

extern int ra_tls_server_startup(int sockfd);
*/
import "C"

func ratlsServerStartup(fd uintptr) {
	C.ra_tls_server_startup(C.int(fd))
}
