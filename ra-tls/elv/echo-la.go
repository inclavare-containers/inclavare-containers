// +build lareport

package main

/*
#cgo CFLAGS: -I../build/include -I/opt/intel/sgxsdk/include -I../sgx-ra-tls -I../wolfssl/
#cgo CFLAGS: -DLA_REPORT=1
#cgo LDFLAGS: -L../build/lib -l:libra-challenger.a -l:libwolfssl.a -lsgx_urts -lm
*/
import "C"
