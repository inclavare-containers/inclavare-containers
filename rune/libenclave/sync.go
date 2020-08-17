package libenclave // import "github.com/inclavare-containers/rune/libenclave"

import (
	"encoding/json"
	"fmt"
	"github.com/opencontainers/runc/libcontainer/utils"
	"io"
)

type syncType string

type syncT struct {
	Type syncType `json:"type"`
}

// during enclave setup. They come in pairs (with procError being a generic
// response which is followed by a &genericError).
//
//           [  runelet  ] <-> [  parent  ]
//
//    procEnclaveConfigReq -->
// [ recv enclave config ] <-- [ send enclave config ]
//    procEnclaveConfigACK -->
//
//         procEnclaveInit -->
//                         <-- procEnclaveReady
const (
	procError            syncType = "procError"
	procEnclaveConfigReq syncType = "procEnclaveConfigReq"
	procEnclaveConfigAck syncType = "procEnclaveConfigAck"
	procEnclaveInit      syncType = "procEnclaveInit"
	procEnclaveReady     syncType = "procEnclaveReady"
)

// writeSync is used to write to a synchronisation pipe. An error is returned
// if there was a problem writing the payload.
func writeSync(pipe io.Writer, sync syncType) error {
	return utils.WriteJSON(pipe, syncT{sync})
}

// readSync is used to read from a synchronisation pipe. An error is returned
// if we got a genericError, the pipe was closed, or we got an unexpected flag.
func readSync(pipe io.Reader, expected syncType) error {
	var procSync syncT
	if err := json.NewDecoder(pipe).Decode(&procSync); err != nil {
		if err == io.EOF {
			return fmt.Errorf("parent closed synchronisation channel")
		}

		if procSync.Type == procError {
			var ierr genericError

			if err := json.NewDecoder(pipe).Decode(&ierr); err != nil {
				return fmt.Errorf("failed reading error from parent: %v", err)
			}

			return &ierr
		}

		if procSync.Type != expected {
			return fmt.Errorf("invalid synchronisation flag from parent")
		}
	}
	return nil
}
