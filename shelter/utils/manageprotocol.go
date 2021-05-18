package utils

import (
	"encoding/json"
	"fmt"
)

const (
	MRENCLAVE_HASH_SIZE = 32
	MRSINGER_HASH_SIZE  = 32
	MANAGE_POOL_MAXSIZE = 2048
	ManageCmd1          = "GETENCLAVEINFO"
)

var ReceiveMsg [MANAGE_POOL_MAXSIZE]byte
var ReceiveMsgLen uint = 0

type GetEnclaveInfo struct {
	MsgType string `json:"type"`
}

type EnclaveInfo struct {
	Id        string `json:"id,omitempty"`
	Message   string `json:"message,omitempty"`
	Mrenclave string `json:"mrenclave,omitempty"`
	Mrsigner  string `json:"mrsigner,omitempty"`
	Version   uint8  `json:"version,omitempty"`
}

func ConstructSendmsg(cmd string) ([]byte, uint, error) {
	cmdstr := cmd
	var cmdmsg GetEnclaveInfo
	switch cmdstr {
	case ManageCmd1:
		cmdmsg = GetEnclaveInfo{
			MsgType: "GETENCLAVEINFO",
		}
	default:
		cmdmsg = GetEnclaveInfo{
			MsgType: "GETENCLAVEINFO",
		}
	}
	msg, err := json.Marshal(cmdmsg)
	if err != nil {
		return nil, 0, fmt.Errorf("json marshal failed, err: %s \n", err)
	}
	len := (uint)(len(msg))
	return msg, len, nil
}

func ParseReceiveMsg(cmd string) (interface{}, error) {
	cmdstr := cmd
	var encInfo EnclaveInfo
	receiveBuffer := ReceiveMsg[:ReceiveMsgLen]
	switch cmdstr {
	case ManageCmd1:
		err := json.Unmarshal(receiveBuffer, &encInfo)
		if err != nil {
			return "", fmt.Errorf("json Unmarshal failed, err: %s \n", err)
		}
	default:
		err := json.Unmarshal(receiveBuffer, &encInfo)
		if err != nil {
			return "", fmt.Errorf("json Unmarshal failed, err: %s \n", err)
		}
	}
	var remoteMrenclave string = encInfo.Mrenclave
	var remoteMrsigner string = encInfo.Mrsigner
	fmt.Println("App Enclave mrenclave:", remoteMrenclave)
	fmt.Println("App Enclave mrsigner:", remoteMrsigner)
	return encInfo, nil
}
