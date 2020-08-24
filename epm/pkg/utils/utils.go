package utils

import (
	"fmt"
	"os/exec"
)

func ExecCmd(cmd string, args []string) (string, error) {
	c := exec.Command(cmd, args...)
	b, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("output: %s, error:%++v", string(b), err)
	}
	return string(b), nil
}
