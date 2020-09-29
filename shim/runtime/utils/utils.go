package utils

import (
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
)

func CopyFile(src, dst string, bufferSize int64) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file.", src)
	}
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()
	_, err = os.Stat(dst)
	if err == nil {
		return fmt.Errorf("File %s already exists.", dst)
	}

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, bufferSize)
	for {
		n, err := source.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}
		if _, err := destination.Write(buf[:n]); err != nil {
			return err
		}
	}
	return err
}

// ExecCommand executes the cmd with args
func ExecCommand(cmd string, arg ...string) ([]byte, error) {
	b, err := exec.Command(cmd, arg...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s", string(b), err)
	}
	return b, nil
}

func Md5File(file string) (string, error) {
	if _, err := os.Stat(file); err != nil {
		return "", err
	}
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", md5.Sum(bytes)), nil
}
