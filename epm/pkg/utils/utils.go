package utils

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

const blockSize = 1024 * 4

/*func ExecCmd(cmd string, args []string) (string, error) {
	c := exec.Command(cmd, args...)
	b, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("output: %s, error:%++v", string(b), err)
	}
	return string(b), nil
}*/

func DirSize(dir string) (int64, error) {
	var total int64 = 0
	f, err := os.Lstat(dir)
	if err != nil {
		return 0, err
	}
	if f.IsDir() {
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			return 0, err
		}
		for _, file := range files {
			size, err := DirSize(filepath.Join(dir, file.Name()))
			if err != nil {
				return 0, err
			}
			total += size
		}
	} else {
		size, err := FileSize(dir)
		if err != nil {
			return 0, err
		}
		total += size
	}
	return total, nil
}

func FileSize(file string) (int64, error) {
	f, err := os.Lstat(file)
	if err != nil {
		return 0, err
	}
	size := f.Size()
	blocks := size / blockSize
	remainder := size % blockSize
	if remainder > 0 {
		size = (blocks + 1) * blockSize
	}
	return size, nil
}
