package utils

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"
)

type CopyOptions struct {
	overwrite      bool
	followSymbolic bool
}

type CopyOpt func(*CopyOptions)

func defaultCopyOptions() *CopyOptions {
	return &CopyOptions{
		overwrite:      true,
		followSymbolic: false,
	}
}

func NotOverwrite(option *CopyOptions) {
	option.overwrite = false
}

func FollowSymbolic(option *CopyOptions) {
	option.followSymbolic = true
}

func CopyDirectory(scrDir, dest string, opts ...CopyOpt) error {
	entries, err := ioutil.ReadDir(scrDir)
	if err != nil {
		return err
	}
	options := defaultCopyOptions()
	for _, opt := range opts {
		opt(options)
	}
	for _, entry := range entries {
		sourcePath := filepath.Join(scrDir, entry.Name())
		destPath := filepath.Join(dest, entry.Name())
		var fileInfo os.FileInfo
		var err error
		if options.followSymbolic {
			fileInfo, err = os.Stat(sourcePath)
		} else {
			fileInfo, err = os.Lstat(sourcePath)
		}
		if err != nil {
			return err
		}
		stat, ok := fileInfo.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("failed to get raw syscall.Stat_t data for '%s'", sourcePath)
		}

		switch fileInfo.Mode() & os.ModeType {
		case os.ModeDir:
			if err := CreateIfNotExists(destPath, 0755); err != nil {
				return err
			}
			if err := CopyDirectory(sourcePath, destPath, opts...); err != nil {
				return err
			}
		case os.ModeSymlink:
			if err := copySymLink(sourcePath, destPath, options.overwrite); err != nil {
				return err
			}
		default:
			if err := copyFile(sourcePath, destPath, options.overwrite); err != nil {
				return err
			}
		}

		if err := os.Lchown(destPath, int(stat.Uid), int(stat.Gid)); err != nil {
			return err
		}

		isSymlink := entry.Mode()&os.ModeSymlink != 0
		if !isSymlink {
			if err := os.Chmod(destPath, entry.Mode()); err != nil {
				return err
			}
		}
	}
	return nil
}

func CopyFile(srcFile, dstFile string, opts ...CopyOpt) error {
	fileInfo, err := os.Lstat(srcFile)
	if err != nil {
		return err
	}
	options := defaultCopyOptions()
	for _, opt := range opts {
		opt(options)
	}
	switch fileInfo.Mode() & os.ModeType {
	case os.ModeDir:
		return fmt.Errorf("%s is a direcotry, not a file", srcFile)
	case os.ModeSymlink:
		if err := copySymLink(srcFile, dstFile, options.overwrite); err != nil {
			return err
		}
	default:
		if err := copyFile(srcFile, dstFile, options.overwrite); err != nil {
			return err
		}
	}
	return nil
}

func Exists(filePath string) bool {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	}
	return true
}

func CreateIfNotExists(dir string, perm os.FileMode) error {
	if Exists(dir) {
		return nil
	}

	if err := os.MkdirAll(dir, perm); err != nil {
		return fmt.Errorf("failed to create directory: '%s', error: '%s'", dir, err.Error())
	}
	return nil
}

func copySymLink(source, dest string, overwrite bool) error {
	if overwrite {
		os.Remove(dest)
	} else if _, err := os.Lstat(dest); err == nil {
		return nil
	}
	link, err := os.Readlink(source)
	if err != nil {
		return err
	}
	return os.Symlink(link, dest)
}

func copyFile(srcFile, dstFile string, overwrite bool) error {
	if overwrite {
		os.Remove(dstFile)
	} else if _, err := os.Lstat(dstFile); err == nil {
		return nil
	}
	out, err := os.Create(dstFile)
	if err != nil {
		return err
	}

	defer out.Close()

	in, err := os.Open(srcFile)
	defer in.Close()
	if err != nil {
		return err
	}

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}

	return nil
}
