package utils

import (
	"testing"
)

func Test_CopyDirectory(t *testing.T) {
	t.Skip()
	err := CopyDirectory("/tmp/test/src", "/tmp/test/dst/fff")
	if err != nil {
		t.Fatal(err)
	}
}

func Test_CopyFile(t *testing.T) {
	err := copyFile("/tmp/test/src/a/a.txt", "/tmp/test/dst/a/a.txt")
	if err != nil {
		t.Fatal(err)
	}
}

func Test_CopySymLink(t *testing.T) {
	err := CopyDirectory("/tmp/test/src/rune/build/bin", "/tmp/test/dst/bin")
	if err != nil {
		t.Fatal(err)
	}
}
