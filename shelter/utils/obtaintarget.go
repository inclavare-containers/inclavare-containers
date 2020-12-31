package utils

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	repoKeyWord = "github.com"
)

//bash cmd exec
func ExecShell(cmdstring string) (retstr string, ret bool) {
	cmd := exec.Command("/bin/bash", "-c", cmdstring)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Errorf("exec bash cmd %s with error %s.\n", cmdstring, err)
		return "", false
	}

	if err = cmd.Start(); err != nil {
		fmt.Errorf("exec bash cmd.Start %s with error %s.\n", cmdstring, err)
		return "", false
	}

	var rstr string = ""
	for {
		tmp := make([]byte, 1024)
		_, err := stdout.Read(tmp)
		fmt.Print(string(tmp))
		rstr = rstr + string(tmp)
		if err != nil {
			fmt.Errorf("exec bash cmd, err is %s.\n", err)
			break
		}
	}

	if err := cmd.Wait(); err != nil {
		fmt.Errorf("exec bash cmd.Wait %s with error %s.\n", cmdstring, err)
		return "", false
	}

	return rstr, true
}

//precheck if git is ready
func CheckGit() bool {
	cmd_string := "git version"
	if _, ret := ExecShell(cmd_string); !ret {
		fmt.Errorf("git is not ready.\n")
		return false
	}
	return true
}

//check if local directory exist;
func CheckPath(path string) bool {
	fileinfo, err := os.Stat(path)
	if err != nil {
		fmt.Errorf("file or path: %s not exist!, err is %s.\n", path, err)
		return false
	}
	return fileinfo.IsDir()
}

//check if the url include right keyword or not;
func checkurl(url string, keyword string) bool {
	return strings.Contains(url, keyword)
}

//download target source code to local path
func GetSrcCode(srcurl string, branch string, commitid string, localpath string) bool {
	var i uint
	if ret := CheckGit(); !ret {
		fmt.Errorf("CheckGit failed.\n")
		return false
	}

	if ret := checkurl(srcurl, repoKeyWord); !ret {
		fmt.Errorf("checkurl failed,srcurl is %s, repokeyword is %s.\n", srcurl, repoKeyWord)
		return false
	}

	if ret := CheckPath(localpath); ret == true {
		if ret := os.RemoveAll(localpath); ret != nil {
			fmt.Errorf("Remove localpath %s failed\n", localpath)
		}
	}

	//build locla path
	if ret := os.MkdirAll(localpath, os.ModePerm); ret != nil {
		fmt.Errorf("Create localpath %s failed\n", localpath)
		return false
	}

	var bt bytes.Buffer
	cmd_string := "git clone "
	bt.WriteString(cmd_string)
	bt.WriteString(srcurl)
	bt.WriteString(" -b ")
	bt.WriteString(branch)
	bt.WriteString(" ")
	bt.WriteString(localpath)
	allcmd := bt.String()
	if _, ret := ExecShell(allcmd); !ret {
		for i = 0; i < 3; i++ {
			_, ret := ExecShell(allcmd)
			if ret == true {
				break
			}
		}
		if i == 3 {
			fmt.Errorf("GetSrcCode failed with error %s.\n", ret)
			return false
		}
	}

	return true
}

func BuildTargetSrc(path string) bool {
	if ret := CheckPath(path); !ret {
		return false
	}

	currentpath, _ := os.Getwd()
	os.Chdir(path)

	cmd_string := "pwd"
	_, _ = ExecShell(cmd_string)
	cmd_string = "make clean"
	_, _ = ExecShell(cmd_string)
	cmd_string = "make"
	if _, ret := ExecShell(cmd_string); !ret {
		fmt.Errorf("make target projcet failed.\n")
		return false
	}
	os.Chdir(currentpath)
	return true
}
