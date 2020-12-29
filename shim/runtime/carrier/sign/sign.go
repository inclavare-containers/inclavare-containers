package sign

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"os/exec"
	"path/filepath"

	signclient "github.com/inclavare-containers/shim/runtime/signature/client"
)

const requestGroup = "/api/v1/signature"

func GetPublicKey(serverAddress string) (publicKeyFile string, err error) {
	url, err := url.Parse(fmt.Sprintf("%s%s", serverAddress, requestGroup))
	if err != nil {
		return "", err
	}
	client := signclient.NewClient(signclient.PKCS1, url)
	bytes, err := client.GetPublicKey()
	if err != nil {
		return "", err
	}
	file, err := ioutil.TempFile("/tmp", "public-key")
	if err != nil {
		return "", err
	}
	if err = ioutil.WriteFile(file.Name(), bytes, 0644); err != nil {
		return "", err
	}
	return file.Name(), nil
}

func RemoteSign(signingMaterial, serverAddress string) (publicKeyFile, signatureFile string, err error) {
	url, err := url.Parse(fmt.Sprintf("%s%s", serverAddress, requestGroup))
	if err != nil {
		return
	}
	client := signclient.NewClient(signclient.PKCS1, url)
	bytes, err := ioutil.ReadFile(signingMaterial)
	if err != nil {
		return
	}
	dir, err := ioutil.TempDir("/tmp", "signature-")
	if err != nil {
		return
	}
	signatureFile = filepath.Join(dir, "signature.dat")
	publicKeyFile = filepath.Join(dir, "public_key.pem")
	signature, publicKey, err := client.Sign(bytes)
	if err != nil {
		return "", "", err
	}
	if err := ioutil.WriteFile(signatureFile, signature, 0644); err != nil {
		return "", "", err
	}
	if err := ioutil.WriteFile(publicKeyFile, publicKey, 0644); err != nil {
		return "", "", err
	}
	return
}

func MockSign(signingMaterial string) (publicKeyFile, signatureFile string, err error) {
	dir, _ := ioutil.TempDir("/tmp", "signature-")
	privateKeyFile := filepath.Join(dir, "private_key.pem")
	publicKeyFile = filepath.Join(dir, "public_key.pem")
	signatureFile = filepath.Join(dir, "signature.dat")
	cmd := exec.Command("openssl", "genrsa", "-out", privateKeyFile, "-3", "3072")
	if _, err = cmd.Output(); err != nil {
		return
	}
	cmd = exec.Command("openssl", "rsa", "-in", privateKeyFile, "-pubout", "-out", publicKeyFile)
	if _, err = cmd.Output(); err != nil {
		return
	}
	cmd = exec.Command("openssl", "dgst", "-sha256", "-out", signatureFile, "-sign", privateKeyFile, "-keyform", "PEM", signingMaterial)
	if _, err = cmd.Output(); err != nil {
		return
	}
	return
}
