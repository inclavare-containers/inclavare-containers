package v2

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/BurntSushi/toml"
	"os"
	"path/filepath"

	shim_config "github.com/inclavare-containers/shim/config"
	"github.com/inclavare-containers/shim/runtime/v2/rune/constants"
)

var (
	logLevel              string
	agentContainerRootDir string
	agentContainerPath    string
)

func parseConfig() error {
	var cfg shim_config.Config

	_, err := toml.DecodeFile(constants.ConfigurationPath, &cfg)
	if err != nil {
		return err
	}

	logLevel = cfg.LogLevel
	agentContainerPath = cfg.Containerd.AgentContainerInstance
	agentContainerRootDir = cfg.Containerd.AgentContainerRootDir

	return nil
}

// resolvePath returns the fully resolved and expanded value of the
// specified path.
func resolvePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path must be specified")
	}

	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		if os.IsNotExist(err) {
			// Make the error clearer than the default
			return "", fmt.Errorf("file %v does not exist", absolute)
		}

		return "", err
	}

	return resolved, nil
}

func validBundle(containerID, bundlePath string) (string, error) {
	// container ID MUST be provided.
	if containerID == "" {
		return "", fmt.Errorf("missing container ID")
	}

	// bundle path MUST be provided.
	if bundlePath == "" {
		return "", fmt.Errorf("missing bundle path")
	}

	// bundle path MUST be valid.
	fileInfo, err := os.Stat(bundlePath)
	if err != nil {
		return "", fmt.Errorf("invalid bundle path '%s': %s", bundlePath, err)
	}
	if !fileInfo.IsDir() {
		return "", fmt.Errorf("invalid bundle path '%s', it should be a directory", bundlePath)
	}

	resolved, err := resolvePath(bundlePath)
	if err != nil {
		return "", err
	}

	return resolved, nil
}

func generateID() string {
	b := make([]byte, 32)
	rand.Read(b)

	return hex.EncodeToString(b)
}
