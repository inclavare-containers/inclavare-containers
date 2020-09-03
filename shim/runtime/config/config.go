package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	defaultEnclaveType = "intelSgx"
	envSeparator       = "="
)

// LoadSpec loads the specification from the provided path.
func LoadSpec(cPath string) (spec *specs.Spec, err error) {
	cf, err := os.Open(cPath)
	if err != nil {
		return nil, err
	}
	defer cf.Close()
	if err = json.NewDecoder(cf).Decode(&spec); err != nil {
		return nil, err
	}
	_, err = json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	return spec, nil
}

func SaveSpec(cPath string, spec *specs.Spec) error {
	data, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(cPath, data, 0644)
}

func UpdateEnvs(spec *specs.Spec, kvs map[string]string, overwrite bool) error {
	if spec.Process == nil || kvs == nil || len(kvs) <= 0 {
		return nil
	}
	all := make(map[string]string)
	for _, env := range spec.Process.Env {
		p := strings.SplitN(env, envSeparator, 2)
		if len(p) != 2 {
			continue
		}
		all[p[0]] = p[1]
	}
	for k, v := range kvs {
		if overwrite {
			all[k] = v
		} else if _, ok := all[k]; !ok {
			all[k] = v
		}
	}
	envs := make([]string, 0)
	for k, v := range all {
		envs = append(envs, fmt.Sprintf("%s%s%s", k, envSeparator, v))
	}
	spec.Process.Env = envs
	return nil
}

func GetEnv(spec *specs.Spec, key string) (string, bool) {
	if spec.Process == nil {
		return "", false
	}
	for _, env := range spec.Process.Env {
		p := strings.SplitN(env, envSeparator, 2)
		if len(p) != 2 {
			continue
		}
		if p[0] != key {
			continue
		}
		return p[1], true
	}
	return "", false
}

func UpdateEnclaveEnvConfig(cPath string) error {
	spec, err := LoadSpec(cPath)
	if err != nil {
		return err
	}
	var name string = "ENCLAVE_TYPE"
	m := map[string]string{name: defaultEnclaveType}
	if err := UpdateEnvs(spec, m, false); err != nil {
		return err
	}
	if err := SaveSpec(cPath, spec); err != nil {
		return err
	}
	return nil
}
