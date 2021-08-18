module github.com/inclavare-containers/sgx-tools

go 1.14

require (
	github.com/go-restruct/restruct v0.0.0-20191227155143-5734170a48a1
	github.com/inclavare-containers/epm v0.0.0-00010101000000-000000000000 // indirect
	github.com/inclavare-containers/rune v0.0.0-00010101000000-000000000000
	github.com/konsorten/go-windows-terminal-sequences v1.0.3 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/urfave/cli v1.22.4
)

replace (
	github.com/inclavare-containers/epm => github.com/alibaba/inclavare-containers/epm v0.0.0-20201031054937-5f9853351c6c
	github.com/inclavare-containers/rune => github.com/alibaba/inclavare-containers/rune v0.0.0-20210817133247-5cb0274219c8
)
