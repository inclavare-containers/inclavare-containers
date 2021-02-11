module github.com/inclavare-containers/sgx-tools

go 1.14

require (
	github.com/go-restruct/restruct v0.0.0-20191227155143-5734170a48a1
	github.com/golang/protobuf v1.4.2 // indirect
	github.com/inclavare-containers/epm v0.0.0-00010101000000-000000000000 // indirect
	github.com/inclavare-containers/rune v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.6.0
	github.com/urfave/cli v1.22.4
)

replace (
	github.com/inclavare-containers/epm => github.com/alibaba/inclavare-containers/epm v0.0.0-20201031054937-5f9853351c6c
	github.com/inclavare-containers/rune => github.com/alibaba/inclavare-containers/rune v0.0.0-20210211091308-fcf82973a538
)
