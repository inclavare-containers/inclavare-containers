package constants

const (
	ConfigurationPath        = "/etc/inclavare-containers/config.toml"
	RuneOCIRuntime           = "rune"
	EnvKeyRuneCarrier        = "RUNE_CARRIER"
	EnvKeyRaType             = "ENCLAVE_IS_RA_TYPE_EPID"
	EnvKeyIsProductEnclave   = "ENCLAVE_IS_PRODUCT_ENCLAVE"
	EnvKeyRaEpidSpid         = "ENCLAVE_RA_EPID_SPID"
	EnvKeyRaEpidSubKey       = "ENCLAVE_RA_EPID_SUB_KEY"
	EnvKeyRaEpidIsLinkable   = "ENCLAVE_RA_EPID_IS_LINKABLE"
	EnvKeyImageDigest        = "IMAGE_DIGEST"
	RuneDefaultWorkDirectory = "/var/run/rune"
)

const (
	SignatureMethodServer = "server"
	SignatureMethodClient = "client"
)
