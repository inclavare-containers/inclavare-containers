package attestation // import "github.com/inclavare-containers/rune/libenclave/attestation"

func GetParameter(key string, p map[string]string) string {
	for k, v := range p {
		if k == key {
			return v
		}
	}

	return ""
}
