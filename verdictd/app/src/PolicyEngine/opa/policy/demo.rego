package demo

mrEnclave = "123"
mrSigner = "456"
productId = "1"

default allow = false

allow = true {
	mrEnclave == input.mrEnclave
	mrSigner == input.mrSigner
	productId == input.productId
}