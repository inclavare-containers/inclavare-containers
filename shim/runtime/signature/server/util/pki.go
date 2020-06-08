package util

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

func ParseRsaPrivateKey(file string) (*rsa.PrivateKey, error) {
	priByte, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(priByte)
	if b == nil {
		return nil, errors.New("error decoding private key")
	}
	priKey, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	return priKey, nil
}

func ParseX509Certificate(file string) (*x509.Certificate, error) {
	cerBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	cer, err := x509.ParseCertificate(cerBytes)
	if err != nil {
		return nil, errors.New("error parsing certificate")
	}
	return cer, nil
}

func ParseRsaPublicKey(file string) (*rsa.PublicKey, error) {
	pubByte, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(pubByte)
	if b == nil {
		return nil, errors.New("error decoding public key")
	}
	pubKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	return pubKey.(*rsa.PublicKey), nil
}
