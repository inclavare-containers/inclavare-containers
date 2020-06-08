package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"

	"github.com/alibaba/inclavare-containers/shim/runtime/signature/types"

	"github.com/golang/glog"

	"github.com/gin-gonic/gin"
)

var rng = rand.Reader

func (s *ApiServer) pkcs1Handler(c *gin.Context) {
	payload := &types.SignaturePayload{}
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		glog.Errorf("failed to parse request body, err:%v", err.Error())
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	hashed := sha256.Sum256(body)
	signedBytes, err := rsa.SignPKCS1v15(rng, s.privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		glog.Errorf("failed to sign request, err:%v", err.Error())
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	payload.Signature = string(signedBytes)
	payload.PublicKey = string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(s.publicKey),
	}))
	c.JSON(http.StatusOK, payload)
}
