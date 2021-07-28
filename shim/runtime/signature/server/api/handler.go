package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"io/ioutil"
	"net/http"

	"github.com/inclavare-containers/shim/runtime/signature/types"

	"k8s.io/klog/v2"

	"github.com/gin-gonic/gin"
)

var rng = rand.Reader

func (s *ApiServer) pkcs1Handler(c *gin.Context) {
	payload := &types.SignaturePayload{}
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		klog.Errorf("failed to parse request body, err:%v", err.Error())
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	hashed := sha256.Sum256(body)
	signedBytes, err := rsa.SignPKCS1v15(rng, s.privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		klog.Errorf("failed to sign request, err:%v", err.Error())
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	payload.Signature = base64.StdEncoding.EncodeToString(signedBytes)
	bytes, err := ioutil.ReadFile(s.publicKeyFilePath)
	if err != nil {
		klog.Errorf("failed to parse public key, public key path: %s, err:%v", s.publicKeyFilePath, err.Error())
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	payload.PublicKey = string(bytes)
	c.JSON(http.StatusOK, payload)
}

func (s *ApiServer) publicKeyHandler(c *gin.Context) {
	bytes, err := ioutil.ReadFile(s.publicKeyFilePath)
	if err != nil {
		klog.Errorf("failed to parse public key, public key path: %s, err:%v", s.publicKeyFilePath, err.Error())
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.String(http.StatusOK, string(bytes))
}
