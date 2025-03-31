package wgkeys

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func GeneratePrivateKey() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("error generate the private key")
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func GeneratePublicKey(privateKey string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("error decoding the private key")
	}
	publicKey := make([]byte, 32)
	copy(publicKey, key[:32])
	return base64.StdEncoding.EncodeToString(publicKey), nil
}
