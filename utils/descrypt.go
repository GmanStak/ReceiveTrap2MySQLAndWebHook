package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

var AESKEY = "0ra5s7dixgtkswy7"

func Descrypt(pass64 string) (string, error) {
	bytesPass, err := base64.StdEncoding.DecodeString(pass64)
	if err != nil {
		return "", err
	}
	tpass, err := AesDecrypt(bytesPass, []byte(AESKEY))
	if err != nil {
		return "", err
	}
	return string(tpass), nil
}

func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
