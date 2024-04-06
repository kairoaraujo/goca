// MIT License
//
// Copyright (c) 2020, Kairo de Araujo
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package key provides RSA Key API management for crypto/x509/rsa.
//
// This package makes easy to generate Keys and load RSA from files to be
// used by GoLang applications.
//
// Generating RSA Keys, the files will be saved in the $CAPATH by default.
// For $CAPATH, please check out the GoCA documentation.
package key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	storage "github.com/kairoaraujo/goca/v2/_storage"
)

// KeysData represents the RSA keys with Private Key (Key) and Public Key (Public Key).
type KeysData struct {
	Key       rsa.PrivateKey
	PublicKey rsa.PublicKey
}

// CreateKeys creates RSA private and public keyData that contains Key and PublicKey.
//
// The files are stored in the $CAPATH
func CreateKeys(CACommonName, commonName string, creationType storage.CreationType, bitSize int) (KeysData, error) {
	reader := rand.Reader
	if bitSize == 0 {
		bitSize = 2048
	}

	key, err := rsa.GenerateKey(reader, bitSize)

	if err != nil {
		return KeysData{}, err
	}

	publicKey := key.PublicKey

	fileData := storage.File{
		CA:             CACommonName,
		CommonName:     commonName,
		FileType:       storage.FileTypeKey,
		PrivateKeyData: key,
		PublicKeyData:  publicKey,
		CreationType:   creationType,
	}

	err = storage.SaveFile(fileData)
	if err != nil {
		return KeysData{}, err
	}

	keys := KeysData{
		Key:       *key,
		PublicKey: publicKey,
	}

	return keys, nil
}

// LoadPrivateKey loads a RSA Private Key from a read file.
//
// Using ioutil.ReadFile() satisfyies it.
func LoadPrivateKey(keyString []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(string(keyString)))
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	return privateKey, nil
}

// LoadPublicKey loads a RSA Public Key from a read file.
//
// Using ioutil.ReadFile() satisfyies it.
func LoadPublicKey(keyString []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(string(keyString)))
	publicKey, _ := x509.ParsePKCS1PublicKey(block.Bytes)

	return publicKey, nil
}
