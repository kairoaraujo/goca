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
package _storage

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// File name constants
const (
	PEMFile       = "key.pem"
	PublicPEMFile = "key.pub"
)

func checkError(err error) error {
	if err != nil {
		return err
	}

	return nil
}

func savePEMKey(fileName string, key *rsa.PrivateKey) {

	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	checkError(err)
}

func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	checkError(err)

	err = os.Chmod(fileName, 0600)
	checkError(err)
}

func saveCSR(fileName string, csr []byte) {
	var pemCSR = &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}
	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemCSR)
	checkError(err)

}

func saveCert(fileName string, cert []byte) {
	var pemCert = &pem.Block{Type: "CERTIFICATE", Bytes: cert}
	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemCert)
	checkError(err)

}

func saveCRL(fileName string, crl []byte) {
	var pemCRL = &pem.Block{Type: "X509 CRL", Bytes: crl}
	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemCRL)
	checkError(err)
}

// File has the content to save a file
type File struct {
	CA             string
	CommonName     string
	FileType       FileType
	PrivateKeyData *rsa.PrivateKey
	PublicKeyData  rsa.PublicKey
	CSRData        []byte
	CertData       []byte
	CRLData        []byte
	CreationType   CreationType
}

// CheckCertExists returns if a certificate exists or not
func CheckCertExists(f File) bool {
	caPath, _ := caPathInit()
	if _, err := os.Stat(caPath + "/" + f.CA + "/certs/" + f.CommonName + "/" + f.CommonName + ".crt"); os.IsNotExist(err) {
		return false
	}

	return true
}

// MakeFolder creates folder inside the CAPATH infrastructure.
func MakeFolder(folderPath string) error {

	errMakedirAll := os.MkdirAll(folderPath, 0755)
	if errMakedirAll != nil {
		return errMakedirAll
	}

	return nil

}

func caPathInit() (string, error) {
	CAPATH := os.Getenv("CAPATH")

	if CAPATH == ".//" && os.Getenv("GOCATEST") != "true" {
		return "", errors.New("not allowed CAPATH=./DoNotUseThisCAPATHTestOnly")

	} else if CAPATH == "" {
		currentPath, err := os.Getwd()

		if err != nil {
			return "", err
		}

		CAPATH = currentPath
	}

	if _, err := os.Stat(CAPATH); os.IsNotExist(err) {

		err := MakeFolder(CAPATH)
		if err != nil {
			return "", err
		}

	}

	return CAPATH, nil
}

func CAPathIsReady() (string, error) {

	caPath, err := caPathInit()

	return caPath, err
}

func CAStorage(commonName string) bool {
	caPath, err := CAPathIsReady()
	if err != nil {
		return false
	}

	if _, err := os.Stat(caPath + "/" + commonName); os.IsNotExist(err) {
		return false
	}

	return true

}

// CreationType represents if CA or Certificate owns the file
type CreationType int

const (
	// CreationTypeCA owned by CA
	CreationTypeCA CreationType = 1 << iota
	// CreationTypeCertificate owned by Certificate
	CreationTypeCertificate
)

// FileType represents what type of file
type FileType int

const (
	// FileTypeKey is Key files
	FileTypeKey FileType = 1 << iota
	// FileTypeCSR is a Certificate Signging Request file
	FileTypeCSR
	// FileTypeCertificate is a Certificate file
	FileTypeCertificate
	// FileTypeCRL is a Certificate Revoking List file
	FileTypeCRL
)

// SaveFile saves a File{}
func SaveFile(f File) error {

	var fileName string

	caDir, err := caPathInit()
	if err != nil {
		return nil

	}

	fileName = caDir

	// Creation type
	switch f.CreationType {
	case CreationTypeCA:
		fileName += "/" + f.CA + "/ca/"

	case CreationTypeCertificate:
		fileName += "/" + f.CA + "/certs/" + f.CommonName + "/"
		if _, err := os.Stat(fileName); os.IsNotExist(err) {

			err := MakeFolder(fileName)
			if err != nil {
				return err
			}
		}
	}

	// File Type
	switch f.FileType {
	case FileTypeKey:
		savePEMKey(fileName+PEMFile, f.PrivateKeyData)
		savePublicPEMKey(fileName+PublicPEMFile, f.PublicKeyData)

	case FileTypeCSR:
		saveCSR(fileName+"/"+f.CommonName+".csr", f.CSRData)

	case FileTypeCertificate:
		saveCert(fileName+"/"+f.CommonName+".crt", f.CertData)

	case FileTypeCRL:
		saveCRL(fileName+"/"+f.CommonName+".crl", f.CRLData)
	}

	return nil

}

// LoadFile loads a file by file name from $CAPATH
func LoadFile(fileName string) ([]byte, error) {
	caPath, err := CAPathIsReady()
	if err != nil {
		return nil, err
	}

	fileData, err := ioutil.ReadFile(caPath + "/" + fileName)
	if err != nil {
		return []byte{}, err
	}

	return fileData, nil

}

// ListCertificates return a list of certificates folders
func ListCertificates(CACommonName string) []string {
	caPath, err := CAPathIsReady()
	if err != nil {
		return nil
	}

	var certificates []string

	files, err := filepath.Glob(caPath + "/" + CACommonName + "/certs/*")
	if err != nil {
		return nil
	}

	for _, f := range files {
		info, _ := os.Stat(f)
		if info.IsDir() {
			dirSplited := strings.Split(f, "/")
			certificates = append(certificates, dirSplited[len(dirSplited)-1])
		}
	}

	return certificates
}
