// MIT License
//
// # Copyright (c) 2020, Kairo de Araujo
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
	"io"
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

var ErrIncompleteCopy = errors.New("file copy was incomplete")

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

	err = os.Chmod(fileName, 0600)
	checkError(err)

	var privateKey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	checkError(err)
}

func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "RSA PUBLIC KEY",
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
	if _, err := os.Stat(filepath.Join(caPath, f.CA, "certs", f.CommonName, f.CommonName+".crt")); os.IsNotExist(err) {
		return false
	}

	return true
}

// MakeFolder creates folder inside the CAPATH infrastructure.
func MakeFolder(folderPath ...string) error {

	errMakedirAll := os.MkdirAll(filepath.Join(folderPath...), 0755)
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

	if _, err := os.Stat(filepath.Join(caPath, commonName)); os.IsNotExist(err) {
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
		fileName = filepath.Join(fileName, f.CA, "ca")

	case CreationTypeCertificate:
		fileName = filepath.Join(fileName, f.CA, "certs", f.CommonName)
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
		savePEMKey(filepath.Join(fileName, PEMFile), f.PrivateKeyData)
		savePublicPEMKey(filepath.Join(fileName, PublicPEMFile), f.PublicKeyData)

	case FileTypeCSR:
		saveCSR(filepath.Join(fileName, f.CommonName+".csr"), f.CSRData)

	case FileTypeCertificate:
		saveCert(filepath.Join(fileName, f.CommonName+".crt"), f.CertData)

	case FileTypeCRL:
		saveCRL(filepath.Join(fileName, f.CommonName+".crl"), f.CRLData)
	}

	return nil

}

// LoadFile loads a file by file name from $CAPATH
func LoadFile(filePath ...string) ([]byte, error) {
	var fileName = filepath.Join(filePath...)
	caPath, err := CAPathIsReady()
	if err != nil {
		return nil, err
	}

	fileData, err := ioutil.ReadFile(filepath.Join(caPath, fileName))
	if err != nil {
		return []byte{}, err
	}

	return fileData, nil

}

// CopyFile copies the specified src file to the given destination.
// Both paths are relative to the $CAPATH hierarchy.
func CopyFile(src, dest string) error {
	caPath, err := CAPathIsReady()
	if err != nil {
		return err
	}

	srcPath := filepath.Join(caPath, src)
	destPath := filepath.Join(caPath, dest)

	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()

	inStat, err := in.Stat()
	if err != nil {
		return err
	}

	out, err := os.OpenFile(destPath, os.O_RDWR|os.O_CREATE, inStat.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	written, err := io.Copy(out, in)
	if err != nil {
		return err
	}

	if written != inStat.Size() {
		return ErrIncompleteCopy
	}

	return nil
}

func listDirs(paths ...string) []string {
	var path = filepath.Join(paths...)
	caPath, err := CAPathIsReady()
	if err != nil {
		return nil
	}

	var dirs []string

	files, err := filepath.Glob(filepath.Join(caPath, path, "*"))
	if err != nil {
		return nil
	}

	for _, f := range files {
		info, _ := os.Stat(f)
		if info.IsDir() {
			dirSplited := strings.Split(f, string(os.PathSeparator))
			dirs = append(dirs, dirSplited[len(dirSplited)-1])
		}
	}

	return dirs
}

// ListCertificates return a list of certificates folders
func ListCertificates(CACommonName string) []string {
	return listDirs(CACommonName, "certs")
}

// ListCAs return a list of certificates folders
func ListCAs() []string {
	return listDirs("")
}
