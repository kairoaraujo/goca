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

// Package cert provides RSA Key API management for crypto/x509 certificates.
//
//
// This package makes easy to generate and certificates from files to be used
// by GoLang applications.
//
// Generating Certificates (even by Signing), the files will be saved in the
// $CAPATH by default.
//For $CAPATH, please check out the GoCA documentation.
package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"time"

	storage "github.com/kairoaraujo/goca/_storage"
)

const (
	// MinValidCert is the minimal valid time: 1 day
	MinValidCert int = 1
	// MaxValidCert is the maximum valid time: 825 day
	MaxValidCert int = 825
	// DefaultValidCert is the default valid time: 397 days
	DefaultValidCert int = 397
)

// ErrCertExists means that the certificate requested already exists
var ErrCertExists = errors.New("certificate already exists")

func newSerialNumber() (serialNumber *big.Int) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)

	return serialNumber
}

// CreateCSR creates a Certificate Signing Request returning certData with CSR.
//
// The CSR is also stored in $CAPATH with extension .csr
func CreateCSR(CACommonName, commonName, country, province, locality, organization, organizationalUnit, emailAddresses string, dnsNames []string, priv *rsa.PrivateKey, creationType storage.CreationType) (csr []byte, err error) {
	var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	subject := pkix.Name{
		CommonName:         commonName,
		Country:            []string{country},
		Province:           []string{province},
		Locality:           []string{locality},
		Organization:       []string{organization},
		OrganizationalUnit: []string{organizationalUnit},
	}

	rawSubj := subject.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddresses},
	})
	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{emailAddresses},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	dnsNames = append(dnsNames, commonName)
	template.DNSNames = dnsNames

	csr, err = x509.CreateCertificateRequest(rand.Reader, &template, priv)
	if err != nil {
		return csr, err
	}

	fileData := storage.File{
		CA:           CACommonName,
		CommonName:   commonName,
		FileType:     storage.FileTypeCSR,
		CSRData:      csr,
		CreationType: creationType,
	}

	err = storage.SaveFile(fileData)

	if err != nil {
		return csr, err
	}

	return csr, nil
}

// LoadCSR loads a Certificate Signing Request from a read file.
//
// Using ioutil.ReadFile() satisfyies the read file.
func LoadCSR(csrString []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(string(csrString)))
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	return csr, nil
}

// CreateRootCert creates a Root CA Certificate (self signed)
func CreateRootCert(CACommonName, commonName, country, province, locality, organization, organizationalUnit, emailAddresses string, valid int, dnsNames []string, priv *rsa.PrivateKey, pub *rsa.PublicKey, creationType storage.CreationType) (cert []byte, err error) {

	if valid == 0 {
		valid = DefaultValidCert
	}
	rootCA := &x509.Certificate{
		SerialNumber: newSerialNumber(),
		Subject: pkix.Name{
			Organization:       []string{organization},
			OrganizationalUnit: []string{organizationalUnit},
			Country:            []string{country},
			Province:           []string{province},
			Locality:           []string{locality},
			//TODO: StreetAddress: []string{"ADDRESS"},
			//TODO: PostalCode:    []string{"POSTAL_CODE"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, valid),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	dnsNames = append(dnsNames, commonName)
	rootCA.DNSNames = dnsNames

	cert, err = x509.CreateCertificate(rand.Reader, rootCA, rootCA, pub, priv)
	if err != nil {
		return nil, err
	}

	fileData := storage.File{
		CA:           CACommonName,
		CommonName:   commonName,
		FileType:     storage.FileTypeCertificate,
		CertData:     cert,
		CreationType: creationType,
	}

	err = storage.SaveFile(fileData)

	if err != nil {
		return nil, err
	}

	return cert, nil
}

// LoadCert loads a certifiate from a read file (bytes).
//
// Using ioutil.ReadFile() satisfyies the read file.
func LoadCert(certString []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(string(certString)))
	cert, _ := x509.ParseCertificate(block.Bytes)

	return cert, nil
}

// CASignCSR signs an Certificate Signing Request and returns the Certificate as Go bytes.
//
// A file is also stored in $CAPATH/certs/<CSR Common Name>/<CSR Common Name>.crt
func CASignCSR(CACommonName string, csr x509.CertificateRequest, caCert *x509.Certificate, privKey *rsa.PrivateKey, valid int, creationType storage.CreationType) (cert []byte, err error) {
	if valid == 0 {
		valid = DefaultValidCert

	} else if valid > MaxValidCert || valid < MinValidCert {
		return nil, errors.New("the certificate valid (min/max) is not between 1 - 825")
	}

	fileData := storage.File{
		CA:           CACommonName,
		CommonName:   csr.Subject.CommonName,
		FileType:     storage.FileTypeCertificate,
		CreationType: creationType,
	}

	if storage.CheckCertExists(fileData) {
		return nil, ErrCertExists
	}

	if err != nil {
		return nil, err
	}

	csrTemplate := x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: newSerialNumber(),
		Issuer:       caCert.Subject,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, valid),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	csrTemplate.DNSNames = csr.DNSNames

	cert, err = x509.CreateCertificate(rand.Reader, &csrTemplate, caCert, csrTemplate.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	fileData.CertData = cert

	err = storage.SaveFile(fileData)

	if err != nil {
		return nil, err
	}

	return cert, nil

}

// RevokeCertificate is used to revoke a certificate (added to the revoked list)
func RevokeCertificate(CACommonName string, certificateList []pkix.RevokedCertificate, caCert *x509.Certificate, privKey *rsa.PrivateKey) (crl []byte, err error) {

	crlTemplate := x509.RevocationList{
		SignatureAlgorithm:  caCert.SignatureAlgorithm,
		RevokedCertificates: certificateList,
		Number:              newSerialNumber(),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().AddDate(0, 0, 1),
	}

	crlByte, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, privKey)
	if err != nil {
		return nil, err
	}

	fileData := storage.File{
		CA:           CACommonName,
		CommonName:   CACommonName,
		FileType:     storage.FileTypeCRL,
		CRLData:      crlByte,
		CreationType: storage.CreationTypeCA,
	}

	err = storage.SaveFile(fileData)

	if err != nil {
		return nil, err
	}

	return crlByte, err
}
