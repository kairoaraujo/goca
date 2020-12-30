package goca

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	storage "github.com/kairoaraujo/goca/_storage"
	"github.com/kairoaraujo/goca/cert"
	"github.com/kairoaraujo/goca/key"
)

// Const
const (
	certExtension string = ".crt"
	csrExtension  string = ".csr"
	crlExtension  string = ".crl"
)

// A Identity represents the Certificate Authority Identity Information
type Identity struct {
	Organization       string   // Organization name
	OrganizationalUnit string   // Organizational Unit name
	Country            string   // Country (two letters)
	Locality           string   // Locality name
	Province           string   // Province name
	EmailAddresses     string   // Email Address
	DNSNames           []string // DNS Names list
	Intermediate       bool     // Intermendiate Certificate Authority (default is false)
	KeyBitSize         int      // Key Bit Size (defaul: 2048)
	Valid              int      // Minimum 1 day, maximum 825 days -- Default: 397
}

// A CAData represents all the Certificate Authority Data as
// RSA Keys, CRS, CRL, Certificates etc
type CAData struct {
	PrivateKey  string
	PublicKey   string
	CSR         string
	Certificate string
	CRL         string
	privateKey  rsa.PrivateKey
	certificate *x509.Certificate
	publicKey   rsa.PublicKey
	csr         *x509.CertificateRequest
	crl         *pkix.CertificateList
}

// ErrCAMissingInfo means that all information goca.Information{} is required
var ErrCAMissingInfo = errors.New("all CA details ('Organization', 'Organizational Unit', 'Country', 'Locality', 'Province') are required")

// ErrCAGenerateExists means that the CA with the same Common Name exists in
// the $CAPATH.
var ErrCAGenerateExists = errors.New("a Certificate Authority with this common name already exists")

// ErrCALoadNotFound means that CA was not found in $CAPATH to be loaded.
var ErrCALoadNotFound = errors.New("the requested Certificate Authority does not exist")

func (c *CA) create(commonName string, id Identity) error {

	caData := CAData{}

	// verifies if the CA, based in the 'common name', exists
	caStorage := storage.CAStorage(commonName)
	if caStorage {
		return ErrCAGenerateExists
	}

	var (
		caDir           string = "/" + commonName + "/ca"
		caCertsDir      string = "/" + commonName + "/certs"
		keyString       []byte
		publicKeyString []byte
		csrString       []byte
		certString      []byte
		crlString       []byte
	)

	if id.Organization == "" || id.OrganizationalUnit == "" || id.Country == "" || id.Locality == "" || id.Province == "" {
		return ErrCAMissingInfo
	}

	if err := storage.MakeFolder(os.Getenv("CAPATH") + caDir); err != nil {
		return err
	}

	if err := storage.MakeFolder(os.Getenv("CAPATH") + caCertsDir); err != nil {
		return err
	}

	caKeys, err := key.CreateKeys(commonName, commonName, storage.CreationTypeCA, id.KeyBitSize)
	if err != nil {
		return err
	}

	if keyString, err = storage.LoadFile(caDir + "/key.pem"); err != nil {
		keyString = []byte{}
	}

	if publicKeyString, err = storage.LoadFile(caCertsDir + "/key.pub"); err != nil {
		publicKeyString = []byte{}
	}

	privKey := &caKeys.Key
	pubKey := &caKeys.PublicKey

	caData.privateKey = caKeys.Key
	caData.PrivateKey = string(keyString)
	caData.publicKey = caKeys.PublicKey
	caData.PublicKey = string(publicKeyString)

	if !id.Intermediate {
		certBytes, err := cert.CreateRootCert(commonName, commonName, id.Country, id.Province, id.Locality, id.Organization, id.OrganizationalUnit, id.EmailAddresses, id.Valid, id.DNSNames, privKey, pubKey, storage.CreationTypeCA)
		if err != nil {
			return err
		}
		certificate, _ := x509.ParseCertificate(certBytes)

		if certString, err = storage.LoadFile(caDir + "/" + commonName + certExtension); err != nil {
			certString = []byte{}
		}

		caData.certificate = certificate
		caData.Certificate = string(certString)

		crlBytes, err := cert.RevokeCertificate(c.CommonName, []pkix.RevokedCertificate{}, certificate, privKey)
		if err != nil {
			crl, err := x509.ParseCRL(crlBytes)
			if err != nil {
				caData.crl = crl
			}
		}

		if crlString, err = storage.LoadFile(caDir + "/" + commonName + crlExtension); err != nil {
			crlString = []byte{}
		}

		c.Data.CRL = string(crlString)

	} else {
		csrBytes, err := cert.CreateCSR(commonName, commonName, id.Country, id.Province, id.Locality, id.Organization, id.OrganizationalUnit, id.EmailAddresses, id.DNSNames, privKey, storage.CreationTypeCA)
		if err != nil {
			return err
		}
		csr, _ := x509.ParseCertificateRequest(csrBytes)
		if csrString, err = storage.LoadFile(caDir + "/" + commonName + csrExtension); err != nil {
			csrString = []byte{}
		}

		caData.csr = csr
		caData.CSR = string(csrString)
	}

	c.Data = caData

	return nil

}

func (c *CA) loadCA(commonName string) error {

	caData := CAData{}

	var (
		caDir           string = "/" + commonName + "/ca"
		keyString       []byte
		publicKeyString []byte
		csrString       []byte
		certString      []byte
		crlString       []byte
		loadErr         error
	)

	// verifies if the CA, based in the 'common name', exists
	caStorage := storage.CAStorage(commonName)
	if !caStorage {
		return ErrCALoadNotFound
	}

	if keyString, loadErr = storage.LoadFile(caDir + "/key.pem"); loadErr == nil {
		privateKey, err := key.LoadPrivateKey(keyString)
		if err != nil {
			return err
		}
		caData.PrivateKey = string(keyString)
		caData.privateKey = *privateKey
	} else {
		return loadErr
	}

	if publicKeyString, loadErr = storage.LoadFile(caDir + "/key.pub"); loadErr == nil {
		publicKey, err := key.LoadPublicKey(publicKeyString)
		if err != nil {
			return err
		}
		caData.PublicKey = string(publicKeyString)
		caData.publicKey = *publicKey
	} else {
		return loadErr
	}

	if csrString, loadErr = storage.LoadFile(caDir + "/" + commonName + csrExtension); loadErr == nil {
		csr, err := cert.LoadCSR(csrString)
		if err != nil {
			return err
		}
		caData.CSR = string(csrString)
		caData.csr = csr
	}

	if certString, loadErr = storage.LoadFile(caDir + "/" + commonName + certExtension); loadErr == nil {
		cert, err := cert.LoadCert(certString)
		if err != nil {
			return err
		}
		caData.Certificate = string(certString)
		caData.certificate = cert
	}

	var crlFile string = caDir + "/" + c.CommonName + crlExtension
	if crlString, loadErr = storage.LoadFile(crlFile); loadErr == nil {
		crl, err := cert.LoadCRL(crlString)
		if err != nil {
			return err
		}
		caData.CRL = string(crlString)
		caData.crl = crl
	}

	c.Data = caData

	return nil
}

func (c *CA) signCSR(csr x509.CertificateRequest, valid int) (certificate Certificate, err error) {

	certificate = Certificate{
		CommonName:    csr.Subject.CommonName,
		csr:           csr,
		caCertificate: c.Data.certificate,
		CACertificate: c.Data.Certificate,
	}

	csrFile := "/" + c.CommonName + "/cert/" + certificate.CommonName + csrExtension
	if csrString, err := storage.LoadFile(csrFile); err == nil {
		_, err := cert.LoadCSR(csrString)
		if err != nil {
			return certificate, err
		}
		certificate.CSR = string(csrString)
	}

	certBytes, err := cert.CASignCSR(c.CommonName, csr, c.Data.certificate, &c.Data.privateKey, valid, storage.CreationTypeCertificate)
	if err != nil {
		return certificate, err
	}

	var certRow bytes.Buffer
	var pemCert = &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	_ = pem.Encode(&certRow, pemCert)

	certificate.Certificate = string(certRow.String())

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return certificate, err
	}

	certificate.certificate = cert

	return certificate, err

}

func (c *CA) issueCertificate(commonName string, id Identity) (certificate Certificate, err error) {

	var (
		caCertsDir      string = "/" + c.CommonName + "/certs/"
		keyString       []byte
		publicKeyString []byte
		csrString       []byte
	)

	certificate.CACertificate = c.Data.Certificate
	certificate.caCertificate = c.Data.certificate

	certKeys, err := key.CreateKeys(c.CommonName, commonName, storage.CreationTypeCertificate, id.KeyBitSize)
	if err != nil {
		return certificate, err
	}

	if keyString, err = storage.LoadFile(caCertsDir + commonName + "/key.pem"); err != nil {
		keyString = []byte{}
	}

	if publicKeyString, err = storage.LoadFile(caCertsDir + commonName + "/key.pub"); err != nil {
		publicKeyString = []byte{}
	}

	privKey := &certKeys.Key
	pubKey := &certKeys.PublicKey

	certificate.privateKey = *privKey
	certificate.PrivateKey = string(keyString)
	certificate.publicKey = *pubKey
	certificate.PublicKey = string(publicKeyString)

	csrBytes, err := cert.CreateCSR(c.CommonName, commonName, id.Country, id.Province, id.Locality, id.Organization, id.OrganizationalUnit, id.EmailAddresses, id.DNSNames, privKey, storage.CreationTypeCertificate)
	if err != nil {
		return certificate, err
	}

	csr, _ := x509.ParseCertificateRequest(csrBytes)
	if csrString, err = storage.LoadFile(caCertsDir + commonName + "/" + commonName + csrExtension); err != nil {
		csrString = []byte{}
	}

	certificate.csr = *csr
	certificate.CSR = string(csrString)
	fmt.Println(csr.Subject.CommonName)
	certBytes, err := cert.CASignCSR(c.CommonName, *csr, c.Data.certificate, &c.Data.privateKey, id.Valid, storage.CreationTypeCertificate)
	if err != nil {
		return certificate, err
	}

	var certRow bytes.Buffer
	var pemCert = &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	_ = pem.Encode(&certRow, pemCert)

	certificate.Certificate = string(certRow.String())

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return certificate, err
	}

	certificate.certificate = cert

	return certificate, nil

}

func (c *CA) loadCertificate(commonName string) (certificate Certificate, err error) {

	var (
		caCertsDir      string = "/" + c.CommonName + "/certs/" + commonName + "/"
		keyString       []byte
		publicKeyString []byte
		csrString       []byte
		certString      []byte
		loadErr         error
	)

	certificate.CACertificate = c.Data.Certificate
	certificate.caCertificate = c.Data.certificate

	if keyString, loadErr = storage.LoadFile(caCertsDir + "private.pem"); loadErr == nil {
		privateKey, _ := key.LoadPrivateKey(keyString)
		certificate.PrivateKey = string(keyString)
		certificate.privateKey = *privateKey
	}

	if publicKeyString, loadErr = storage.LoadFile(caCertsDir + "/public.pem"); loadErr == nil {
		publicKey, _ := key.LoadPublicKey(publicKeyString)
		certificate.PublicKey = string(publicKeyString)
		certificate.publicKey = *publicKey
	}

	if csrString, loadErr = storage.LoadFile(caCertsDir + "/" + commonName + csrExtension); loadErr == nil {
		csr, _ := cert.LoadCSR(csrString)
		certificate.CSR = string(csrString)
		certificate.csr = *csr
	}

	if certString, loadErr = storage.LoadFile(caCertsDir + "/" + commonName + certExtension); loadErr == nil {
		cert, err := cert.LoadCert(certString)
		if err != nil {
			return certificate, err
		}
		certificate.Certificate = string(certString)
		certificate.certificate = cert
	}

	return certificate, nil
}

func (c *CA) revokeCertificate(certificate *x509.Certificate) error {

	var revokedCerts []pkix.RevokedCertificate
	var caDir string = "/" + c.CommonName + "/ca"
	var crlString []byte

	if c.Data.crl != nil {
		revokedCerts = c.Data.crl.TBSCertList.RevokedCertificates
	}

	newCertRevoke := pkix.RevokedCertificate{
		SerialNumber:   certificate.SerialNumber,
		RevocationTime: time.Now(),
	}

	revokedCerts = append(revokedCerts, newCertRevoke)

	crlByte, err := cert.RevokeCertificate(c.CommonName, revokedCerts, c.Data.certificate, &c.Data.privateKey)
	if err != nil {
		return err
	}

	crl, err := x509.ParseCRL(crlByte)
	if err != nil {
		return err
	}
	c.Data.crl = crl

	var crlFile string = caDir + "/" + c.CommonName + crlExtension
	if crlString, err = storage.LoadFile(crlFile); err != nil {
		crlString = []byte{}
	}

	c.Data.CRL = string(crlString)

	return nil
}
