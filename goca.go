// Package goca provides Certificate Authority (CA) framework managing
//
// GoCA is an API Framework that uses mainly crypto/x509 to manage
// Certificate Authorities.
//
// Using GoCA makes easy to create a CA and issue certificates, signing
// Certificates Signing Request (CSR) and revoke certificate generating
// Certificates Request List (CRL).
//
// All files are stored in the “$CAPATH“. The “$CAPATH“ is an environment
// variable the defines were all files (keys, certificates, etc) will be stored.
// It is importante to have this folder in a safety place.
//
// GoCA also make easier manipulate files such as Private and Public Keys,
// Certificate Signing Request, Certificate Request Lists and Certificates
// for other Go applications.
package goca

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"

	storage "github.com/kairoaraujo/goca/_storage"
)

// CA represents the basic CA data
type CA struct {
	CommonName string // Certificate Authority Common Name
	Data       CAData // Certificate Authority Data (CAData{})
}

// Certificate represents a Certificate data
type Certificate struct {
	commonName    string                  // Certificate Common Name
	Certificate   string                  `json:"certificate" example:"-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\n"`         // Certificate certificate string
	CSR           string                  `json:"csr" example:"-----BEGIN CERTIFICATE REQUEST-----...-----END CERTIFICATE REQUEST-----\n"` // Certificate Signing Request string
	PrivateKey    string                  `json:"private_key" example:"-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----\n"`         // Certificate Private Key string
	PublicKey     string                  `json:"public_key" example:"-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----\n"`            // Certificate Public Key string
	CACertificate string                  `json:"ca_certificate" example:"-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\n"`      // CA Certificate as string
	privateKey    rsa.PrivateKey          // Certificate Private Key object rsa.PrivateKey
	publicKey     rsa.PublicKey           // Certificate Private Key object rsa.PublicKey
	csr           x509.CertificateRequest // Certificate Sigining Request object x509.CertificateRequest
	certificate   *x509.Certificate       // Certificate certificate *x509.Certificate
	caCertificate *x509.Certificate       // CA Certificate *x509.Certificate
}

//
// Certificate Authority
//

// Load an existent Certificate Authority from $CAPATH
func Load(commonName string) (ca CA, err error) {
	ca = CA{
		CommonName: commonName,
	}

	err = ca.loadCA(commonName)
	if err != nil {
		return CA{}, err
	}

	return ca, nil

}

// List list all existent Certificate Authorities in $CAPATH
func List() []string {
	return storage.ListCAs()
}

// New creat new Certificate Authority
func New(commonName string, identity Identity) (ca CA, err error) {
	ca, err = NewCA(commonName, "", identity)
	return ca, err
}

// New create a new Certificate Authority
func NewCA(commonName, parentCommonName string, identity Identity) (ca CA, err error) {
	ca = CA{
		CommonName: commonName,
	}

	err = ca.create(commonName, parentCommonName, identity)
	if err != nil {
		return ca, err
	}

	return ca, nil
}

// GetPublicKey returns the PublicKey as string
func (c *CA) GetPublicKey() string {
	return c.Data.PublicKey
}

// GetPrivateKey returns the Private Key as string
func (c *CA) GetPrivateKey() string {
	return c.Data.PrivateKey
}

// GoPrivateKey returns the Private Key as Go bytes rsa.PrivateKey
func (c *CA) GoPrivateKey() rsa.PrivateKey {
	return c.Data.privateKey
}

// GoPublicKey returns the Public Key as Go bytes rsa.PublicKey
func (c *CA) GoPublicKey() rsa.PublicKey {
	return c.Data.publicKey
}

// GetCSR returns the Certificate Signing Request as string
func (c *CA) GetCSR() string {
	return c.Data.CSR
}

// GoCSR return the Certificate Signing Request as Go bytes *x509.CertificateRequest
func (c *CA) GoCSR() *x509.CertificateRequest {
	return c.Data.csr
}

// GetCertificate returns Certificate Authority Certificate as string
func (c *CA) GetCertificate() string {
	return c.Data.Certificate
}

// GoCertificate returns Certificate Authority Certificate as Go bytes *x509.Certificate
func (c *CA) GoCertificate() *x509.Certificate {
	return c.Data.certificate
}

// GetCRL returns Certificate Revocation List as x509 CRL string
func (c *CA) GetCRL() string {
	return c.Data.CRL
}

// GoCRL returns Certificate Revocation List as Go bytes *pkix.CertificateList
func (c *CA) GoCRL() *pkix.CertificateList {
	return c.Data.crl
}

// IsIntermediate returns if the CA is Intermediate CA (true)
func (c *CA) IsIntermediate() bool {
	return c.Data.IsIntermediate

}

// ListCertificates returns all certificates in the CA
func (c *CA) ListCertificates() []string {
	return storage.ListCertificates(c.CommonName)
}

// Status get details about Certificate Authority status.
func (c *CA) Status() string {
	if c.Data.CSR != "" && c.Data.Certificate == "" {
		return "Intermediate Certificate Authority not ready, missing Certificate."

	} else if c.Data.CSR != "" && c.Data.Certificate != "" {
		return "Intermediate Certificate Authority is ready."

	} else if c.Data.CSR == "" && c.Data.Certificate != "" {
		return "Certificate Authority is ready."

	} else {
		return "CA is inconsistent."
	}
}

// SignCSR perform a creation of certificate from a CSR (x509.CertificateRequest) and returns *x509.Certificate
func (c *CA) SignCSR(csr x509.CertificateRequest, valid int) (certificate Certificate, err error) {

	certificate, err = c.signCSR(csr, valid)

	return certificate, err

}

// IssueCertificate creates a new certificate
//
// It is import create an Identity{} with Certificate Client/Server information.
func (c *CA) IssueCertificate(commonName string, id Identity) (certificate Certificate, err error) {

	certificate, err = c.issueCertificate(commonName, id)

	return certificate, err
}

// LoadCertificate loads a certificate managed by the Certificate Authority
//
// The method ListCertificates can be used to list all available certificates.
func (c *CA) LoadCertificate(commonName string) (certificate Certificate, err error) {
	certificate, err = c.loadCertificate(commonName)

	return certificate, err
}

// RevokeCertificate revokes a certificate managed by the Certificate Authority
//
// The method ListCertificates can be used to list all available certificates.
func (c *CA) RevokeCertificate(commonName string) error {

	certToRevoke, err := c.loadCertificate(commonName)
	if err != nil {
		return err
	}

	err = c.revokeCertificate(certToRevoke.certificate)
	if err != nil {
		return err
	}

	return nil
}

//
// Certificates
//

// GetCertificate returns the certificate as string.
func (c *Certificate) GetCertificate() string {
	return c.Certificate
}

// GoCert returns the certificate as Go x509.Certificate.
func (c *Certificate) GoCert() x509.Certificate {
	return *c.certificate
}

// GetCSR returns the certificate as string.
func (c *Certificate) GetCSR() string {
	return c.CSR
}

// GoCSR returns the certificate as Go x509.Certificate.
func (c *Certificate) GoCSR() x509.CertificateRequest {
	return c.csr
}

// GetCACertificate returns the certificate as string.
func (c *Certificate) GetCACertificate() string {
	return c.CACertificate
}

// GoCACertificate returns the certificate *x509.Certificate.
func (c *Certificate) GoCACertificate() x509.Certificate {
	return *c.caCertificate
}
