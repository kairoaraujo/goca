package goca

import (
	"fmt"
	"os"
	"testing"
)

const CaTestFolder string = "./DoNotUseThisCAPATHTestOnly"

func tearDown() {
	os.Unsetenv("GOCATEST")
	os.RemoveAll(CaTestFolder)
}

// TestFunctionalRootCACreation creates a RootCA
func TestFunctionalRootCACreation(t *testing.T) {
	tearDown()
	os.Setenv("CAPATH", CaTestFolder)
	os.Setenv("GOCATEST", "true")

	rootCAIdentity := Identity{
		Organization:       "GO CA Root Company Inc.",
		OrganizationalUnit: "Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		Intermediate:       false,
		DNSNames:           []string{"www.go-root.ca", "secure.go-root.ca"},
	}

	RootCompanyCA, err := New("go-root.ca", rootCAIdentity)
	if err != nil {
		t.Errorf("Failing to create the CA")
	}
	if RootCompanyCA.IsIntermediate() != false {
		t.Errorf("Intermediate is true instead false")
	}

	if RootCompanyCA.Status() != "Certificate Authority is ready." {
		t.Errorf(RootCompanyCA.Status())
	}

	t.Log("Tested Creating a Root CA")

}

// Creates a Intermediate CA
func TestFunctionalIntermediateCACration(t *testing.T) {
	os.Setenv("CAPATH", CaTestFolder)

	intermediateCAIdentity := Identity{
		Organization:       "Intermediate CA Company Inc.",
		OrganizationalUnit: "Intermediate Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		Intermediate:       true,
	}

	IntermediateCA, err := New("go-itermediate.ca", intermediateCAIdentity)
	if err != nil {
		t.Log(err)
		t.Errorf("Failing to create the CA")
	}

	if IntermediateCA.IsIntermediate() != true {
		t.Errorf("Intermediate is false instead true")
	}

	if IntermediateCA.Status() != "Intermediate Certificate Authority not ready, missing Certificate." {
		t.Errorf(IntermediateCA.Status())
	}

	t.Log("Tested Creating a Intermediate CA")

}

func TestFunctionalListCAs(t *testing.T) {
	if len(List()) == 0 {
		t.Error("Empty list of CAs")
	}
	t.Log(List())
}

// RootCA signs the Intermediate CA
func TestFunctionalRootCASignsIntermediateCA(t *testing.T) {

	t.Log("Tested load Root CA")
	RootCA, err := Load("go-root.ca")
	if err != nil {
		t.Log(err)
		t.Errorf("Failed to load Root CA")
	}

	if RootCA.GetCRL() == "" {
		t.Error("Empty CRL")
	}

	t.Log(RootCA.GoCertificate().DNSNames)

	if RootCA.IsIntermediate() {
		t.Errorf("Failed to load as Root CA")
	}

	t.Log("Tested load Intermediate CA")
	IntermediateCA, err := Load("go-itermediate.ca")

	if err != nil {
		t.Log(err)
		t.Errorf("Failed to load Intermediate CA")
	}

	if !IntermediateCA.IsIntermediate() {
		t.Errorf("CA should be Intermediate")
	}

	IntermediateCACert, err := RootCA.SignCSR(*IntermediateCA.GoCSR(), 1000)
	if err != nil {
		t.Log("Tested the with 1000 days valid")
		t.Log(IntermediateCACert.Certificate)
	}

	IntermediateCACert, err = RootCA.SignCSR(*IntermediateCA.GoCSR(), 365)
	if err != nil {
		t.Log(err)
		t.Errorf("Failed to sign Intermediate CSR")
	}
	t.Log("Tested Sign CSR with correct valid days (365)")

	fmt.Println(RootCA.ListCertificates())
}

func TestFunctionalRootCAIssueNewCertificate(t *testing.T) {
	intranteIdentity := Identity{
		Organization:       "SFTP Server CA Company Inc.",
		OrganizationalUnit: "Intermediate Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		Intermediate:       true,
		DNSNames:           []string{"w3.intranet.go-root.ca"},
	}

	RootCA, err := Load("go-root.ca")
	if err != nil {
		t.Log(err)
		t.Errorf("Failed to load Root CA")
	}

	intranetCert, err := RootCA.IssueCertificate("intranet.go-root.ca", intranteIdentity)
	if err != nil {
		t.Log(err)
		t.Errorf("Failed to Root CA issue new certificate (intranet.go-root.ca)")
	}

	fmt.Println(RootCA.ListCertificates())

	if RootCA.GetCertificate() != intranetCert.GetCACertificate() {
		t.Log(RootCA.GetCertificate())
		t.Log(intranetCert.GetCACertificate())
		t.Error("The CA Certificate is not the same as the Certificate CA Certificate")
	}

}

func TestFunctionalRootCALoadCertificates(t *testing.T) {

	RootCA, err := Load("go-root.ca")
	if err != nil {
		t.Log(err)
		t.Errorf("Failed to load Root CA")
	}

	intranetCert, err := RootCA.LoadCertificate("intranet.go-root.ca")
	if err != nil {
		fmt.Println(err)
		t.Log(err)
	}

	if intranetCert.GetCACertificate() != "" {
		t.Log("Failed to load intranet")
	}
	intermediateCert, _ := RootCA.LoadCertificate("go-itermediate.ca")

	if RootCA.GetCertificate() != intermediateCert.GetCACertificate() {
		t.Log(RootCA.GetCertificate())
		t.Log(intermediateCert.GetCACertificate())
		t.Error("The CA Certificate is not the same as the Certificate CA Certificate")
	}

}

func TestFunctionalRevokeCertificate(t *testing.T) {
	RootCA, _ := Load("go-root.ca")
	intermediateCert, _ := RootCA.LoadCertificate("go-itermediate.ca")

	if RootCA.Data.crl == nil {
		t.Error("CRL is nil")
	}

	err := RootCA.RevokeCertificate("go-itermediate.ca")
	if err != nil {
		t.Error("Failed to revoke certificate")
	}
	t.Log(intermediateCert.certificate.SerialNumber)
	t.Log(RootCA.Data.crl.TBSCertList.RevokedCertificates[0].SerialNumber)
	result := intermediateCert.certificate.SerialNumber.Cmp(RootCA.Data.crl.TBSCertList.RevokedCertificates[0].SerialNumber)
	if result != 0 {
		t.Error("Certificate Serial Number is not in the CRL")
	}

	t.Log("Negative check")
	intranetCert, _ := RootCA.LoadCertificate("intranet.go-root.ca")
	t.Log(intranetCert.certificate.SerialNumber)
	t.Log(RootCA.Data.crl.TBSCertList.RevokedCertificates[0].SerialNumber)
	result = intranetCert.certificate.SerialNumber.Cmp(RootCA.Data.crl.TBSCertList.RevokedCertificates[0].SerialNumber)
	if result == 0 {
		t.Error("Non revoked certificate in list")
	}
	err = RootCA.RevokeCertificate("intranet.go-root.ca")
	if err != nil {
		t.Error("Failed to revoke.")
	}
	t.Log(RootCA.Data.crl.TBSCertList.RevokedCertificates)
	if len(RootCA.Data.crl.TBSCertList.RevokedCertificates) != 2 {
		t.Error("Not appending certificates to revoke list")
	}
	t.Logf("Test appending revoked certificates")

	if RootCA.GetCRL() == "" {
		t.Error("CRL X509 file is empty!")
	}
}
