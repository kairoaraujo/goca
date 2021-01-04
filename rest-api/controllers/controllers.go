package controllers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kairoaraujo/goca"
	"github.com/kairoaraujo/goca/rest-api/models"
)

type NewCAJSON struct {
	CommonName string
	Identity   goca.Identity
}

func getCAData(ca goca.CA) models.CAJSON {
	var caData models.CAJSON

	caType := ca.IsIntermediate()

	caData.CommonName = ca.CommonName
	caData.Intermediate = caType
	caData.Status = ca.Status()
	caData.DNSNames = ca.GoCertificate().DNSNames

	certificate := ca.GoCertificate()
	csr := ca.GoCSR()

	caData.Certificates = ca.ListCertificates()

	if csr != nil {
		caData.CSR = true
	}

	if certificate != nil {
		crl := ca.GoCRL()
		caData.SerialNumber = certificate.SerialNumber.String()
		if crl != nil {
			var revokedCertificates []string
			for _, serialNumber := range crl.TBSCertList.RevokedCertificates {
				revokedCertificates = append(revokedCertificates, serialNumber.SerialNumber.String())
			}
			caData.CertificateRevocationList = revokedCertificates
		}
	}

	caData.Files = ca.Data

	return caData
}

// GetCA is the handler of Certificate Authorities endpoint
// @Summary List Certificate Authorities (CA)
// @Description list all the Certificate Authorities
// @Tags CA
// @Produce json
// @Success 200
// @Router /api/v1/ca [get]
func GetCA(c *gin.Context) {
	var caList []string
	caList = goca.List()

	c.JSON(http.StatusOK, gin.H{"data": caList, "error": nil})
}

func NewCA(c *gin.Context) {

	var json NewCAJSON
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"data": nil, "error": err.Error()})
		return
	}
	c.BindJSON(&json)

	caCommonName := json.CommonName
	caIdentity := goca.Identity{
		Organization:       json.Identity.Organization,
		OrganizationalUnit: json.Identity.OrganizationalUnit,
		Country:            json.Identity.Country,
		Locality:           json.Identity.Locality,
		Province:           json.Identity.Province,
		DNSNames:           json.Identity.DNSNames,
		Intermediate:       json.Identity.Intermediate,
		KeyBitSize:         json.Identity.KeyBitSize,
		Valid:              json.Identity.Valid,
	}
	ca, err := goca.New(caCommonName, caIdentity)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"data": nil, "error": err.Error()})
		return
	}

	var caData models.CAJSON

	caData = getCAData(ca)

	c.JSON(http.StatusOK, gin.H{"Data": caData})
	return

}

// GetCACommonName is the handler of Certificate Authorities endpoint
// @Summary List Certificate Authorities (CA) based in Common Name
// @Description list the Certificate Authorities data
// @Tags CA
// @Produce json
// @Success 200 {object} models.CAData
// @Router /api/v1/ca/{cn} [get]
func GetCACommonName(c *gin.Context) {

	var caData models.CAJSON

	ca, err := goca.Load(c.Param("cn"))

	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusNotFound, gin.H{"data": nil, "error": err.Error()})
		return
	}

	caData = getCAData(ca)

	c.JSON(http.StatusOK, gin.H{"data": caData, "error": nil})
}

func GetCertificates(c *gin.Context) {

	ca, err := goca.Load(c.Param("cn"))
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusNotFound, gin.H{"data": nil, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": ca.ListCertificates(), "error": nil})
}

func GetCertificatesCommonName(c *gin.Context) {

	var caData models.CertificateJSON

	ca, err := goca.Load(c.Param("cn"))
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusNotFound, gin.H{"data": nil, "error": err.Error()})
		return
	}

	certificate, err := ca.LoadCertificate(c.Param("cert_cn"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"data": nil, "error": err.Error()})
		return
	}

	cert := certificate.GoCert()

	caData.CommonName = cert.Subject.CommonName
	caData.DNSNames = cert.DNSNames
	caData.SerialNumber = cert.SerialNumber.String()
	caData.Files = certificate

	c.JSON(http.StatusOK, gin.H{"data": caData, "error": nil})

}
