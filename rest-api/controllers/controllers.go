package controllers

import (
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/kairoaraujo/goca"
	storage "github.com/kairoaraujo/goca/_storage"
	"github.com/kairoaraujo/goca/cert"
	"github.com/kairoaraujo/goca/rest-api/models"
)

func getCAData(ca goca.CA) (body models.CABody) {

	caType := ca.IsIntermediate()

	body.CommonName = ca.CommonName
	body.Intermediate = caType
	body.Status = ca.Status()

	certificate := ca.GoCertificate()
	csr := ca.GoCSR()

	body.Certificates = ca.ListCertificates()

	if csr != nil {
		body.CSR = true
	}

	if certificate != nil {
		body.DNSNames = certificate.DNSNames
		body.IssueDate = certificate.NotBefore.String()
		body.ExpireDate = certificate.NotAfter.String()
		crl := ca.GoCRL()
		body.SerialNumber = certificate.SerialNumber.String()
		if crl != nil {
			var revokedCertificates []string
			for _, serialNumber := range crl.TBSCertList.RevokedCertificates {
				revokedCertificates = append(revokedCertificates, serialNumber.SerialNumber.String())
			}
			body.CertificateRevocationList = revokedCertificates
		}
	}

	body.Files = ca.Data

	return body
}

func getCertificateData(certificate goca.Certificate) (body models.CertificateBody) {

	cert := certificate.GoCert()

	body.CommonName = cert.Subject.CommonName
	body.DNSNames = cert.DNSNames
	body.SerialNumber = cert.SerialNumber.String()
	body.IssueDate = cert.NotBefore.String()
	body.ExpireDate = cert.NotAfter.String()
	body.Files = certificate

	return body

}

func payloadInit(json models.Payload) (commonName string, identity goca.Identity) {

	commonName = json.CommonName
	identity = goca.Identity{
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

	return commonName, identity
}

// GetCA is the handler of Certificate Authorities endpoint
// @Summary List Certificate Authorities (CA)
// @Description list all the Certificate Authorities
// @Tags CA
// @Produce json
// @Success 200 {object} models.ResponseList
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca [get]
func GetCA(c *gin.Context) {
	var caList []string = goca.List()
	c.JSON(http.StatusOK, gin.H{"data": caList})
}

// AddCA is the handler of Certificate Authorities endpoint
// @Summary Create new Certificate Authorities (CA) or Intermediate Certificate Authorities (ICA)
// @Description create a new Certificate Authority Root or Intermediate
// @Tags CA
// @Accept json
// @Produce json
// @Param json_payload body models.Payload true "Add new Certificate Authority or Intermediate Certificate Authority"
// @Success 200 {object} models.ResponseCA
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca [post]
func AddCA(c *gin.Context) {

	var json models.Payload
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	commonName, identity := payloadInit(json)

	ca, err := goca.New(commonName, identity)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var caData models.CABody = getCAData(ca)

	c.JSON(http.StatusOK, gin.H{"Data": caData})

}

// GetCACommonName is the handler of Certificate Authorities endpoint
// @Summary Certificate Authorities (CA) Information based in Common Name
// @Description list the Certificate Authorities data
// @Tags CA
// @Produce json
// @Success 200 {object} models.ResponseCA
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca/{cn} [get]
func GetCACommonName(c *gin.Context) {

	var body models.CABody

	ca, err := goca.Load(c.Param("cn"))
	if err != nil {
		if err == goca.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}

	body = getCAData(ca)

	c.JSON(http.StatusOK, gin.H{"data": body})
}

// UploadCertificateICA is the handler of Intermediate Certificate Authorities endpoint
// @Summary Upload a Certificate to an Intermediate CA
// @Description Upload a Certificate to a ICA pending certificate
// @Tags CA
// @Produce json
// @Param file formData file true "Attached signed Certificate file"
// @Success 200 {object} models.ResponseCA
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca/{cn}/upload [post]
func UploadCertificateICA(c *gin.Context) {

	var body models.CABody
	caCN := c.Param("cn")
	ca, err := goca.Load(caCN)
	if err != nil {
		if err == goca.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}

	if ca.Status() != "Intermediate Certificate Authority not ready, missing Certificate." {
		c.JSON(http.StatusBadRequest, gin.H{"error": "The Intermediate Certificate Authority is not pending certificate"})
		return
	}

	certUploaded, _ := c.FormFile("file")
	fileName := uuid.New().String()
	fileNameFull := os.Getenv("CAPATH") + "/" + fileName
	if err := c.SaveUploadedFile(certUploaded, fileNameFull); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	certFile, err := storage.LoadFile(fileName)
	if err != nil {
		os.Remove(fileNameFull)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	fileData := storage.File{
		CA:           caCN,
		CommonName:   caCN,
		FileType:     storage.FileTypeCertificate,
		CertData:     certFile,
		CreationType: storage.CreationTypeCA,
	}
	err = storage.SaveFile(fileData)
	if err != nil {
		os.Remove(fileNameFull)
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	}

	ca, err = goca.Load(caCN)
	if err != nil {
		os.Remove(fileNameFull)
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	os.Remove(fileNameFull)

	// Generate the initial CRL
	privKey := ca.GoPrivateKey()
	_, err = cert.RevokeCertificate(ca.CommonName, []pkix.RevokedCertificate{}, ca.GoCertificate(), &privKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	body = getCAData(ca)

	c.JSON(http.StatusOK, gin.H{"data": body})
}

// SignCSR is the handler of Certificate Authorities endpoint
// @Summary Certificate Authorities (CA) Signer for Certificate Sigining Request (CSR)
// @Description create a new certificate signing a Certificate Sigining Request (CSR)
// @Tags CA
// @Accept json
// @Produce json
// @Param file formData file true "Attached CSR file"
// @Param valid query int false "Number certificate valid days"
// @Success 200 {object} models.ResponseCertificates
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca/{cn}/sign [post]
func SignCSR(c *gin.Context) {

	var body models.CertificateBody
	var valid int = 0

	csrUploaded, _ := c.FormFile("file")

	if c.Query("valid") != "" {
		valid, err := strconv.Atoi(c.Query("valid"))
		if err != nil {
			fmt.Println(valid)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

	}

	fileName := uuid.New().String()
	fileNameFull := os.Getenv("CAPATH") + "/" + fileName
	if err := c.SaveUploadedFile(csrUploaded, fileNameFull); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	csrFile, err := storage.LoadFile(fileName)
	if err != nil {
		os.Remove(fileNameFull)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	csr, err := cert.LoadCSR(csrFile)
	if err != nil {
		os.Remove(fileNameFull)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ca, err := goca.Load(c.Param("cn"))
	if err != nil {
		if err == goca.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}
	certificate, err := ca.SignCSR(*csr, valid)
	if err != nil {
		os.Remove(fileNameFull)
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	}
	os.Remove(fileNameFull)

	body = getCertificateData(certificate)

	c.JSON(http.StatusOK, gin.H{"data": body})
}

// GetCertificates is the handler of Certificates by Authorities Certificates endpoint
// @Summary List all Certificates managed by a certain Certificate Authority
// @Description list all certificates managed by a certain Certificate Authority (cn)
// @Tags CA/{CN}/Certificates
// @Produce json
// @Success 200 {object} models.ResponseCA
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca/{cn}/certificates [get]
func GetCertificates(c *gin.Context) {

	ca, err := goca.Load(c.Param("cn"))
	if err != nil {
		if err == goca.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}

	c.JSON(http.StatusOK, gin.H{"data": ca.ListCertificates()})
}

// AddCertificates is the handler of Certificates by Authorities Certificates endpoint
// @Summary CA issue new certificate
// @Description the Certificate Authority issues a new Certificate
// @Tags CA/{CN}/Certificates
// @Produce json
// @Accept json
// @Param ca body models.Payload true "Add new Certificate Authority or Intermediate Certificate Authority"
// @Success 200 {object} models.ResponseCertificates
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca/{cn}/certificates [post]
func IssueCertificates(c *gin.Context) {

	ca, err := goca.Load(c.Param("cn"))
	if err != nil {
		if err == goca.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}

	if !strings.Contains(ca.Status(), "is ready") {
		c.JSON(http.StatusBadRequest, gin.H{"error": ca.Status()})
		return
	}

	var json models.Payload

	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_ = c.BindJSON(&json)

	commonName, identity := payloadInit(json)

	certificate, err := ca.IssueCertificate(commonName, identity)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	body := getCertificateData(certificate)

	c.JSON(http.StatusOK, gin.H{"data": body})
}

// GetCertificatesCommonName is the handler of Certificates by Authorities Certificates endpoint
// @Summary Get information about a Certificate
// @Description get information about a certificate issued by a certain CA
// @Tags CA/{CN}/Certificates
// @Produce json
// @Success 200 {object} models.ResponseCertificates
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca/{cn}/certificates/{certificate_cn} [get]
func GetCertificatesCommonName(c *gin.Context) {

	ca, err := goca.Load(c.Param("cn"))
	if err != nil {
		if err == goca.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}

	certificate, err := ca.LoadCertificate(c.Param("cert_cn"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	body := getCertificateData(certificate)

	c.JSON(http.StatusOK, gin.H{"data": body})

}

// RevokeCertificate is the handler of Certificates by Authorities Certificates endpoint
// @Summary CA revoke a existent certificate managed by CA
// @Description the Certificate Authority revokes a managed Certificate
// @Tags CA/{CN}/Certificates
// @Produce json
// @Accept json
// @Success 200 {object} models.CABody
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca/{cn}/certificates/{certificate_cn} [delete]
func RevokeCertificate(c *gin.Context) {

	ca, err := goca.Load(c.Param("cn"))
	if err != nil {
		if err == goca.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}

	err = ca.RevokeCertificate(c.Param("cert_cn"))
	if err != nil {
		if err == goca.ErrCertRevoked {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	body := getCAData(ca)

	c.JSON(http.StatusOK, gin.H{"data": body})

}
