package models

import (
	"github.com/kairoaraujo/goca"
)

type CAData struct {
	Data  CAJSON `json:"data"`
	Error string `json:"error" example:"Certificate Authority not found"`
}

type CAJSON struct {
	CommonName                string      `json:"common_name" example:"go-root.ca"`
	Intermediate              bool        `json:"intermediate"`
	Status                    string      `json:"status" example:"Certificate Authority is ready."`
	SerialNumber              string      `json:"serial_number" example:"271064285308788403797280326571490069716"`
	DNSNames                  []string    `json:"dns_names" example:"www.go-root.ca,secure.go-root.ca,go-root.ca"`
	CSR                       bool        `json:"csr" example:"false"`
	Certificates              []string    `json:"certificates" example:"go-itermediate.ca,intranet.go-root.ca"`
	CertificateRevocationList []string    `json:"revoked_certificates" example:"38188836191244388427366318074605547405,338255903472757769326153358304310617728"`
	Files                     goca.CAData `json:"files"`
}

type CertificateJSON struct {
	CommonName   string           `json:"common_name"`
	SerialNumber string           `json:"serial_number"`
	DNSNames     []string         `json:"dns_names"`
	Files        goca.Certificate `json:"files"`
}
