package models

import (
	"github.com/kairoaraujo/goca"
)

type ResponseError struct {
	Error string `json:"error" example:"error message"`
}

type ResponseCA struct {
	Data CABody `json:"data"`
}

type ResponseCertificates struct {
	Data CertificateBody `json:"data"`
}

type ResponseList struct {
	Data []string `json:"data" example:"cn1,cn2,cn3"`
}

type Payload struct {
	CommonName       string        `json:"common_name" example:"root-ca" binding:"required"`
	ParentCommonName string        `json:"parent_common_name" example:"root-ca"`
	Identity         goca.Identity `json:"identity" binding:"required"`
}

type CABody struct {
	CommonName                string      `json:"common_name" example:"root-ca"`
	Intermediate              bool        `json:"intermediate"`
	Status                    string      `json:"status" example:"Certificate Authority is ready."`
	SerialNumber              string      `json:"serial_number" example:"271064285308788403797280326571490069716"`
	IssueDate                 string      `json:"issue_date" example:"2021-01-06 10:31:43 +0000 UTC"`
	ExpireDate                string      `json:"expire_date" example:"2022-01-06 10:31:43 +0000 UTC"`
	DNSNames                  []string    `json:"dns_names" example:"ca.example.ca,root-ca.example.com"`
	CSR                       bool        `json:"csr" example:"false"`
	Certificates              []string    `json:"certificates" example:"intranet.example.com,w3.example.com"`
	CertificateRevocationList []string    `json:"revoked_certificates" example:"38188836191244388427366318074605547405,338255903472757769326153358304310617728"`
	Files                     goca.CAData `json:"files"`
}

type CertificateBody struct {
	CommonName   string           `json:"common_name" example:"intranet.go-root"`
	SerialNumber string           `json:"serial_number" example:"338255903472757769326153358304310617728"`
	IssueDate    string           `json:"issue_date" example:"2021-01-06 10:31:43 +0000 UTC"`
	ExpireDate   string           `json:"expire_date" example:"2022-01-06 10:31:43 +0000 UTC"`
	DNSNames     []string         `json:"dns_names" example:"w3.intranet.go-root.ca,intranet.go-root.ca"`
	Files        goca.Certificate `json:"files"`
}
