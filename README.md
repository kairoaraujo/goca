# Go Certificate Authority management package

[![Go Report Card](https://goreportcard.com/badge/github.com/kairoaraujo/goca)](https://goreportcard.com/report/github.com/kairoaraujo/goca)
[![Build Status](https://github.com/kairoaraujo/goca/workflows/tests/badge.svg)](https://github.com/kairoaraujo/goca/actions)
[![Go Reference](https://pkg.go.dev/badge/github.com/kairoaraujo/goca.svg)](https://pkg.go.dev/github.com/kairoaraujo/goca)
[![Docker Pulls](https://img.shields.io/docker/pulls/kairoaraujo/goca.svg?maxAge=604800)](https://hub.docker.com/r/kairoaraujo/goca/)


GocA provides a Certificate Authority (CA) framework managing, a Simple PKI.

GoCA is a framework that uses mainly crypto/x509 to manage Certificate
Authorities.

Using GoCA makes it easy to create a CA and issue certificates, signing
Certificates Signing Request (CSR), and revoke certificate generating
Certificates Request List (CRL).

**Content**:

- [Go Certificate Authority management package](#go-certificate-authority-management-package)
  - [GoCA Package](#goca-package)
  - [GoCA HTTP REST API](#goca-http-rest-api)
  - [GoCA Docker Container](#goca-docker-container)
- [Contributing](#contributing)

## GoCA Package

```shell
go get http://github.com/kairoaraujo/goca
```

All files are store in the ``$CAPATH``. The ``$CAPATH`` is an environment
variable that defines where all files (keys, certificates, etc.) are stored.
It is essential to have this folder in a safe place.

$CPATH structure:

```shell

$CPATH
├── <CA Common Name>
    ├── ca
    │   ├── <CA Common Name>.crl
    │   ├── <CA Common Name>.crt
    │   ├── key.pem
    │   └── key.pub
    └── certs
        └── <Certificate Common Name>
            ├── <Certificate Common Name>.crt
            ├── <Certificate Common Name>.csr
            ├── key.pem
            └── key.pub
```

GoCA also make it easier to manipulate files such as Private and Public Keys,
Certificate Signing Request, Certificate Request Lists, and Certificates
for other Go applications.


This example shows

1. Creating a Certificate Authority (Root) or Loading if it already exists
2. Issue a new Certificate
3. Shows the certificate

```go

// Define the GOCAPTH (Default is current dir)
os.Setenv("CAPATH", "/opt/GoCA/CA")

// RootCAIdentity for creation
rootCAIdentity := goca.Identity{
    Organization:       "GO CA Root Company Inc.",
    OrganizationalUnit: "Certificates Management",
    Country:            "NL",
    Locality:           "Noord-Brabant",
    Province:           "Veldhoven",
    Intermediate:       false,
}

// (1) Create the New Root CA or loads existent from disk ($CAPATH)
RootCA, err := goca.New("mycompany.com", rootCAIdentity)
if err != nil {
    // Loads in case it exists
    fmt.Println("Loading CA")
    RootCA, err = goca.Load("gocaroot.nl")
    if err != nil {
        log.Fatal(err)
    }

    // Check the CA status and shows the CA Certificate
    fmt.Println(RootCA.Status())
    fmt.Println(RootCA.GetCertificate())

} else {
    log.Fatal(err)
}

// (2) Issue certificate for example intranet server
intranetIdentity := goca.Identity{
    Organization:       "Intranet Company Inc.",
    OrganizationalUnit: "Global Intranet",
    Country:            "NL",
    Locality:           "Noord-Brabant",
    Province:           "Veldhoven",
    Intermediate:       false,
    DNSNames:           []string{"w3.intranet.example.com", "www.intranet.example.com"},
}

intranetCert, err := RootCA.IssueCertificate("intranet.example.com", intranetIdentity)
if err != nil {
    log.Fatal(err)
}

// (3) Shows the Certificate (string)
fmt.Println(intranetCert.GetCertificate())

// Shows all CA Certificates
fmt.Println(RootCA.ListCertificates())
```

## GoCA HTTP REST API

GoCA also provides an implementation using HTTP REST API.

This is available in [``rest-api``](rest-api/) folder.

## GoCA Docker Container

GoCA Docker ready to use HTTP Rest API that uses mainly crypto/x509 to manage Certificate Authorities and Certificates such
as a simple PKI Service.

The API Documentation is online available at http://kairoaraujo.github.io/goca/.

More details in [Docker README](DOCKER_README.md).

GoCA Docker Image is available at https://hub.docker.com/r/kairoaraujo/goca/

# Contributing

See [CONTRIBUTING](CONTRIBUTING.md).