# Go Certificate Authority management package

[![Go Report Card](https://goreportcard.com/badge/github.com/kairoaraujo/goca)](https://goreportcard.com/report/github.com/kairoaraujo/goca)
[![Build Status](https://github.com/kairoaraujo/goca/workflows/tests/badge.svg)](https://github.com/kairoaraujo/goca/actions)

Package GocA provides a Certificate Authority (CA) framework managing.

GoCA is an API Framework that uses mainly crypto/x509 to manage Certificate
Authorities.

Using GoCA makes it easy to create a CA and issue certificates, signing
Certificates Signing Request (CSR), and revoke certificate generating
Certificates Request List (CRL).

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