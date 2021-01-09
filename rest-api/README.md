# Go Certificate Authority HTTP Rest API

This is a simple implementation of GoCA as HTTP Rest API.

GoCA is an API Framework that uses mainly crypto/x509 to manage Certificate
Authorities, such as a simple PKI.

With this HTTP Rest API is possible to create Certificate Authorities (CA),
including Intermediate Certificate Authorities (ICA), from the CA issue Certificates, sign CSR and revoke Certificates.

The API Swagger Documentation is available in ``docs`` and the online
documentation is published in http://kairoaraujo.github.io/goca/.
