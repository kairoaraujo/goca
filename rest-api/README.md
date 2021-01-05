# Go Certificate Authority HTTP Rest API

This is a simple implementation of GoCA as HTTP Rest API.

GoCA is an API Framework that uses mainly crypto/x509 to manage Certificate
Authorities, such as a simple PKI.

The API Documentation is available in ``docs`` folder.

With this HTTP Rest API is possible to create Certificate Authorities (CA),
including Intermediate Certificate Authorities (ICA) and issue, sign CSR and
revoke Certificates as a Service.
