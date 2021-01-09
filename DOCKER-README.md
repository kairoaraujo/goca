# GoCA Docker

[![Docker Pulls](https://img.shields.io/docker/pulls/kairoaraujo/goca.svg?maxAge=604800)](https://hub.docker.com/r/kairoaraujo/goca/)

GoCA Docker is HTTP Rest API that uses mainly crypto/x509 to manage Certificate Authorities and Certificates such
as a simple PKI Service.

> NOTE: Do not explose the GoCA service, use it behind to some Authentication/Authorization service.

## Docker Container
### Stable
```
docker run -p 80:80 kairoaraujo/goca goca-server /goca/data
```
