# GoCA Docker Container

[![Docker Pulls](https://img.shields.io/docker/pulls/kairoaraujo/goca.svg?maxAge=604800)](https://hub.docker.com/r/kairoaraujo/goca/)


GocA provides a Certificate Authority (CA) framework managing, a Simple PKI.

The API Documentation is online available at http://kairoaraujo.github.io/goca/.

## GoCA Docker Container

GoCA Docker is HTTP Rest API that uses mainly crypto/x509 to manage Certificate Authorities and Certificates such
as a simple PKI Service.

> NOTE: Do not expose the GoCA HTTP REST API service directly. Use it behind to some
Authentication/Authorization service.

### Docker Container

```
$ docker run -p 80:80 kairoaraujo/goca:tag
```

### Where store the data

> The GoCA data (certificate, keys, etc.) is in ``/goca/data``; make sure you have a protected volume for this data.

Create a data directory on a suitable volume on your host system, e.g. /my/own/datadir.

Start your GoCA container like this:

````
$ docker run -p 80:80 -v /my/own/datadir:/goca/data kairoaraujo/goca:tag
````
