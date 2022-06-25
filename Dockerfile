FROM golang:1.17-alpine as builder

RUN mkdir /goca-builder

ADD . /goca-builder
WORKDIR /goca-builder/rest-api

RUN go build -o main .

FROM golang:1.17-alpine

RUN mkdir -p /goca/data

ENV CAPATH=/goca/data

WORKDIR /goca/
COPY --from=builder /goca-builder/rest-api/main .

CMD ["/goca/main"]