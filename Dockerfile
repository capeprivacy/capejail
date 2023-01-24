FROM golang:1.18-alpine as builder

WORKDIR /build

RUN apk add libseccomp-dev

COPY . /build

RUN go build . 

RUN cp capejail /bin/

