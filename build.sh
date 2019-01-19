#!/bin/bash
dep ensure
go get -u github.com/go-bindata/go-bindata
go-bindata bpf/ingress.c
go build
