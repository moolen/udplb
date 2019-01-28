.PHONY: build
build:
	dep ensure
	go get -u github.com/go-bindata/go-bindata
	go-bindata bpf/ingress.c
	go build
	(cd test && CGO_ENABLED=0 go build -o snd ./udpsnd)
	(cd test && CGO_ENABLED=0 go build -o rcv ./udprcv)

.PHONY: test
test: unit-test integration-test

.PHONY: unit-test
unit-test: build
	go test -v -cover ./...

.PHONY: integration-test
integration-test:
	(cd test && ./integration.sh)

.PHONY: run
run: build
	docker-compose build
	docker-compose up
