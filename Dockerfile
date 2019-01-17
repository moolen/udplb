FROM archlinux/base
RUN pacman -Sy git curl make gcc clang go linux-headers glibc go lib32-glibc --noconfirm
ENV GOPATH=/go
ENV PATH="/go/bin:${PATH}"

RUN go get -u github.com/golang/dep/cmd/dep
WORKDIR /go/src/github.com/moolen/udpf
ADD . /go/src/github.com/moolen/udpf
RUN make

ENTRYPOINT [ "/go/src/github.com/moolen/udpf/entrypoint.sh" ]
