FROM golang
COPY ./*.go /go/src/github.com/flaccid/golang-examples/
WORKDIR /go/src/github.com/flaccid/golang-examples
