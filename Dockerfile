FROM golang:latest as builder
 
RUN go get github.com/onsecurity/shodan 

FROM scratch
COPY --from=builder /go/bin/shodan /shodan

ENTRYPOINT["/shodan"]