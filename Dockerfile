FROM golang:latest as builder
 
RUN go get github.com/onsecurity/shodan 
WORKDIR /go/src/github.com/onsecurity/shodan
RUN CGO_ENABLED=0 go build -o /shodan

FROM alpine:latest
COPY --from=builder /shodan /shodan
COPY --from=0 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT ["/shodan"]