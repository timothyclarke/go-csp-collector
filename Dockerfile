FROM golang:1.10-alpine AS build
COPY . /go/src/jacobbednarz/go-csp-collector
WORKDIR /go/src/jacobbednarz/go-csp-collector
RUN set -ex \
  && apk add --no-cache git \
  && go get -d ./... \
  && go build csp_collector.go

FROM alpine:3.8
LABEL maintainer="Timothy Clarke <ghtimothy@timothy.fromnz.net>"
COPY --from=build /go/src/jacobbednarz/go-csp-collector/csp_collector /
EXPOSE 8080
CMD ["/csp_collector"]
