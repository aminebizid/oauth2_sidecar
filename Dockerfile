FROM golang:1.12-alpine3.9 as build-env

RUN apk update && \
    apk add --no-cache make ca-certificates git && \
    update-ca-certificates

WORKDIR $GOPATH/src/github.com/aminebizid/oauth2_sidecar
COPY . .

RUN make build && mv dist/oauth2_sidecar /oauth2_sidecar

RUN mkdir -p /tmp/empty

FROM scratch

COPY --from=build-env /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build-env /oauth2_sidecar /oauth2_sidecar
# make sure /tmp exists
COPY --from=build-env /tmp/empty /tmp

ENTRYPOINT [ "/oauth2_sidecar" ]