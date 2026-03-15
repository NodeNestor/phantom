FROM golang:1.23-alpine AS builder
ENV GOTOOLCHAIN=local
RUN apk add --no-cache upx
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/phantom-setup  ./cmd/setup \
 && CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/phantom-auth   ./cmd/auth \
 && CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/phantom-relay  ./cmd/relay \
 && CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/phantom-client ./cmd/client \
 && CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/phantom-ui     ./cmd/ui \
 && upx --best /bin/phantom-*

FROM alpine:3.21
RUN apk add --no-cache curl bash
COPY --from=builder /bin/phantom-* /usr/local/bin/
WORKDIR /data
