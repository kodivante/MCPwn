# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mcpwn ./cmd/mcpwn

FROM alpine:3.20

COPY --from=builder /mcpwn /usr/local/bin/mcpwn
RUN adduser -D -H -u 10001 mcpwn
USER mcpwn

ENTRYPOINT ["mcpwn"]
CMD ["--help"]
