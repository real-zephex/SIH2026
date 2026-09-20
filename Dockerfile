# syntax=docker/dockerfile:1
# ULPF Phase 2 — air-gap friendly: pure-Go SQLite (no CGO), static binary.
FROM golang:1.27 AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /ulpf .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /ulpf /ulpf
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["/ulpf"]
