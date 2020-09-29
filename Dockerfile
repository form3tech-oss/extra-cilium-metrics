FROM golang:1.15 AS builder
WORKDIR /go/src/github.com/form3tech-oss/extra-cilium-metrics
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build TARGET=/extra-cilium-metrics

FROM gcr.io/distroless/base
USER nobody:nobody
WORKDIR /
COPY --from=builder /extra-cilium-metrics /extra-cilium-metrics
ENTRYPOINT ["/extra-cilium-metrics"]
