FROM cgr.dev/chainguard/go:latest AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /open-kmip ./cmd/open-kmip/

FROM cgr.dev/chainguard/wolfi-base:latest
RUN mkdir -p /data && chown nonroot:nonroot /data
COPY --from=build /open-kmip /usr/local/bin/open-kmip
USER nonroot

EXPOSE 5696 8200
VOLUME /data

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- --no-check-certificate https://localhost:8200/healthz || exit 1

ENTRYPOINT ["open-kmip"]
CMD ["--db", "/data/open-kmip.db"]
