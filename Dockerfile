# syntax=docker/dockerfile:1
#
# nhcx-adapter container image.
#
#   docker build -t nhcx-adapter .                       # or: make docker
#   docker run --env-file .env -v ./data:/data -p 8090:8090 nhcx-adapter
#
# The binary is cross-compiled on the build host (pure Go, CGO off), so a
# multi-arch build needs no emulation: the runtime stage has no RUN steps.

ARG GO_VERSION=1.26

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS TARGETARCH
# .git is not in the build context; CI and `make docker` pass these in.
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILT_AT=
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.builtAt=${BUILT_AT}" \
      -o /out/nhcx-adapter . \
 && mkdir -p /out/data

FROM alpine:3.22
COPY --from=build /out/nhcx-adapter /usr/local/bin/nhcx-adapter
# /data holds the key, certificate and ledger. Owned by the runtime user so a
# fresh named volume inherits it.
COPY --from=build --chown=10001:10001 /out/data /data
COPY config.docker.json /etc/nhcx-adapter/config.json

# The baked-in config reads everything from the environment. Required, no
# default: NHCX_PARTICIPANT_ID, NHCX_CLIENT_ID, NHCX_CLIENT_SECRET,
# NHCX_CALLBACK_URL. Mount your own file and point NHCX_ADAPTER_CONFIG at it
# to use a hand-written config instead.
ENV NHCX_ADAPTER_CONFIG=/etc/nhcx-adapter/config.json \
    NHCX_ENV=sandbox \
    NHCX_PUBLIC_URL= \
    NHCX_ADAPTER_API_KEY= \
    NHCX_CALLBACK_API_KEY= \
    NHCX_PANEL_PASSWORD= \
    NHCX_LOG_LEVEL=info \
    NHCX_LOG_FORMAT=json \
    NHCX_ADAPTER_NO_UPDATE_CHECK=1 \
    NHCX_ADAPTER_NO_BANNER=1 \
    HOME=/data

USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8090

# serve only listens once the setup checks pass, which can take a while.
HEALTHCHECK --interval=30s --timeout=5s --start-period=2m --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8090/healthz || exit 1

ENTRYPOINT ["nhcx-adapter"]
CMD ["serve", "--no-tui"]
