FROM golang:1.24-alpine AS builder
ENV CGO_ENABLED=0
WORKDIR /backend
COPY backend/go.* .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download
COPY backend/. .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o bin/service

FROM --platform=$BUILDPLATFORM node:24-alpine AS client-builder
WORKDIR /ui
# cache packages in layer
COPY ui/package.json /ui/package.json
COPY ui/package-lock.json /ui/package-lock.json
RUN --mount=type=cache,target=/usr/src/app/.npm \
    npm set cache /usr/src/app/.npm && \
    npm ci
# install
COPY ui /ui
RUN npm run build

FROM alpine
LABEL org.opencontainers.image.title="Docker OTTY" \
    org.opencontainers.image.description="Docker Desktop extension for Trivy-based image scanning with Docker OTTY workflow." \
    org.opencontainers.image.vendor="22507260" \
    com.docker.desktop.extension.api.version="0.4.2" \
    com.docker.extension.screenshots="[{\"alt\":\"Docker OTTY dashboard\",\"url\":\"https://raw.githubusercontent.com/22507260/docker-otty/main/assets/logo.png\"}]" \
    com.docker.desktop.extension.icon="https://raw.githubusercontent.com/22507260/docker-otty/main/assets/logo.png" \
    com.docker.extension.detailed-description="Run container image scans from Docker Desktop using a Trivy-powered workflow and inspect severity summaries." \
    com.docker.extension.publisher-url="https://github.com/22507260/docker-otty" \
    com.docker.extension.additional-urls="[{\"title\":\"Source Code\",\"url\":\"https://github.com/22507260/docker-otty\"},{\"title\":\"Usage Guide\",\"url\":\"https://github.com/22507260/docker-otty/blob/main/docs/USAGE.md\"}]" \
    com.docker.extension.categories="[\"security\"]" \
    com.docker.extension.changelog="https://github.com/22507260/docker-otty/blob/main/CHANGELOG.md"

COPY --from=builder /backend/bin/service /
COPY docker-compose.yaml .
COPY metadata.json .
COPY docker.svg .
COPY icon.png .
COPY --from=client-builder /ui/build ui
CMD /service -socket /run/guest-services/backend.sock
