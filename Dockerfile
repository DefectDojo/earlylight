FROM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/earlylight ./cmd/earlylight \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/emudhra-scan ./cmd/emudhra-scan \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/php2shell-scan ./cmd/php2shell-scan

# static-debian13 ships a CA bundle without the distrusted roots, needed to pull images.
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/earlylight /out/emudhra-scan /out/php2shell-scan /
COPY LICENSE THIRD_PARTY_NOTICES.txt /licenses/
ENTRYPOINT ["/earlylight"]
