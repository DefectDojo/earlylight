# Negative controls on Ubuntu 24.04 with no PHP installed: a Go binary carrying both
# PHP banner strings (not NUL-terminated), a C binary with the header only, a shell
# script and a text file quoting the header, and php8.3-cli .debs sitting on disk
# (not installed; a documented limit: must not be reported as a runtime).
FROM mirror.gcr.io/library/golang:1.27.3-alpine AS go
COPY _hostile/fake.go /src/fake.go
RUN cd /src && CGO_ENABLED=0 go build -o /out/php-banner-tool fake.go
FROM mirror.gcr.io/library/alpine:3.22 AS c
RUN apk add --no-cache gcc musl-dev
COPY _hostile/header-only.c /src/
RUN gcc -O2 -static -o /out-header-only /src/header-only.c
FROM mirror.gcr.io/library/ubuntu:24.04
COPY --from=go /out/php-banner-tool /usr/local/bin/php-banner-tool
COPY --from=c /out-header-only /usr/local/bin/x-powered-by-php
RUN printf '#!/bin/sh\necho "X-Powered-By: PHP/8.3.20"\necho "Zend Engine v4.3.20, Copyright (c) Zend Technologies"\n' > /usr/local/bin/php && chmod +x /usr/local/bin/php && \
    printf 'X-Powered-By: PHP/8.3.20\0Zend Engine v4.3.20, Copyright (c) Zend Technologies\0\n' > /usr/share/php-fingerprints.txt && \
    mkdir -p /root/debs && cd /root/debs && apt-get update && apt-get download php8.3-cli php8.3-common && rm -rf /var/lib/apt/lists/* && ls -la /root/debs
