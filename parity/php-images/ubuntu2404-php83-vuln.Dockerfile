# Ubuntu 24.04 PHP 8.3 pinned to the archive as of 2026-10-20 (snapshot.ubuntu.com):
# 8.3.6-0ubuntu0.24.04.12, the last build before USN-8948-1. amd64 only: the
# snapshot service does not cover ports.ubuntu.com. ca-certificates first, from the
# live archive, because the snapshot service is HTTPS.
FROM mirror.gcr.io/library/ubuntu:24.04
RUN rm -f /etc/dpkg/dpkg.cfg.d/excludes && apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    apt-get update --snapshot 20261020T000000Z && \
    DEBIAN_FRONTEND=noninteractive apt-get install --snapshot 20261020T000000Z -y --no-install-recommends php8.3-cli php8.3-fpm && \
    dpkg-query -W php8.3-cli && rm -rf /var/lib/apt/lists/*
