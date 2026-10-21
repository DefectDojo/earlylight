# Ubuntu 24.04 php8.3-cli (fixed .13) whose /usr/bin/php8.3 was then overwritten
# with the official image's PHP 8.3.35 CLI: must be unknown (modified), never fixed.
FROM mirror.gcr.io/library/php:8.3.35-cli AS official
FROM mirror.gcr.io/library/ubuntu:24.04
RUN rm -f /etc/dpkg/dpkg.cfg.d/excludes && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends php8.3-cli && rm -rf /var/lib/apt/lists/*
COPY --from=official /usr/local/bin/php /usr/bin/php8.3
