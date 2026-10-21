# Ubuntu 24.04 + ppa:ondrej/php (the PPA is added by hand: no software-properties).
FROM mirror.gcr.io/library/ubuntu:24.04
RUN rm -f /etc/dpkg/dpkg.cfg.d/excludes && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates gnupg curl && \
    curl -fsSL 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x14AA40EC0831756756D7F66C4F4EA0AAE5267A6C' | gpg --dearmor > /usr/share/keyrings/ondrej-php.gpg && \
    echo 'deb [signed-by=/usr/share/keyrings/ondrej-php.gpg] https://ppa.launchpadcontent.net/ondrej/php/ubuntu noble main' > /etc/apt/sources.list.d/ondrej-php.list && \
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -o Acquire::Retries=20 -y --no-install-recommends php8.3-cli php8.3-fpm php8.4-cli && \
    rm -rf /var/lib/apt/lists/*
