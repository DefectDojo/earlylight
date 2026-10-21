# Debian 12 PHP 8.2 from the archive as served today (bookworm-security).
FROM mirror.gcr.io/library/debian:12
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      php8.2-cli php8.2-fpm php8.2-cgi libapache2-mod-php8.2 && rm -rf /var/lib/apt/lists/*
