# Ubuntu 24.04 PHP 8.3 as served today. The image's dpkg excludes drop
# /usr/share/doc; they are removed so the oracle can read the changelog.
FROM mirror.gcr.io/library/ubuntu:24.04
RUN rm -f /etc/dpkg/dpkg.cfg.d/excludes && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      php8.3-cli php8.3-fpm php8.3-cgi libapache2-mod-php8.3 && rm -rf /var/lib/apt/lists/*
