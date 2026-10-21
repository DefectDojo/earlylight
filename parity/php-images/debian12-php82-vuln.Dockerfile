# Debian 12 PHP 8.2 pinned to the last vulnerable security build, 8.2.34-1~deb12u1,
# from snapshot.debian.org (debian-security as of 2026-10-15).
FROM mirror.gcr.io/library/debian:12
RUN rm -f /etc/apt/sources.list.d/debian.sources && \
    printf 'deb http://deb.debian.org/debian bookworm main\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20261015T000000Z bookworm-security main\n' > /etc/apt/sources.list && \
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      php8.2-cli=8.2.34-1~deb12u1 php8.2-common=8.2.34-1~deb12u1 php8.2-opcache=8.2.34-1~deb12u1 php8.2-readline=8.2.34-1~deb12u1 \
      php8.2-fpm=8.2.34-1~deb12u1 libapache2-mod-php8.2=8.2.34-1~deb12u1 && rm -rf /var/lib/apt/lists/*
