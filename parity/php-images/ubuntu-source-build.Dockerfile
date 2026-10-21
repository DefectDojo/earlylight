# PHP 8.3.35 built from source into /usr/local on Ubuntu 24.04 (unowned: judged by
# upstream version). The source tarball is the official image's /usr/src/php.tar.xz.
FROM mirror.gcr.io/library/php:8.3.35-cli AS src
FROM mirror.gcr.io/library/ubuntu:24.04 AS build
COPY --from=src /usr/src/php.tar.xz /usr/src/php.tar.xz
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential pkg-config xz-utils bison re2c libxml2-dev libsqlite3-dev && \
    mkdir /usr/src/php && tar -xJf /usr/src/php.tar.xz -C /usr/src/php --strip-components=1 && cd /usr/src/php && \
    ./configure --prefix=/usr/local --enable-fpm --disable-cgi --disable-phpdbg && make -j"$(nproc)" && make install
FROM mirror.gcr.io/library/ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libxml2 libsqlite3-0 && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local /usr/local
RUN /usr/local/bin/php -v
