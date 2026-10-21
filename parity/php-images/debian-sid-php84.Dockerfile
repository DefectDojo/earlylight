FROM mirror.gcr.io/library/debian:sid
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      php8.4-cli php8.4-fpm && rm -rf /var/lib/apt/lists/*
