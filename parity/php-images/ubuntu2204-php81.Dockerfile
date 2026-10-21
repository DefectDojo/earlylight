FROM mirror.gcr.io/library/ubuntu:22.04
RUN rm -f /etc/dpkg/dpkg.cfg.d/excludes && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      php8.1-cli php8.1-fpm && rm -rf /var/lib/apt/lists/*
