# Ubuntu 20.04 without ESM: the public archive's last php7.4 build has no fix.
FROM mirror.gcr.io/library/ubuntu:20.04
RUN rm -f /etc/dpkg/dpkg.cfg.d/excludes && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      php7.4-cli php7.4-fpm && rm -rf /var/lib/apt/lists/*
