FROM mirror.gcr.io/library/debian:13
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      php8.4-cli php8.4-fpm libapache2-mod-php8.4 && rm -rf /var/lib/apt/lists/*
