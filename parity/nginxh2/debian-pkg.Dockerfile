# Debian 12's own nginx (1.22.1-9+deb12u10, no fixed package on 2026-11-18), a site enabled through a symbolic link.
FROM debian:12
RUN apt-get update && apt-get install -y --no-install-recommends nginx && rm -rf /var/lib/apt/lists/*
COPY conf/tls-proxy.conf /etc/nginx/sites-available/app
RUN rm /etc/nginx/sites-enabled/default && ln -s ../sites-available/app /etc/nginx/sites-enabled/app
