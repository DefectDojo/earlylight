# Ubuntu 24.04's nginx (1.24.0-2ubuntu7.19), the default site.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends nginx && rm -rf /var/lib/apt/lists/*
