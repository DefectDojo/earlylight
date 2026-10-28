FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends libbrotli1=1.1.0-2ubuntu0.1 && rm -rf /var/lib/apt/lists/*
