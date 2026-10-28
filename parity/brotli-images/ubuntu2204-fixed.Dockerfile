FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends libbrotli1=1.0.9-2ubuntu0.1 && rm -rf /var/lib/apt/lists/*
