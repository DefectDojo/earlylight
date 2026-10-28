FROM debian:13
RUN apt-get update && apt-get install -y --no-install-recommends libbrotli1=1.1.0-2+deb13u1 && rm -rf /var/lib/apt/lists/*
