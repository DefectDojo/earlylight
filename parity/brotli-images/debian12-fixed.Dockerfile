FROM debian:12
RUN apt-get update && apt-get install -y --no-install-recommends libbrotli1=1.0.9-2+deb12u1 && rm -rf /var/lib/apt/lists/*
