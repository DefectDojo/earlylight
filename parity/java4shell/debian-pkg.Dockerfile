# Debian 12's openjdk-17 package (17.0.21+9-1~deb12u1 on 2026-11-17: no fix yet).
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openjdk-17-jre-headless && rm -rf /var/lib/apt/lists/*
