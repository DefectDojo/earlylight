# Ubuntu 24.04's openjdk-25 package (25.0.5.0.3+1-3~24.04.1: no fix yet).
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends openjdk-25-jre-headless && rm -rf /var/lib/apt/lists/*
