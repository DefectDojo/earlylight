# Debian sid's openjdk-17 package: the five-part 17.0.21.0.3+1-1 (the
# release the OpenJDK advisory names as the last affected; no fix yet).
FROM debian:sid-slim
RUN apt-get update && apt-get install -y --no-install-recommends openjdk-17-jre-headless && rm -rf /var/lib/apt/lists/*
