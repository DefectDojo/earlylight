# Temurin 21.0.13 on Alpine (musl: its VM library names linux-amd64-musl)
# under a release file forged to claim the fixed 21.0.13.1: the VM
# library's own version decides.
FROM eclipse-temurin:21.0.13_9-jre-alpine
RUN sed -i 's/^JAVA_VERSION=.*/JAVA_VERSION="21.0.13.1"/; s/^JAVA_RUNTIME_VERSION=.*/JAVA_RUNTIME_VERSION="21.0.13.1+2-LTS"/' /opt/java/openjdk/release
