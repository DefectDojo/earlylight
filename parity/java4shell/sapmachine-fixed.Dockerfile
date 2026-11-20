# SapMachine 21.0.13.1, the first 21 release with the Java4Shell fix
# (released 2026-11-17), unpacked from its GitHub release tarball.
FROM debian:12-slim
ADD --checksum=sha256:6cb4df182dc9efd3cd37722517832e402cd1beed4f7e3d4d9b58abeb3e949ae9 \
    https://github.com/SAP/SapMachine/releases/download/sapmachine-21.0.13.1/sapmachine-jre-21.0.13.1_linux-x64_bin.tar.gz /tmp/sap.tgz
RUN mkdir -p /opt/sapmachine && tar xzf /tmp/sap.tgz -C /opt/sapmachine --strip-components=1 && rm /tmp/sap.tgz
