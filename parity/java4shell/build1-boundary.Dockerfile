# SYNTHETIC boundary case: the fixed SapMachine 21.0.13.1+2 with the
# version line in its VM library and release file rewritten to build +1,
# which upstream (jdk-21.0.13.1+1) did not have the fix. No +1 binary was
# published; this checks that a build below the fixed build is not
# judged fixed.
FROM debian:12-slim
ADD --checksum=sha256:6cb4df182dc9efd3cd37722517832e402cd1beed4f7e3d4d9b58abeb3e949ae9 \
    https://github.com/SAP/SapMachine/releases/download/sapmachine-21.0.13.1/sapmachine-jre-21.0.13.1_linux-x64_bin.tar.gz /tmp/sap.tgz
RUN mkdir -p /opt/sapmachine && tar xzf /tmp/sap.tgz -C /opt/sapmachine --strip-components=1 && rm /tmp/sap.tgz \
 && sed -i 's/21\.0\.13\.1+2-LTS/21.0.13.1+1-LTS/g' /opt/sapmachine/lib/server/libjvm.so /opt/sapmachine/release
