FROM fedora:43
RUN dnf -y install brotli-1.2.0-1.fc43 && dnf clean all
