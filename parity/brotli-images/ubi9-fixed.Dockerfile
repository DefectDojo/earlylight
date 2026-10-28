FROM registry.access.redhat.com/ubi9/ubi
RUN dnf -y install brotli-1.0.9-10.el9_8.1 && dnf clean all
