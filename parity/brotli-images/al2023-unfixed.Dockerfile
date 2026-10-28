FROM amazonlinux:2023
RUN dnf -y install brotli-1.1.0-1.amzn2023.0.1 && dnf clean all
