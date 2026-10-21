FROM mirror.gcr.io/library/amazonlinux:2023
RUN dnf -y install php8.3-cli php8.3-fpm && dnf clean all
