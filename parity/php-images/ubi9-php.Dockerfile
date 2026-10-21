# UBI 9 AppStream: the default php (8.0) stream.
FROM registry.access.redhat.com/ubi9/ubi:latest
RUN dnf -y install php-cli php-fpm && dnf clean all
