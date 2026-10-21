# UBI 9 AppStream: the php:8.3 module stream.
FROM registry.access.redhat.com/ubi9/ubi:latest
RUN dnf -y module enable php:8.3 && dnf -y install php-cli php-fpm && dnf clean all
