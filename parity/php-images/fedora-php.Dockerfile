FROM mirror.gcr.io/library/fedora:latest
RUN dnf -y install php-cli php-fpm && dnf clean all
