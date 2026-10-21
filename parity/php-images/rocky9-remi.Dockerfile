# Rocky Linux 9 + Remi's repository (remi-modular php:remi-8.3). Remi's mirror
# network sometimes serves stale repodata, hence the retries.
FROM mirror.gcr.io/library/rockylinux:9
RUN dnf -y install epel-release && dnf -y install https://rpms.remirepo.net/enterprise/remi-release-9.rpm && \
    for i in 1 2 3 4 5 6; do dnf -y module reset php && dnf -y module enable php:remi-8.3 && dnf -y install php-cli php-fpm && ok=1 && break; dnf clean all; sleep 10; done; \
    [ -n "$ok" ] && dnf clean all
