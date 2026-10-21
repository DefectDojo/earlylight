FROM mirror.gcr.io/opensuse/leap:15.6
RUN zypper -n install php8 php8-fpm && zypper clean -a
