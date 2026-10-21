FROM mirror.gcr.io/opensuse/leap:15.6
RUN zypper -n install php7 php7-fpm && zypper clean -a
