# No "*" account but root (Alpine's default), with PermitRootLogin yes.
FROM alpine:3.22
RUN arch=$(apk --print-arch) && cd /tmp \
 && for p in openssh-keygen openssh-server-common openssh-server; do \
      wget -q https://dl-cdn.alpinelinux.org/alpine/v3.22/main/$arch/$p-10.0_p1-r10.apk; done \
 && apk add --no-cache /tmp/*.apk && rm /tmp/*.apk \
 && adduser -D alice && echo 'alice:parity-only-not-secret' | chpasswd -c sha512 \
 && echo 'PermitRootLogin yes' > /etc/ssh/sshd_config.d/10-root.conf
