# Alpine 3.22 with openssh 10.0_p1-r10, the release before the fix: an
# account "bob" with the password field "*" and "alice" with a sha512 hash.
FROM alpine:3.22
RUN arch=$(apk --print-arch) && cd /tmp \
 && for p in openssh-keygen openssh-server-common openssh-server openssh-server-pam; do \
      wget -q https://dl-cdn.alpinelinux.org/alpine/v3.22/main/$arch/$p-10.0_p1-r10.apk; done \
 && apk add --no-cache linux-pam /tmp/*.apk && rm /tmp/*.apk \
 && adduser -D alice && echo 'alice:parity-only-not-secret' | chpasswd -c sha512 \
 && adduser -D bob && sed -i 's/^bob:[^:]*:/bob:*:/' /etc/shadow
