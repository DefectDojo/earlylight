FROM alpine:3.22
RUN apk add --no-cache 'openssh-server>=10.0_p1-r11' 'openssh-server-pam>=10.0_p1-r11' \
 && adduser -D alice && echo 'alice:parity-only-not-secret' | chpasswd -c sha512 \
 && adduser -D bob && sed -i 's/^bob:[^:]*:/bob:*:/' /etc/shadow
