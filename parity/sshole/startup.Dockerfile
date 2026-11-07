# Password logins off and no "*" account as the image ships; the entrypoint
# turns password logins on and sets a "*" account when the container starts.
FROM earlylight-parity-sshole:vuln
RUN echo 'PasswordAuthentication no' > /etc/ssh/sshd_config.d/00-off.conf \
 && sed -i 's/^bob:\*:/bob:!:/' /etc/shadow \
 && printf '#!/bin/sh\nrm -f /etc/ssh/sshd_config.d/00-off.conf\necho "PasswordAuthentication yes" >> /etc/ssh/sshd_config\necho "$SSH_USER:*" | chpasswd -e\nexec /usr/sbin/sshd -D -e\n' > /entrypoint.sh \
 && chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
