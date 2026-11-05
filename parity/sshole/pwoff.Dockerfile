FROM earlylight-parity-sshole:vuln
RUN echo 'PasswordAuthentication no' > /etc/ssh/sshd_config.d/00-off.conf
