FROM earlylight-parity-sshole:vuln
RUN printf 'PasswordAuthentication no\nMatch Address 10.0.0.0/8\n  PasswordAuthentication yes\n' > /etc/ssh/sshd_config.d/00-match.conf
