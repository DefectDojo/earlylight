FROM earlylight-parity-sshole:vuln
RUN echo 'UsePAM yes' > /etc/ssh/sshd_config.d/00-pam.conf
