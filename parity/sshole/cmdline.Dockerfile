# Password logins off in sshd_config, on again in the image's command.
FROM earlylight-parity-sshole:vuln
RUN echo 'PasswordAuthentication no' > /etc/ssh/sshd_config.d/00-off.conf
CMD ["/usr/sbin/sshd", "-D", "-e", "-o", "PasswordAuthentication=yes"]
