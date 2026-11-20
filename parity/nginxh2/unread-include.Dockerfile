# An include of files the scan does not read as configuration: exposure unknown, never off.
FROM nginx:1.31.8
COPY conf/unread-main.conf /etc/nginx/nginx.conf
RUN mkdir -p /srv/vhosts && printf 'server { listen 443 ssl http2; }\n' > /srv/vhosts/site
