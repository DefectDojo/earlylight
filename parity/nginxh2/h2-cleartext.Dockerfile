# HTTP/2 without TLS (prior knowledge) in front of a proxy.
FROM nginx:1.31.8
COPY conf/cleartext.conf /etc/nginx/conf.d/default.conf
