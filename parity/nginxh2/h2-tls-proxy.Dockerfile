# nginx 1.31.8 (official, sha256:165ddde8751e...) serving HTTP/2 over TLS in front of a proxy: exposed to both.
FROM nginx:1.31.8
COPY conf/tls-proxy.conf /etc/nginx/conf.d/default.conf
