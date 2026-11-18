# TLS, a proxy, and "http2 off;": not exposed, still vulnerable.
FROM nginx:1.31.8
COPY conf/off.conf /etc/nginx/conf.d/default.conf
