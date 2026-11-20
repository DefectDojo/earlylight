# HTTP/2 over TLS serving static files only (no proxy): exposed to CVE-2026-123007, not the 123633 path.
FROM nginx:1.31.8
COPY conf/static-h2.conf /etc/nginx/conf.d/default.conf
