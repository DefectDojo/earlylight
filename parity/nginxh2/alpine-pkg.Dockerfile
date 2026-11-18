# Alpine 3.24's nginx as published when built (1.30.7-r0 from 2026-11-18 17:06 UTC), HTTP/2 on in http.d.
FROM alpine:3
RUN apk add --no-cache nginx
COPY conf/static-h2.conf /etc/nginx/http.d/default.conf
