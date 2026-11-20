# Alpine 3.23's nginx (1.28.3-r7): that branch had no fixed package on 2026-11-18.
FROM alpine:3.23
RUN apk add --no-cache nginx
