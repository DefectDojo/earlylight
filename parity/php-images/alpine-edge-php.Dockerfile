FROM mirror.gcr.io/library/alpine:edge
RUN apk add --no-cache php84 php84-fpm php85 php85-fpm
