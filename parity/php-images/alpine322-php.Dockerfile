FROM mirror.gcr.io/library/alpine:3.22
RUN apk add --no-cache php83 php83-fpm php83-cgi php84 php84-fpm
