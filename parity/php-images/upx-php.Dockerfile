# The official Alpine CLI image with its php binary UPX-packed: must be listed skipped.
FROM mirror.gcr.io/library/php:8.3.35-cli-alpine
RUN apk add --no-cache upx && upx -q /usr/local/bin/php && apk del upx && /usr/local/bin/php -v
