# Adversarial forgery: a non-PHP ELF with both banner strings NUL-terminated.
FROM mirror.gcr.io/library/alpine:3.22 AS c
RUN apk add --no-cache gcc musl-dev
COPY _hostile/forgery.c /src/
RUN gcc -O2 -static -o /out-forgery /src/forgery.c
FROM mirror.gcr.io/library/alpine:3.22
COPY --from=c /out-forgery /usr/local/bin/not-php
