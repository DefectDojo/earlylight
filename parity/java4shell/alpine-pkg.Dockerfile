# Alpine's openjdk21 package (21.0.13.0.3_p1-r0 in 3.23 on 2026-11-17: no fix yet).
FROM alpine:3.23
RUN apk add --no-cache openjdk21-jre-headless
