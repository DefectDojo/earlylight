ARG NGINX_TAG=1.30.6
FROM nginx:1.31.8-alpine AS edge
FROM nginx:${NGINX_TAG}-perl AS web
COPY conf.d/ /etc/nginx/conf.d/
FROM debian:12 AS deb
RUN apt-get update && apt-get install -y --no-install-recommends nginx=1.22.1-9+deb12u10 && rm -rf /var/lib/apt/lists/*
FROM alpine:3.24 AS apk
RUN apk add --no-cache nginx
FROM ubuntu:24.04 AS ub
RUN sh -c "apt-get update && apt-get install -y nginx-full"
FROM debian:trixie-slim AS org
RUN curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor > /usr/share/keyrings/nginx.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/nginx.gpg] http://nginx.org/packages/mainline/debian trixie nginx" > /etc/apt/sources.list.d/nginx.list \
 && apt-get update && apt-get install -y nginx=1.31.8-1~trixie
FROM rockylinux:9 AS rh
RUN dnf module enable -y nginx:1.24 && dnf install -y nginx
FROM nginx:mainline AS moving
FROM openresty/openresty:1.31.8.1-alpine AS or
ENV PKGS="nginx"
RUN apk add $PKGS $EXTRA
FROM nginx:1.31.9 AS ok
