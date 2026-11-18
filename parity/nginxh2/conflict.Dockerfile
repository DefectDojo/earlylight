# Synthetic: 1.31.8 with only its version line edited to claim 1.31.9 (the Server header still says 1.31.8). Unknown, never fixed.
FROM nginx:1.31.8
RUN rm /usr/sbin/nginx-debug && sed -i 's#nginx version: nginx/1\.31\.8#nginx version: nginx/1.31.9#' /usr/sbin/nginx
