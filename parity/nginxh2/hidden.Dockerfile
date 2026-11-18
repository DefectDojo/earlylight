# Synthetic: the version line is renamed away (same length), as a patched or stripped build might be. Never cleared.
FROM nginx:1.31.8
RUN rm /usr/sbin/nginx-debug && sed -i 's/nginx version: /nginx-build: v /' /usr/sbin/nginx
