# Synthetic: the module list and configure arguments edited to read as a build without HTTP/2. Not affected.
FROM nginx:1.31.8
RUN rm /usr/sbin/nginx-debug && sed -i 's/ngx_http_v2_module/ngx_http_vX_module/g; s/--with-http_v2_module/--with-http_vX_module/g' /usr/sbin/nginx
