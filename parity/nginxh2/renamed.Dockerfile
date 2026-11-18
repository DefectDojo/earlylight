# Synthetic: a build that names itself something else everywhere. Unknown.
FROM nginx:1.31.8
RUN rm /usr/sbin/nginx-debug && sed -i 's#nginx/1\.31\.8#WAFsrv/9.9.9#g' /usr/sbin/nginx
