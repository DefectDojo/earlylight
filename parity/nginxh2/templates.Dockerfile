# The official entrypoint writes /etc/nginx/templates/*.template to conf.d at start.
FROM nginx:1.31.8
RUN rm /etc/nginx/conf.d/default.conf
COPY conf/tls-proxy.conf /etc/nginx/templates/default.conf.template
