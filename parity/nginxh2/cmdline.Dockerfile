# The image's command loads another configuration (-c) that turns HTTP/2 on.
FROM nginx:1.31.8
COPY conf/app.conf /srv/app.conf
CMD ["nginx", "-c", "/srv/app.conf", "-g", "daemon off;"]
