# Include loops, a symbolic link loop, a fan-out of includes, deep nesting and an oversized
# configuration file: the scan finishes, the server stays vulnerable, exposure is unknown.
FROM nginx:1.31.8
RUN cd /etc/nginx/conf.d \
 && printf 'include /etc/nginx/conf.d/b.inc;\n' > a.inc \
 && printf 'include /etc/nginx/conf.d/a.inc;\n' > b.inc \
 && printf 'include /etc/nginx/conf.d/a.inc;\n' > loop.conf \
 && ln -s self.conf self.conf \
 && for i in $(seq 0 15); do n=$((i+1)); printf 'include /etc/nginx/fan/l%d.inc; include /etc/nginx/fan/l%d.inc;\n' $n $n > /tmp/l$i.inc; done \
 && mkdir -p /etc/nginx/fan && mv /tmp/l*.inc /etc/nginx/fan/ && printf 'include /etc/nginx/fan/l0.inc;\n' > fan.conf \
 && awk 'BEGIN{for(i=0;i<80;i++) printf "location /%d {", i; for(i=0;i<80;i++) printf "}"; print ""}' > /etc/nginx/deep.inc \
 && printf 'server { listen 81; include /etc/nginx/deep.inc; }\n' > deep.conf \
 && head -c 5000000 /dev/zero | tr '\0' '#' > big.conf
