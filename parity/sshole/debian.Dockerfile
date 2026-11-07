FROM debian:12-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends openssh-server >/dev/null \
 && useradd -m bob && usermod -p '*' bob && rm -rf /var/lib/apt/lists/*
