FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      iproute2 \
      iptables \
      openresolv \
      procps \
      python3 \
      tinyproxy \
      wireguard-tools \
 && rm -rf /var/lib/apt/lists/*

# Docker sets this sysctl at container creation. Some runtimes reject the same
# write from inside the container, which otherwise makes wg-quick abort.
RUN sed -i \
      's@sysctl -q net.ipv4.conf.all.src_valid_mark=1@sysctl -q net.ipv4.conf.all.src_valid_mark=1 2>/dev/null || true@' \
      /usr/bin/wg-quick

COPY supervisor.py /usr/local/bin/proxy-supervisor
RUN chmod +x /usr/local/bin/proxy-supervisor

EXPOSE 8888 8889

ENTRYPOINT ["/usr/local/bin/proxy-supervisor"]
