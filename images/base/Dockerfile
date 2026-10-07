# remote-workplace/base:2 — the base image of every workplace call (docs/protocol.md), base image v2 (v2.1): adds socat,
# the relay a call of a policy with egress (any network.mode but none) starts to its egress socket. The labels are
# inherited by derived images; provision, run and doctor check the egress-relay label for a policy with egress.
# No VOLUME, no USER, no ENTRYPOINT: the workplace sets the user and mounts.
FROM debian:trixie-slim
LABEL ai.relux.remote-workplace.base-image=2 ai.relux.remote-workplace.egress-relay=socat
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates coreutils findutils procps tar make socat \
 && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 10001 worker && useradd -u 10001 -g 10001 -M -d /work/home -s /bin/bash worker \
 && mkdir -p /work /cache && chown 10001:10001 /work && chmod 0700 /work \
 && find / -xdev -perm /6000 -type f -exec chmod a-s {} +
ENV HOME=/work/home TMPDIR=/tmp LANG=C.UTF-8
