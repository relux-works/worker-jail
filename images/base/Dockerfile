# worker-jail/base:1 — the base image of every jailed call (docs/protocol.md). Base image v2 (v2.1): adds socat,
# the relay a call of a policy with egress (any network.mode but none) starts to its egress socket. The tag stays :1; rebuild it.
# No VOLUME, no USER, no ENTRYPOINT: the jail sets the user and mounts.
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates coreutils findutils procps tar make socat \
 && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 10001 worker && useradd -u 10001 -g 10001 -M -d /work/home -s /bin/bash worker \
 && mkdir -p /work /cache && chown 10001:10001 /work && chmod 0700 /work \
 && find / -xdev -perm /6000 -type f -exec chmod a-s {} +
ENV HOME=/work/home TMPDIR=/tmp LANG=C.UTF-8
