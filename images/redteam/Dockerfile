# worker-jail/redteam:1 — TEST-ONLY adversarial image for the red-team suite (docs/protocol.md section 12).
# It deliberately ships sudo (NOPASSWD for worker), a setuid-root binary and network tools, so the suite
# can prove that the jail's runtime flags make them useless. Never use this image for real workers.
FROM worker-jail/base:1
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl netcat-openbsd iproute2 libcap2-bin sudo \
 && rm -rf /var/lib/apt/lists/* \
 && echo 'worker ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/worker && chmod 0440 /etc/sudoers.d/worker \
 && cp /usr/bin/id /usr/local/bin/suid-id && chown root:root /usr/local/bin/suid-id && chmod 4755 /usr/local/bin/suid-id
