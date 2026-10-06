# worker-jail/egress:1 — the egress service wj-egress (docs/design/v2/egress.md), v2.1 part A: network mode modules.
# Built from the repository root (`make image`): docker build -f images/egress/Dockerfile -t worker-jail/egress:1 .
# A static binary in an empty image: CA certificates, the binary and the three volume mount points; no shell, no VOLUME.
# It runs as uid 10002. The mount points' owners become the volumes' owners when Docker first mounts an empty volume:
# sock and cache belong to the service; policy belongs to uid 10001, which the jail's hardened policy calls write as.
FROM golang:1.25-trixie AS build
WORKDIR /src
COPY go.mod ./
COPY jail ./jail
COPY egress ./egress
COPY cmd/wj-egress ./cmd/wj-egress
RUN CGO_ENABLED=0 go build -trimpath -ldflags=-s -o /out/wj-egress ./cmd/wj-egress \
 && mkdir -p /out/sock /out/policy /out/cache && chmod 0755 /out/sock /out/policy && chmod 0700 /out/cache

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/wj-egress /usr/local/bin/wj-egress
COPY --from=build --chown=10002:10002 /out/sock /egress/sock
COPY --from=build --chown=10001:10001 /out/policy /egress/policy
COPY --from=build --chown=10002:10002 /out/cache /egress/cache
ENV PATH=/usr/local/bin
USER 10002:10002
ENTRYPOINT ["/usr/local/bin/wj-egress"]
CMD ["serve", "--sockroot", "/egress/sock", "--policydir", "/egress/policy", "--cachedir", "/egress/cache"]
