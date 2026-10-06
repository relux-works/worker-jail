# worker-jail/go:2 — reference derived image with the Go toolchain.
FROM worker-jail/base:2
COPY --from=golang:1.25-trixie /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:$PATH
