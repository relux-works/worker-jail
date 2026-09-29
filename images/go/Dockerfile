# worker-jail/go:1 — reference derived image with the Go toolchain.
FROM worker-jail/base:1
COPY --from=golang:1.25-trixie /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:$PATH
