WORKERS_DOCKER := DOCKER_HOST=unix://$(HOME)/.colima/workers/docker.sock

.PHONY: build test vet cover image image-redteam it redteam

build:
	go build -o bin/remote-workplace ./cmd/remote-workplace
	go build -o bin/rwp-egress ./cmd/rwp-egress

test:
	go test ./...

vet:
	go vet ./...

cover:
	go test -cover ./workplace ./egress

image:
	$(WORKERS_DOCKER) docker build -t remote-workplace/base:2 images/base
	$(WORKERS_DOCKER) docker build -t remote-workplace/go:2 images/go
	$(WORKERS_DOCKER) docker build -f images/egress/Dockerfile -t remote-workplace/egress:1 .

it:
	RWP_IT=1 go test ./workplace -run Integration -count=1 -v

# Test-only adversarial image; never use it for real workers.
image-redteam:
	$(WORKERS_DOCKER) docker build -t remote-workplace/redteam:2 images/redteam

redteam:
	RWP_REDTEAM=1 go test ./workplace -run RedTeam -count=1 -v -timeout 30m
