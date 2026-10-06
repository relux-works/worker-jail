WORKERS_DOCKER := DOCKER_HOST=unix://$(HOME)/.colima/workers/docker.sock

.PHONY: build test vet cover image image-redteam it redteam

build:
	go build -o bin/worker-jail ./cmd/worker-jail
	go build -o bin/wj-egress ./cmd/wj-egress

test:
	go test ./...

vet:
	go vet ./...

cover:
	go test -cover ./jail ./egress

image:
	$(WORKERS_DOCKER) docker build -t worker-jail/base:1 images/base
	$(WORKERS_DOCKER) docker build -t worker-jail/go:1 images/go
	$(WORKERS_DOCKER) docker build -f images/egress/Dockerfile -t worker-jail/egress:1 .

it:
	WJ_IT=1 go test ./jail -run Integration -count=1 -v

# Test-only adversarial image; never use it for real workers.
image-redteam:
	$(WORKERS_DOCKER) docker build -t worker-jail/redteam:1 images/redteam

redteam:
	WJ_REDTEAM=1 go test ./jail -run RedTeam -count=1 -v -timeout 30m
