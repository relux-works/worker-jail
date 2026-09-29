WORKERS_DOCKER := DOCKER_HOST=unix://$(HOME)/.colima/workers/docker.sock

.PHONY: build test vet cover image it

build:
	go build -o bin/worker-jail ./cmd/worker-jail

test:
	go test ./...

vet:
	go vet ./...

cover:
	go test -cover ./jail

image:
	$(WORKERS_DOCKER) docker build -t worker-jail/base:1 images/base
	$(WORKERS_DOCKER) docker build -t worker-jail/go:1 images/go

it:
	WJ_IT=1 go test ./jail -run Integration -count=1 -v
