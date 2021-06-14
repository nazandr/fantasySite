.PHONY: build
build:
	go build -v ./cmd/site

.PHONY: test
test:
	go test -v -race -timeout 30s ./...


.DEFAULT_GOAL := build