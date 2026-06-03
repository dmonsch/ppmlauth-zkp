.PHONY: all build test clean tidy

all: build

build:
	go build ./...

zktool:
	go build -o zktool ./cmd/zktool

bench:
	go build -o bench ./cmd/bench

test:
	go test ./... -v

tidy:
	go mod tidy

clean:
	./scripts/clean.sh


