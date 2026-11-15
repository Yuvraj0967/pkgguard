.PHONY: test vet plugin cli

test:
	go test ./...

vet:
	go vet ./...

cli:
	go build -o bin/pkgguard ./cmd/pkgguard

# Native Bifrost plugin (Linux/macOS only; needs a dynamically linked Bifrost build to load it).
plugin:
	CGO_ENABLED=1 go build -buildmode=plugin -o build/pkgguard.so ./plugin
