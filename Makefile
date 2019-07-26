GO=go
LDFLAGS=-X main.version=$$(git rev-parse --short HEAD)

all:
	$(GO) build -ldflags="$(LDFLAGS)"
