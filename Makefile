.PHONY: build clean install uninstall deb rpm release

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
VERSION_PKG := github.com/nigelbasa/lightr/cmd/lightr
LDFLAGS := -ldflags "-s -w -X $(VERSION_PKG).version=$(VERSION)"
BINARY := lightr
PREFIX ?= /usr/local

# Build targets
build:
	mkdir -p dist
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY) ./cmd/lightr

build-all: build-linux build-darwin build-windows

build-linux:
	mkdir -p dist
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64 ./cmd/lightr
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/$(BINARY)-linux-arm64 ./cmd/lightr

build-darwin:
	mkdir -p dist
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-amd64 ./cmd/lightr
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-arm64 ./cmd/lightr

build-windows:
	mkdir -p dist
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/$(BINARY)-windows-amd64.exe ./cmd/lightr

# Install/Uninstall (for local development)
install: build
	install -Dm755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BINARY)

# System-wide install (for packaging)
install-system: build
	install -Dm755 $(BINARY) $(DESTDIR)/usr/bin/$(BINARY)
	install -Dm644 packaging/lightr.service $(DESTDIR)/lib/systemd/system/lightr.service
	install -Dm644 config/config.minimal.yaml $(DESTDIR)/etc/lightr/config.yaml.example

# Package building
deb: build-linux
	@echo "Building .deb package..."
	mkdir -p dist/deb/DEBIAN
	mkdir -p dist/deb/usr/bin
	mkdir -p dist/deb/lib/systemd/system
	mkdir -p dist/deb/etc/lightr
	cp dist/$(BINARY)-linux-amd64 dist/deb/usr/bin/$(BINARY)
	cp packaging/lightr.service dist/deb/lib/systemd/system/
	cp config/config.minimal.yaml dist/deb/etc/lightr/config.yaml.example
	chmod 755 dist/deb/usr/bin/$(BINARY)
	sed 's/{{VERSION}}/$(VERSION)/g' packaging/debian/control > dist/deb/DEBIAN/control
	cp packaging/debian/postinst dist/deb/DEBIAN/
	cp packaging/debian/prerm dist/deb/DEBIAN/
	cp packaging/debian/postrm dist/deb/DEBIAN/
	chmod 755 dist/deb/DEBIAN/postinst dist/deb/DEBIAN/prerm dist/deb/DEBIAN/postrm
	dpkg-deb --build dist/deb dist/$(BINARY)_$(VERSION)_amd64.deb
	@echo "Package built: dist/$(BINARY)_$(VERSION)_amd64.deb"

deb-arm64: 
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/$(BINARY)-linux-arm64 ./cmd/lightr
	@echo "Building .deb package for arm64..."
	mkdir -p dist/deb-arm64/DEBIAN
	mkdir -p dist/deb-arm64/usr/bin
	mkdir -p dist/deb-arm64/lib/systemd/system
	mkdir -p dist/deb-arm64/etc/lightr
	cp dist/$(BINARY)-linux-arm64 dist/deb-arm64/usr/bin/$(BINARY)
	cp packaging/lightr.service dist/deb-arm64/lib/systemd/system/
	cp config/config.minimal.yaml dist/deb-arm64/etc/lightr/config.yaml.example
	chmod 755 dist/deb-arm64/usr/bin/$(BINARY)
	sed 's/{{VERSION}}/$(VERSION)/g; s/Architecture: amd64/Architecture: arm64/g' packaging/debian/control > dist/deb-arm64/DEBIAN/control
	cp packaging/debian/postinst dist/deb-arm64/DEBIAN/
	cp packaging/debian/prerm dist/deb-arm64/DEBIAN/
	cp packaging/debian/postrm dist/deb-arm64/DEBIAN/
	chmod 755 dist/deb-arm64/DEBIAN/postinst dist/deb-arm64/DEBIAN/prerm dist/deb-arm64/DEBIAN/postrm
	dpkg-deb --build dist/deb-arm64 dist/$(BINARY)_$(VERSION)_arm64.deb
	@echo "Package built: dist/$(BINARY)_$(VERSION)_arm64.deb"

rpm: build-linux
	@echo "Building .rpm package requires rpmbuild..."
	@echo "Consider using 'nfpm' for cross-platform packaging"

# Clean
clean:
	rm -f $(BINARY)
	rm -rf dist/

# Test
test:
	go test -v ./...

# Release (creates all artifacts)
release: clean build-all deb deb-arm64
	@echo "Release artifacts in dist/"
	ls -la dist/
