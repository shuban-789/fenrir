ARCH=amd64
OS=linux

all: build

build:
	@echo "Compiling src/fenrir.go into ./fenrir..."
	GOARCH=$(ARCH) GOOS=$(OS) go build -o fenrir src/fenrir.go

run:
	@echo "Running src/fenrir.go..."
	go run src/fenrir.go

clean:
	@echo "Removing ./fenrir..."
	rm -f fenrir
