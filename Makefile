ARCH=amd64
OS=linux
BASE=./simulation/base_dir
TARGET=./simulation/target_dir

all: build

build:
	@echo "Compiling src/fenrir.go into ./fenrir..."
	GOARCH=$(ARCH) GOOS=$(OS) go build -o fenrir src/fenrir.go

run:
	@echo "Running src/fenrir.go..."
	go run src/fenrir.go -b $(BASE) -t $(TARGET)

clean:
	@echo "Removing ./fenrir..."
	rm -f fenrir
	@echo "Removing conflicts.log..."
	rm -f conflicts.log
	@echo "Removing base_specific.log..."
	rm -f base_specific.log
	@echo "Removing target_specific.log..."
	rm -f target_specific.log

runll:
	@echo "Running parallel/fenrirll.go..."
	go run parallel/fenrirll.go -b $(BASE) -t $(TARGET)

buildll:
	@echo "Compiling parallel/fenrirll.go into ./fenrirll..."
	GOARCH=$(ARCH) GOOS=$(OS) go build -o fenrirll parallel/fenrirll.go