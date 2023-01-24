.PHONY: all
all:
	go build .

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: clean
clean:
	rm -f capejail
