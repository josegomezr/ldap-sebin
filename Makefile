build:
	mkdir -p out/bin/
	go build -o out/bin/ldap-sebin ./cmd/ldap-sebin/

mod-tidy:
	go mod tidy

test:
	go test -v ./cmd/...
	go test -v ./internal/...

fmt:
	go fmt ./cmd/...
	go fmt ./internal/...
