ORG := keratin
PROJECT := authn-go
NAME := $(ORG)/$(PROJECT)
VERSION := 1.1.0

# Run tests
.PHONY: test
test:
	go test ./...

# Cut a release of the current version.
.PHONY: release
release: test
	git tag v$(VERSION)
	git push
	git push --tags
	open https://github.com/$(NAME)/releases/tag/v$(VERSION)

lint:
	@which golangci-lint > /dev/null || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin
	golangci-lint run --config .golangci.yml