PKGS := $(shell glide nv)
ORG := keratin
PROJECT := authn-go
NAME := $(ORG)/$(PROJECT)
VERSION := 0.1.0

.PHONY: clean
clean:
	rm -rf vendor

# Fetch dependencies
vendor:
	glide install

# Run tests
.PHONY: test
test: vendor
	go test $(PKGS)

# Cut a release of the current version.
.PHONY: release
release: test
	git tag v$(VERSION)
	git push --tags
	open https://github.com/$(NAME)/releases/tag/v$(VERSION)
