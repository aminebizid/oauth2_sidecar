##################################################
# Variables                                      #
##################################################
ARCH?=amd64
CGO?=0
TARGET_OS?=linux

##################################################
# Variables                                      #
##################################################

GIT_VERSION = $(shell git describe --always --abbrev=7)
GIT_COMMIT  = $(shell git rev-list -1 HEAD)
DATE        = $(shell date -u +"%Y.%m.%d.%H.%M.%S")

##################################################
# Build                                          #
##################################################
.PHONY: build
build:
	CGO_ENABLED=$(CGO) GOOS=$(TARGET_OS) GOARCH=$(ARCH) go build \
		-ldflags "-X main.GitCommit=$(GIT_COMMIT)" \
		-o dist/oauth2_sidecar \
		cmd/main.go