SHELL=/bin/zsh
APP_NAME=check-pwd
.DEFAULT_GOAL=help

.PHONY: install
install: build # install binary to $HOME
	@go install
	@echo 'check-pwd binary added to $$GOPATH/bin'

.PHONY: build
build: clean # build go binary
	@go build -o ./bin/${APP_NAME} main.go

.PHONY: clean
clean: # clean out legacy bins
	@go clean -i main.go

.PHONY: help
help: # shows help message
	@egrep -h '\s#\s' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?# "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
