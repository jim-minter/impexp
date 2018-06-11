#!/bin/bash

import: generate
	CGO_ENABLED=0 go build ./cmd/import

generate:
	go generate ./pkg/...

image: import
	go get github.com/openshift/imagebuilder/cmd/imagebuilder
	imagebuilder -t docker.io/jimminter/import:latest .

push: image
	docker push docker.io/jimminter/import:latest

.PHONY: generate image import

