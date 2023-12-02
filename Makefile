.PHONY: test docs docker-image

test:
	go test -race -covermode atomic -coverprofile=cover.out ./... -v

	export PATH=$$PATH:`go env GOPATH`/bin; make -C rest-api test-doc
	diff docs-test/swagger.json docs/swagger.json
	diff docs-test/swagger.yaml docs/swagger.yaml

docs:
	export PATH=$$PATH:`go env GOPATH`/bin; make -C rest-api doc

docker-image:
	docker build -t goca-rest-api:latest .

lint:
	golangci-lint run -e gosec