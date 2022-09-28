.PHONY: test docs docker-image

test:
	go test -covermode=count -coverprofile=count.out -v $(go list ./... | grep -v /docs-test/)

	export PATH=$$PATH:`go env GOPATH`/bin; make -C rest-api test-doc
	diff docs-test/swagger.json docs/swagger.json
	diff docs-test/swagger.yaml docs/swagger.yaml

docs:
	export PATH=$$PATH:`go env GOPATH`/bin; make -C rest-api doc

docker-image:
	docker build -t goca-rest-api:latest .

lint:
	if [ ! -f ./bin/golangci-lint ] ; \
	then \
		curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.49.0; \
	fi;
	./bin/golangci-lint run -e gosec