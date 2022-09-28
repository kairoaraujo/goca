.PHONY: check_swag doc test-doc run build

check_swag:
	which swag || GO111MODULE=off go get -u github.com/swaggo/swag/cmd/swag

doc: check_swag
	swag init --output ../docs/ -parseDependency=true

test-doc:
	swag init --output ../docs-test/ -parseDependency=true

run:
	go run main.go

build:
	go build main.go
