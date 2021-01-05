check_swag:
	which swag || GO111MODULE=off go get -u github.com/swaggo/swag/cmd/swag

doc: check_swag
	swag init -parseDependency=true

run:
	go run main.go

build:
	go build main.go