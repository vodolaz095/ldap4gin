deps:
	# install all dependencies required for running application

	# reveal golang information
	go version
	go env

	# installing golint code quality tools and checking, if it can be started
	cd ~ && go get -u golang.org/x/lint/golint
	golint

	# installing golang dependencies using golang modules
	go mod tidy # ensure go.mod is sane
	go mod verify # ensure dependencies are present

start: run

run:
	cd example && go run example.go

test: check

lint:
	gofmt  -w=true -s=true -l=true ./
	golint ./...
	go vet ./...

check: lint
	go test -v ./...

clean:
	go clean