build:
	go build ./cmd/server
	./server
	rm server
	go mod tidy

tester:
	go build ./test/test1.go
	./test1
	rm test1
	go mod tidy