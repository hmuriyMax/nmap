build:
	go build ./cmd/server
	./server
	rm server
	go mod tidy

tester:
	go build ./test/regular_tests
	./regular_tests
	rm regular_tests
	go mod tidy