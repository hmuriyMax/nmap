build:
	go build ./cmd/server
	./server :6000 1
	rm server
	go mod tidy

tester:
	go build ./test/regular_tests
	./regular_tests :6000
	rm regular_tests
	go mod tidy