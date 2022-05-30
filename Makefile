build:
	go mod tidy
	go build ./cmd/server
	./server :6000 1
	rm server

tester:
	go mod tidy
	go build ./test/regular_tests
	./regular_tests :6000
	rm regular_tests