package main

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"nmap/pkg/nmap_api"
	"os"
)

func main() {
	address := ":6000"
	if len(os.Args) > 1 {
		address = os.Args[1]
	}

	//Connecting to GRPC server
	dial, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Could not connect to server: %s", err)
		return
	}

	//Creating request for server
	c := nmap_api.NewNetVulnServiceClient(dial)

	req, err := getReqFromFile("test.csv")
	//TODO: automatically test many files. Replace .csv with?
	if err != nil {
		log.Fatalf("Could not parse .csv file: %s", err)
		return
	}

	//Sending request
	vuln, err := c.CheckVuln(context.Background(), req)
	if err != nil {
		return
	}

	//Printing results
	printResults(vuln)
	//TODO: count time for tests
}
