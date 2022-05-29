package main

import (
	"context"
	"google.golang.org/grpc"
	"log"
	"nmap/pkg/nmap_api"
)

func main() {
	//Connecting to GRPC server
	dial, err := grpc.Dial(":6000", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Could not connect to server: %s", err)
		return
	}

	//Creating request for server
	c := nmap_api.NewNetVulnServiceClient(dial)

	req, err := getReqFromFile("test.csv")
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
}
