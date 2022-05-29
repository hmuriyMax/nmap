package main

import (
	"google.golang.org/grpc"
	"log"
	"net"
	api "nmap/pkg/nmap_api"
	"os"
	"strconv"
)

func main() {
	address := ":6000"
	_LOGLEVEL_ = 1
	if len(os.Args) > 1 {
		address = os.Args[1]
	}
	if len(os.Args) > 2 {
		atoi, err := strconv.Atoi(os.Args[2])
		if err != nil {
			log.Fatalf("Wrong arguement!")
		}
		_LOGLEVEL_ = atoi
	}

	s := grpc.NewServer()
	srv := &GRPCServer{}
	api.RegisterNetVulnServiceServer(s, srv)
	l, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal(err)
	}
	UnimpLog("NMAP server started at http://localhost:6000")
	//Started GRPC server
	err = s.Serve(l)
	if err != nil {
		log.Fatal(err)
	}
}
