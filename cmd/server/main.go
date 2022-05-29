package main

import (
	"google.golang.org/grpc"
	"log"
	"net"
	api "nmap/pkg/nmap_api"
)

func main() {
	s := grpc.NewServer()
	srv := &GRPCServer{}
	api.RegisterNetVulnServiceServer(s, srv)
	l, err := net.Listen("tcp", ":6000")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("NMAP server started at http://localhost:6000")
	//Started GRPC server
	err = s.Serve(l)
	if err != nil {
		log.Fatal(err)
	}
}
