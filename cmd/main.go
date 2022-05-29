package main

import (
	"context"
	"fmt"
	nmap "github.com/Ullaakut/nmap/v2"
	"log"
	api "nmap/pkg/nmap_api"
)

type GRPCServer struct{}

func (s *GRPCServer) CheckVuln(_ context.Context, req *api.CheckVulnRequest) (*api.CheckVulnResponse, error) {
	targets, tcp_ports := req.GetTargets(), req.GetTcpPort()
	var strPorts string
	for el, i := range tcp_ports {
		if i > 0 {
			strPorts += ", "
		}
		strPorts += fmt.Sprint(el)
	}
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(targets...),
		nmap.WithPorts(strPorts),
		nmap.WithScripts("vulners"),
	)
	if err != nil {
		log.Fatalf("Create error: %s", err)
		return nil, err
	}
	run, _, err := scanner.Run()
	if err != nil {
		log.Fatalf("Running error: %s", err)
		return nil, err
	}
	print(run.XMLOutputVersion)
	return nil, nil
}

func main() {

}
