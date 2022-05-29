package main

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	"nmap/pkg/nmap_api"
	"strings"
)

func main() {
	dial, err := grpc.Dial(":6000", grpc.WithInsecure())
	if err != nil {
		return
	}
	c := nmap_api.NewNetVulnServiceClient(dial)
	req := &nmap_api.CheckVulnRequest{
		Targets: []string{"localhost", "ts.mpei.ru", "pkg.go.dev/github.com/t94j0/nmap#section-readme"},
		TcpPort: []int32{80, 6000},
	}
	vuln, err := c.CheckVuln(context.Background(), req)
	if err != nil {
		return
	}
	for i, el := range vuln.GetResults() {
		ip := el.GetTarget()
		fmt.Printf("Result %d at ip %s:\n", i+1, ip)
		services := el.GetServices()
		for i, el := range services {
			name := el.GetName()
			vers := el.GetVersion()
			port := el.GetTcpPort()
			tsts := el.GetVulns()
			fmt.Printf("   Service %d:\n", i+1)
			fmt.Printf("   %s:%d v%s\n", name, port, vers)
			fmt.Printf("      %50s | CVSS\n", "ID")
			for _, el := range tsts {
				id := el.GetIdentifier()
				sc := el.GetCvssScore()
				fmt.Printf("      %50s |", id)
				fmt.Printf(" %5.2f\n", sc)
			}
			println()
		}
		fmt.Printf(strings.Repeat("=", 80))
		println()
	}
}
