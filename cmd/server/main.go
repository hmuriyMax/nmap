package main

import (
	"context"
	"fmt"
	nmap "github.com/Ullaakut/nmap/v2"
	"google.golang.org/grpc"
	"log"
	"net"
	api "nmap/pkg/nmap_api"
	"strconv"
)

type GRPCServer struct{}

func GetVulnScript(port *nmap.Port) nmap.Script {
	for _, scr := range port.Scripts {
		if scr.ID == "vulners" {
			return scr
		}
	}
	log.Printf("Script not found")
	return nmap.Script{}
}

func getByKey(table []nmap.Element, key string) string {
	for _, el := range table {
		if el.Key == key {
			return el.Value
		}
	}
	log.Printf("Nothing found by key %s", key)
	return ""
}

func (s *GRPCServer) CheckVuln(_ context.Context, req *api.CheckVulnRequest) (*api.CheckVulnResponse, error) {
	targets, tcp_ports := req.GetTargets(), req.GetTcpPort()
	var strPorts string
	for i, el := range tcp_ports {
		if i > 0 {
			strPorts += ", "
		}
		strPorts += fmt.Sprint(el)
	}
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(targets...),
		nmap.WithPorts(strPorts),
		nmap.WithServiceInfo(),
		nmap.WithScripts("vulners"),
	)
	if err != nil {
		log.Fatalf("Create error: %s", err)
		return nil, err
	}
	log.Printf("Scan begun")
	run, _, err := scanner.Run()
	log.Printf("Scan finished")
	if err != nil {
		log.Fatalf("Running error: %s", err)
		return nil, err
	}

	log.Printf("Started parsing results")
	var res api.CheckVulnResponse
	for _, host := range run.Hosts {
		var nhost api.TargetResult
		nhost.Target = host.Addresses[0].Addr

		for _, serv := range host.Ports {
			var nserv api.Service
			nserv.Name = serv.Service.Product
			nserv.Version = serv.Service.Version
			nserv.TcpPort = int32(serv.ID)

			if len(serv.Scripts) > 0 {
				for _, vuln := range GetVulnScript(&serv).Tables[0].Tables {
					var nvuln api.Vulnerability
					nvuln.Identifier = getByKey(vuln.Elements, "id")
					float, err := strconv.ParseFloat(getByKey(vuln.Elements, "cvss"), 10)
					if err != nil {
						log.Printf("Formatting error: %s", err)
					} else {
						nvuln.CvssScore = float32(float)
					}
					nserv.Vulns = append(nserv.Vulns, &nvuln)
				}
			}
			nhost.Services = append(nhost.Services, &nserv)
		}
		res.Results = append(res.Results, &nhost)
	}
	log.Printf("Finished parsing results")
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func main() {
	s := grpc.NewServer()
	srv := &GRPCServer{}
	api.RegisterNetVulnServiceServer(s, srv)
	l, err := net.Listen("tcp", ":6000")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("NMAP server started at http://localhost:6000")
	err = s.Serve(l)
	if err != nil {
		log.Fatal(err)
	}
}
