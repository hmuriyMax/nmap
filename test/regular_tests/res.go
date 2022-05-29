package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"nmap/pkg/nmap_api"
	"os"
	"strconv"
	"strings"
)

//Parsing .csv file
func getReqFromFile(filename string) (*nmap_api.CheckVulnRequest, error) {
	csvFile, _ := os.Open(filename)
	defer csvFile.Close()
	reader := csv.NewReader(bufio.NewReader(csvFile))
	targets, err := reader.Read()
	if err != nil {
		return nil, err
	}
	cont, err := reader.Read()
	if err != nil {
		return nil, err
	}
	var portSlice []int32
	for _, el := range cont {
		if el != "" {
			nint, err := strconv.ParseInt(el, 10, 0)
			if err != nil {
				return nil, err
			}
			portSlice = append(portSlice, int32(nint))
		}
	}
	req := &nmap_api.CheckVulnRequest{
		Targets: targets,
		TcpPort: []int32{80},
	}
	return req, nil
}

func printResults(resp *nmap_api.CheckVulnResponse) {
	for i, el := range resp.GetResults() {
		ip := el.GetTarget()
		fmt.Printf("Result %d at ip %s:\n", i+1, ip)
		services := el.GetServices()
		for i, el := range services {
			fmt.Printf("   Service %d:\n", i+1)
			name := el.GetName()
			vers := el.GetVersion()
			port := el.GetTcpPort()
			vlns := el.GetVulns()
			if name == "" {
				fmt.Printf("   Name not detected!\n")
			} else {
				fmt.Printf("   Name:    %s\n", name)
			}
			fmt.Printf("   Port:    %d\n", port)
			if vers == "" {
				fmt.Printf("   Version not detected!\n")
			} else {
				fmt.Printf("   Version: %s\n", vers)
			}

			//Table for vulners
			if len(vlns) > 1 {
				fmt.Printf("      %50s | CVSS\n", "ID")
				for _, el := range vlns {
					id := el.GetIdentifier()
					sc := el.GetCvssScore()
					fmt.Printf("      %50s |", id)
					fmt.Printf(" %5.2f\n", sc)
				}
			} else {
				fmt.Printf("   No vulners found :)")
			}
			println()
		}
		fmt.Printf(strings.Repeat("=", 80))
		println()
	}
}
