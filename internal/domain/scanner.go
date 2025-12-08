package domain

import (
	"context"
	"fmt"
	"net"
)

type Scan struct {
	MainDomain string
	SubDomains []SubDomain
}

type SubDomain struct {
	Domain   string
	IPs      []net.IPAddr
	Services []Service
}

type Service struct {
	Port    int
	Name    string
	Version string
}

func (s *Scan) GetBaseInfo() {
	if len(s.SubDomains) == 0 || s.SubDomains == nil {
		return
	}

	fmt.Printf("\n")
	fmt.Printf("╔═══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║                    SCAN RESULTS SUMMARY                       ║\n")
	fmt.Printf("╚═══════════════════════════════════════════════════════════════╝\n")
	fmt.Printf("\n")
	fmt.Printf("Main Domain: %s\n", s.MainDomain)
	fmt.Printf("Total Subdomains: %d\n", len(s.SubDomains))
	fmt.Printf("\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("\n")

	for idx, subdomain := range s.SubDomains {
		fmt.Printf("┌─ Subdomain #%d: %s\n", idx+1, subdomain.Domain)

		if len(subdomain.IPs) > 0 {
			fmt.Printf("│  IP Addresses:\n")
			for _, ip := range subdomain.IPs {
				fmt.Printf("│    └─ %s\n", ip.String())
			}
		} else {
			fmt.Printf("│  IP Addresses: None found\n")
		}

		if len(subdomain.Services) > 0 {
			fmt.Printf("│  Services (%d found):\n", len(subdomain.Services))
			for i, service := range subdomain.Services {
				fmt.Printf("│    └─ [%d] Port: %-5d | Service: %-15s", i+1, service.Port, service.Name)
				if service.Version != "" {
					fmt.Printf(" | Version: %s\n", service.Version)
				} else {
					fmt.Printf("\n")
				}
			}
		} else {
			fmt.Printf("│  Services: None found\n")
		}

		if idx < len(s.SubDomains)-1 {
			fmt.Printf("│\n")
		} else {
			fmt.Printf("└\n")
		}
	}

	fmt.Printf("\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("\n")
}

type Scanner interface {
	Scan(ctx context.Context, scanData *Scan) (chan BruteforcePart, error)
	GetName() string
	GetReport() error
}
