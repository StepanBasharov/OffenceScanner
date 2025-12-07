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
	Ports    []int
	Services []Service
}

type Service struct {
	Name    string
	Version string
}

func (s *Scan) GetBaseInfo() {
	fmt.Printf("Scanning domain %s\n", s.MainDomain)
	fmt.Printf("Subdomains count: %d\n", len(s.SubDomains))
	for _, subdomain := range s.SubDomains {
		fmt.Println("IP addresses:", len(subdomain.IPs))
		fmt.Printf("Ports for domain %s: %d\n", subdomain.Domain, len(subdomain.Ports))
	}
}

type Scanner interface {
	Scan(ctx context.Context, scanData *Scan) error
	GetName() string
}
