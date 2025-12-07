package host

import (
	"context"
	"net"
	"offsec-scan-go/internal/domain"
	"time"
)

type Host struct {
	Name string
}

func NewHost() Host {
	return Host{
		Name: "host",
	}
}

func (h *Host) GetName() string {
	return h.Name
}

func (h *Host) Scan(ctx context.Context, scanData *domain.Scan) error {
	availableDomains := make([]domain.SubDomain, 0)

	for _, subdomain := range scanData.SubDomains {
		hostCtx, cancel := context.WithTimeout(ctx, 2*time.Second)

		addrs, err := net.DefaultResolver.LookupIPAddr(hostCtx, subdomain.Domain)
		if err != nil || len(addrs) == 0 {
			cancel()
			continue
		}

		ips := make([]net.IPAddr, 0)

		for _, a := range addrs {
			ips = append(ips, a)
		}

		subdomain.IPs = ips

		availableDomains = append(availableDomains, subdomain)

		cancel()
	}

	scanData.SubDomains = availableDomains

	return nil
}
