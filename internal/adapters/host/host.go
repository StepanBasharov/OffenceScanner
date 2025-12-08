package host

import (
	"context"
	"fmt"
	"net"
	"time"

	"offsec-scan-go/internal/domain"
)

type Host struct {
	Name                   string
	AvailableDomainsReport []reportDomain
}

type reportDomain struct {
	domain      string
	isAvailable bool
}

func NewHost() *Host {
	return &Host{
		Name: "host",
	}
}

func (h *Host) GetName() string {
	return h.Name
}

func (h *Host) Scan(ctx context.Context, scanData *domain.Scan) (chan domain.BruteforcePart, error) {
	availableDomains := make([]domain.SubDomain, 0)
	availableDomainsReport := make([]reportDomain, 0)

	for _, subdomain := range scanData.SubDomains {
		hostCtx, cancel := context.WithTimeout(ctx, 2*time.Second)

		addrs, err := net.DefaultResolver.LookupIPAddr(hostCtx, subdomain.Domain)
		if err != nil || len(addrs) == 0 {
			availableDomainsReport = append(availableDomainsReport, reportDomain{
				domain:      subdomain.Domain,
				isAvailable: false,
			})
			cancel()
			continue
		}

		ips := make([]net.IPAddr, 0)

		for _, a := range addrs {
			ips = append(ips, a)
		}

		subdomain.IPs = ips

		availableDomains = append(availableDomains, subdomain)
		availableDomainsReport = append(availableDomainsReport, reportDomain{
			domain:      subdomain.Domain,
			isAvailable: true,
		})

		cancel()
	}

	scanData.SubDomains = availableDomains
	h.AvailableDomainsReport = availableDomainsReport

	return nil, nil
}

func (h *Host) GetReport() error {
	if len(h.AvailableDomainsReport) == 0 {
		return nil
	}

	availableCount := 0
	unavailableCount := 0

	for _, report := range h.AvailableDomainsReport {
		if report.isAvailable {
			availableCount++
		} else {
			unavailableCount++
		}
	}

	fmt.Printf("\n")
	fmt.Printf("╔═══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║                    HOST RESOLUTION REPORT                      ║\n")
	fmt.Printf("╚═══════════════════════════════════════════════════════════════╝\n")
	fmt.Printf("\n")
	fmt.Printf("Total Domains Checked: %d\n", len(h.AvailableDomainsReport))
	fmt.Printf("Available: %d\n", availableCount)
	fmt.Printf("Unavailable: %d\n", unavailableCount)
	fmt.Printf("\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("\n")

	for idx, report := range h.AvailableDomainsReport {
		status := "UNAVAILABLE"
		if report.isAvailable {
			status = "AVAILABLE"
		}
		fmt.Printf("  [%d] %-40s [%s]\n", idx+1, report.domain, status)
	}

	fmt.Printf("\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("\n")

	return nil
}
