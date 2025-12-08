package nmap

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"

	"offsec-scan-go/internal/domain"
	"offsec-scan-go/pkg/logger"
)

type Nmap struct {
	Name        string
	log         logger.Logger
	ScanResults map[string][]domain.Service
}

type ErrNmap struct {
	err          error
	targetDomain string
}

func NewNmap(log logger.Logger) *Nmap {
	return &Nmap{
		Name:        "nmap",
		log:         log,
		ScanResults: make(map[string][]domain.Service),
	}
}

func (n *Nmap) GetName() string {
	return n.Name
}

func (n *Nmap) Scan(ctx context.Context, scanData *domain.Scan) (chan domain.BruteforcePart, error) {
	var (
		wg           sync.WaitGroup
		errChan      = make(chan ErrNmap, len(scanData.SubDomains))
		mutex        sync.Mutex
		subdomainMap = make(map[string]*domain.SubDomain)
	)

	for i := range scanData.SubDomains {
		subdomainMap[scanData.SubDomains[i].Domain] = &scanData.SubDomains[i]
	}

	for _, subdomain := range scanData.SubDomains {
		wg.Add(1)
		go func(wg *sync.WaitGroup, domainName string) {
			var (
				nmapScanFileName = fmt.Sprintf("/tmp/nmap_scan_%s.xml", domainName)
				nmapCtx, cancel  = context.WithCancel(ctx)
			)

			defer wg.Done()
			defer cancel()

			cmd := exec.CommandContext(
				nmapCtx,
				"nmap",
				"-sC",
				"-sV",
				"-oX",
				nmapScanFileName,
				domainName,
			)

			if err := cmd.Run(); err != nil {
				errChan <- ErrNmap{
					err:          fmt.Errorf("nmap scan failed: %w", err),
					targetDomain: domainName,
				}
				return
			}

			xmlContent, err := os.ReadFile(nmapScanFileName)
			if err != nil {
				errChan <- ErrNmap{
					err:          fmt.Errorf("failed to read nmap XML file: %w", err),
					targetDomain: domainName,
				}
				return
			}

			services, err := ParseNmapXML(xmlContent)
			if err != nil {
				errChan <- ErrNmap{
					err:          fmt.Errorf("failed to parse nmap XML: %w", err),
					targetDomain: domainName,
				}
				return
			}

			mutex.Lock()
			if sd, exists := subdomainMap[domainName]; exists {
				sd.Services = services
			}
			n.ScanResults[domainName] = services
			mutex.Unlock()

			if err := os.Remove(nmapScanFileName); err != nil {
				n.log.Error(
					"error removing nmap scanfile",
					logger.Field{Key: "error", Value: err},
					logger.Field{Key: "targetDomain", Value: domainName},
					logger.Field{Key: "scanner", Value: n.GetName()},
				)
			}
		}(&wg, subdomain.Domain)
	}

	go func() {
		wg.Wait()
		close(errChan)
	}()

	for err := range errChan {
		if err.err != nil {
			n.log.Error(
				"error scanning nmap scan",
				logger.Field{Key: "error", Value: err.err},
				logger.Field{Key: "targetDomain", Value: err.targetDomain},
				logger.Field{Key: "scanner", Value: n.GetName()},
			)
		}
	}

	return nil, nil
}

func (n *Nmap) GetReport() error {
	if len(n.ScanResults) == 0 {
		return nil
	}

	totalServices := 0
	for _, services := range n.ScanResults {
		totalServices += len(services)
	}
	totalPorts := totalServices

	fmt.Printf("\n")
	fmt.Printf("╔═══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║                    NMAP SCAN REPORT                            ║\n")
	fmt.Printf("╚═══════════════════════════════════════════════════════════════╝\n")
	fmt.Printf("\n")
	fmt.Printf("Total Targets Scanned: %d\n", len(n.ScanResults))
	fmt.Printf("Total Services Found: %d\n", totalServices)
	fmt.Printf("Total Open Ports: %d\n", totalPorts)
	fmt.Printf("\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("\n")

	idx := 1
	for domain, services := range n.ScanResults {
		fmt.Printf("┌─ Target #%d: %s\n", idx, domain)

		if len(services) > 0 {
			fmt.Printf("│  Open Ports & Services (%d found):\n", len(services))
			for i, service := range services {
				fmt.Printf("│    └─ [%d] Port: %-5d | Service: %-15s", i+1, service.Port, service.Name)
				if service.Version != "" {
					fmt.Printf(" | Version: %s\n", service.Version)
				} else {
					fmt.Printf("\n")
				}
			}
		} else {
			fmt.Printf("│  Open Ports: None found\n")
		}

		if idx < len(n.ScanResults) {
			fmt.Printf("│\n")
		} else {
			fmt.Printf("└\n")
		}
		idx++
	}

	fmt.Printf("\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("\n")

	return nil
}
