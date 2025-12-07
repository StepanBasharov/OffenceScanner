package nmap

import (
	"context"
	"fmt"
	"offsec-scan-go/internal/domain"
	"offsec-scan-go/pkg/logger"
	"os"
	"os/exec"
	"sync"
)

type Nmap struct {
	Name string
	log  logger.Logger
}

type ErrNmap struct {
	err          error
	targetDomain string
}

func NewNmap(log logger.Logger) Nmap {
	return Nmap{
		Name: "nmap",
		log:  log,
	}
}

func (n *Nmap) GetName() string {
	return n.Name
}

func (n *Nmap) Scan(ctx context.Context, scanData *domain.Scan) error {
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

	return nil
}
