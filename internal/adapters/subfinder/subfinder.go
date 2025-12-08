package subfinder

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"offsec-scan-go/internal/domain"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

type SubFinder struct {
	Name            string
	FoundSubdomains []string
}

func NewSubFinder() *SubFinder {
	return &SubFinder{
		Name: "subfinder",
	}
}

func (sf *SubFinder) GetName() string {
	return sf.Name
}

func (sf *SubFinder) Scan(ctx context.Context, scanData *domain.Scan) (chan domain.BruteforcePart, error) {
	options := &runner.Options{
		Timeout:            30,
		MaxEnumerationTime: 10,
		Threads:            10,
		Silent:             true,
		NoColor:            true,
	}

	subfinder, err := runner.NewRunner(options)
	if err != nil {
		return nil, fmt.Errorf("could not create subfinder %w", err)
	}

	output := &bytes.Buffer{}
	var sourceMap map[string]map[string]struct{}

	if sourceMap, err = subfinder.EnumerateSingleDomainWithCtx(ctx, scanData.MainDomain, []io.Writer{output}); err != nil {
		return nil, fmt.Errorf("could not enumerate subfinder %w", err)
	}

	subdomainsFromSubfinder := make([]domain.SubDomain, 0)

	for subdomain, sources := range sourceMap {
		sourcesList := make([]string, 0, len(sources))
		for source := range sources {
			sourcesList = append(sourcesList, source)
		}

		subdomainsFromSubfinder = append(subdomainsFromSubfinder, domain.SubDomain{
			Domain: subdomain,
		})
	}

	subdomainsFromSubfinder = append(subdomainsFromSubfinder, domain.SubDomain{
		Domain: scanData.MainDomain,
	})

	scanData.SubDomains = subdomainsFromSubfinder

	foundDomains := make([]string, 0, len(subdomainsFromSubfinder))
	for _, sd := range subdomainsFromSubfinder {
		foundDomains = append(foundDomains, sd.Domain)
	}
	sf.FoundSubdomains = foundDomains

	return nil, nil
}

func (sf *SubFinder) GetReport() error {
	if len(sf.FoundSubdomains) == 0 {
		return nil
	}

	fmt.Printf("\n")
	fmt.Printf("╔═══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║                  SUBFINDER SCAN REPORT                         ║\n")
	fmt.Printf("╚═══════════════════════════════════════════════════════════════╝\n")
	fmt.Printf("\n")
	fmt.Printf("Total Subdomains Found: %d\n", len(sf.FoundSubdomains))
	fmt.Printf("\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("\n")

	for idx, subdomain := range sf.FoundSubdomains {
		fmt.Printf("  [%d] %s\n", idx+1, subdomain)
	}

	fmt.Printf("\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("\n")

	return nil
}
