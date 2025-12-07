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
	Name string
}

func NewSubFinder() SubFinder {
	return SubFinder{
		Name: "subfinder",
	}
}

func (sf *SubFinder) GetName() string {
	return sf.Name
}

func (sf *SubFinder) Scan(ctx context.Context, scanData *domain.Scan) error {
	options := &runner.Options{
		Timeout:            30,
		MaxEnumerationTime: 10,
		Threads:            10,
		Silent:             true,
		NoColor:            true,
	}

	subfinder, err := runner.NewRunner(options)
	if err != nil {
		return fmt.Errorf("could not create subfinder %w", err)
	}

	output := &bytes.Buffer{}
	var sourceMap map[string]map[string]struct{}

	if sourceMap, err = subfinder.EnumerateSingleDomainWithCtx(ctx, scanData.MainDomain, []io.Writer{output}); err != nil {
		return fmt.Errorf("could not enumerate subfinder %w", err)
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

	return nil
}
