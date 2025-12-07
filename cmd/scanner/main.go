package main

import (
	"context"

	"offsec-scan-go/internal/adapters/host"
	"offsec-scan-go/internal/adapters/nmap"
	"offsec-scan-go/internal/adapters/subfinder"
	"offsec-scan-go/internal/usecase"
	"offsec-scan-go/pkg/logger"
)

func main() {
	var (
		log = logger.NewZeroLogger()
	)

	subfinderAdapter := subfinder.NewSubFinder()
	hostAdapter := host.NewHost()
	nmapAdapter := nmap.NewNmap(log)

	uc := usecase.NewBaseScanUseCase(
		"iconlimits.store",
		&subfinderAdapter,
		&hostAdapter,
		&nmapAdapter,
	)

	if err := uc.Execute(context.Background()); err != nil {
		log.Error(
			"Error executing usecase",
			logger.Field{Key: "error", Value: err},
		)
	}
}
