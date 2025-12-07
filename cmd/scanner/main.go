package main

import (
	"context"
	"log"
	"offsec-scan-go/internal/adapters/host"
	"offsec-scan-go/internal/adapters/subfinder"
	"offsec-scan-go/internal/usecase"
)

func main() {
	subfinderAdapter := subfinder.NewSubFinder()
	hostAdapter := host.NewHost()

	uc := usecase.NewBaseScanUseCase(
		"equip.ru",
		&subfinderAdapter,
		&hostAdapter,
	)

	if err := uc.Execute(context.Background()); err != nil {
		log.Fatal(err)
	}
}
