package usecase

import (
	"context"
	"offsec-scan-go/internal/domain"
)

type BaseScanUseCase struct {
	target   string
	scanners []domain.Scanner
}

func NewBaseScanUseCase(target string, scanners ...domain.Scanner) *BaseScanUseCase {
	return &BaseScanUseCase{
		target:   target,
		scanners: scanners,
	}
}

func (bs *BaseScanUseCase) Execute(ctx context.Context) error {
	scanData := domain.Scan{MainDomain: bs.target}

	for _, scanner := range bs.scanners {
		if err := scanner.Scan(ctx, &scanData); err != nil {
			return err
		}
		scanData.GetBaseInfo()
	}

	return nil
}
