package usecase

import (
	"context"
	"fmt"
	"sync"

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
	var (
		wg sync.WaitGroup
	)

	scanData := domain.Scan{MainDomain: bs.target}

	for _, scanner := range bs.scanners {
		bruteChan, err := scanner.Scan(ctx, &scanData)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}

		if bruteChan != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()

				for bruteData := range bruteChan {
					if bruteData.IsValid {
						fmt.Printf(
							"Valid: %s - %s - %s:%d %s@%s \n",
							bruteData.Service,
							bruteData.Domain,
							bruteData.IP,
							bruteData.Port,
							bruteData.Username,
							bruteData.Password,
						)
					}
				}
			}()
		}

		if errGetReport := scanner.GetReport(); errGetReport != nil {
			return fmt.Errorf("get report: %w", errGetReport)
		}
	}

	wg.Wait()

	scanData.GetBaseInfo()

	return nil
}
