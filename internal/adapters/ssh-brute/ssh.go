package sshbruteforce

import (
	"context"
	
	"offsec-scan-go/internal/domain"
)

const (
	SSH = "ssh"
)

type SSHBruteforcer struct {
	Name string
}

func NewSSHBruteforcer() *SSHBruteforcer {
	return &SSHBruteforcer{
		Name: "ssh-bruteforcer",
	}
}

func (sshb *SSHBruteforcer) Scan(ctx context.Context, scanData *domain.Scan) (chan domain.BruteforcePart, error) {
	for _, subdomain := range scanData.SubDomains {
		for _, services := range subdomain.Services {
			if services.Name == SSH {
				bruteCh := make(chan domain.BruteforcePart)

				go func() {
					defer close(bruteCh)

					userMapMock := map[string]string{
						"admin": "admin",
						"root":  "root",
						"dest":  "dest",
					}

					for k, v := range userMapMock {
						if k == "dest" && v == "dest" {
							bruteCh <- domain.BruteforcePart{
								Service:  services.Name,
								Domain:   subdomain.Domain,
								IP:       "0.0.0.0",
								Port:     services.Port,
								Username: k,
								Password: v,
								IsValid:  true,
							}

							return

						} else {
							bruteCh <- domain.BruteforcePart{
								Service:  services.Name,
								Domain:   subdomain.Domain,
								IP:       "0.0.0.0",
								Port:     services.Port,
								Username: k,
								Password: v,
								IsValid:  false,
							}
						}
					}
				}()

				return bruteCh, nil
			}
		}
	}

	return nil, nil
}

func (sshb *SSHBruteforcer) GetName() string {
	return sshb.Name
}

func (sshb *SSHBruteforcer) GetReport() error {
	return nil
}
