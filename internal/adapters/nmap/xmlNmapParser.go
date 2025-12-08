package nmap

import (
	"encoding/xml"
	"fmt"
	"strconv"

	"offsec-scan-go/internal/domain"
)

type nmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []host   `xml:"host"`
}

type host struct {
	XMLName xml.Name `xml:"host"`
	Ports   ports    `xml:"ports"`
}

type ports struct {
	XMLName xml.Name `xml:"ports"`
	Port    []port   `xml:"port"`
}

type port struct {
	XMLName xml.Name `xml:"port"`
	PortID  string   `xml:"portid,attr"`
	State   state    `xml:"state"`
	Service service  `xml:"service"`
}

type state struct {
	XMLName xml.Name `xml:"state"`
	State   string   `xml:"state,attr"`
}

type service struct {
	XMLName xml.Name `xml:"service"`
	Name    string   `xml:"name,attr"`
	Product string   `xml:"product,attr"`
	Version string   `xml:"version,attr"`
}

func ParseNmapXML(xmlData []byte) ([]domain.Service, error) {
	var nmapRun nmapRun
	if err := xml.Unmarshal(xmlData, &nmapRun); err != nil {
		return nil, fmt.Errorf("failed to parse nmap XML: %w", err)
	}

	var servicesList []domain.Service

	for _, host := range nmapRun.Hosts {
		for _, port := range host.Ports.Port {
			if port.State.State != "open" {
				continue
			}

			portID, err := strconv.Atoi(port.PortID)
			if err != nil {
				continue
			}

			if port.Service.Name != "" {
				serviceName := port.Service.Name
				version := ""

				if port.Service.Product != "" && port.Service.Version != "" {
					version = port.Service.Product + " " + port.Service.Version
				} else if port.Service.Product != "" {
					version = port.Service.Product
				} else if port.Service.Version != "" {
					version = port.Service.Version
				}

				servicesList = append(servicesList, domain.Service{
					Name:    serviceName,
					Version: version,
					Port:    portID,
				})
			}
		}
	}

	return servicesList, nil
}
