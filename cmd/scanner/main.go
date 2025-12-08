package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"offsec-scan-go/internal/adapters/host"
	"offsec-scan-go/internal/adapters/nmap"
	"offsec-scan-go/internal/adapters/subfinder"
	"offsec-scan-go/internal/usecase"
	"offsec-scan-go/pkg/logger"
)

func showBanner() {
	version := "0.01"
	banner := fmt.Sprintf(`
 ________  ________ ________ ________  ________  ________  ________   ________  ________     
|\   __  \|\  _____\\  _____\\   ____\|\   ____\|\   __  \|\   ___  \|\   ____\|\   __  \    
\ \  \|\  \ \  \__/\ \  \__/\ \  \___|\ \  \___|\ \  \|\  \ \  \\ \  \ \  \___|\ \  \|\  \   
 \ \  \\\  \ \   __\\ \   __\\ \_____  \ \  \    \ \   __  \ \  \\ \  \ \  \  __\ \  \\\  \  
  \ \  \\\  \ \  \_| \ \  \_| \|____|\  \ \  \____\ \  \ \  \ \  \\ \  \ \  \|\  \ \  \\\  \ 
   \ \_______\ \__\   \ \__\    ____\_\  \ \_______\ \__\ \__\ \__\\ \__\ \_______\ \_______\
    \|_______|\|__|    \|__|   |\_________\|_______|\|__|\|__|\|__| \|__|\|_______|\|_______|
                               \|_________| v%s
`, version)

	fmt.Println(banner)
}

func main() {
	var (
		log    = logger.NewZeroLogger()
		target string
	)

	flag.StringVar(&target, "t", "", "Target domain to scan (shorthand)")
	flag.StringVar(&target, "target", "", "Target domain to scan")
	flag.Parse()

	if target == "" {
		showBanner()
		if _, err := fmt.Fprintf(os.Stderr, "\nError: target domain is required\n\n"); err != nil {
			os.Exit(1)
		}
		if _, err := fmt.Fprintf(os.Stderr, "Usage: %s -t <domain> or %s --target <domain>\n\n", os.Args[0], os.Args[0]); err != nil {
			os.Exit(1)
		}
		if _, err := fmt.Fprintf(os.Stderr, "Flags:\n"); err != nil {
			os.Exit(1)
		}
		flag.PrintDefaults()
		os.Exit(1)
	}

	showBanner()

	subfinderAdapter := subfinder.NewSubFinder()
	hostAdapter := host.NewHost()
	nmapAdapter := nmap.NewNmap(log)

	uc := usecase.NewBaseScanUseCase(
		target,
		&subfinderAdapter,
		&hostAdapter,
		&nmapAdapter,
	)

	if err := uc.Execute(context.Background()); err != nil {
		log.Error(
			"Error executing usecase",
			logger.Field{Key: "error", Value: err},
		)
		os.Exit(1)
	}
}
