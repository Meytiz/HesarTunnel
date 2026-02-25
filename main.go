package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/Meytiz/HesarTunnel/pkg"
)

var (
	Version   = "1.3.0"
	BuildDate = "unknown"
	GitCommit = "unknown"
)

func main() {
	configPath := flag.String("config", "/etc/hesar-tunnel/config.toml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	mode := flag.String("mode", "", "Run mode: server or client")
	validateOnly := flag.Bool("validate", false, "Validate configuration and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("HesarTunnel v%s\n", Version)
		fmt.Printf("  Build:    %s\n", BuildDate)
		fmt.Printf("  Commit:   %s\n", GitCommit)
		fmt.Printf("  Go:       %s\n", runtime.Version())
		fmt.Printf("  OS/Arch:  %s/%s\n", runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	log.SetPrefix("[HesarTunnel] ")

	cfg, err := pkg.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[FATAL] Configuration error: %v", err)
	}

	if *validateOnly {
		fmt.Println("Configuration is valid.")
		ports, _ := pkg.ParsePorts(cfg.Tunnel.ConfigPorts)
		fmt.Printf("  Protocol:       %s\n", cfg.Tunnel.Protocol)
		fmt.Printf("  Tunnel Port:    %d\n", cfg.Tunnel.TunnelPort)
		fmt.Printf("  Remote IP:      %s\n", cfg.Tunnel.RemoteIP)
		fmt.Printf("  Config Ports:   %v\n", ports)
		fmt.Printf("  Server Bind:    %s\n", cfg.Tunnel.ServerBind)
		fmt.Printf("  Client Forward: %s\n", cfg.Tunnel.ClientForward)
		fmt.Printf("  Encryption:     %s\n", cfg.Crypto.Method)
		fmt.Printf("  Obfuscation:    %s (enabled: %v)\n", cfg.Crypto.ObfsMode, cfg.Crypto.Obfuscation)
		os.Exit(0)
	}

	if *mode != "server" && *mode != "client" {
		fmt.Fprintln(os.Stderr, "Error: --mode is required (server or client)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  hesar-tunnel --mode server --config /path/to/config.toml")
		fmt.Fprintln(os.Stderr, "  hesar-tunnel --mode client --config /path/to/config.toml")
		os.Exit(1)
	}

	runtime.GOMAXPROCS(runtime.NumCPU())
	log.Printf("[INFO] HesarTunnel v%s starting in %s mode", Version, *mode)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	errChan := make(chan error, 1)

	switch *mode {
	case "server":
		srv, err := pkg.NewServer(cfg)
		if err != nil {
			log.Fatalf("[FATAL] Server init: %v", err)
		}
		go func() { errChan <- srv.Run(ctx) }()

		select {
		case sig := <-sigChan:
			log.Printf("[INFO] Signal %v received", sig)
			cancel()
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer shutCancel()
			srv.Shutdown(shutCtx)
		case err := <-errChan:
			if err != nil {
				log.Fatalf("[FATAL] Server: %v", err)
			}
		}

	case "client":
		cli, err := pkg.NewClient(cfg)
		if err != nil {
			log.Fatalf("[FATAL] Client init: %v", err)
		}
		go func() { errChan <- cli.Run(ctx) }()

		select {
		case sig := <-sigChan:
			log.Printf("[INFO] Signal %v received", sig)
			cancel()
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer shutCancel()
			cli.Shutdown(shutCtx)
		case err := <-errChan:
			if err != nil {
				log.Fatalf("[FATAL] Client: %v", err)
			}
		}
	}

	log.Println("[INFO] HesarTunnel stopped")
}
