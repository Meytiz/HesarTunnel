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
	Version   = "1.2.0"
	BuildDate = "unknown"
	GitCommit = "unknown"
)

func main() {
	// Parse flags
	configPath := flag.String("config", "/etc/hesar-tunnel/config.toml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	mode := flag.String("mode", "", "Run mode: server or client")
	validate := flag.Bool("validate", false, "Validate configuration and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("HesarTunnel v%s\n", Version)
		fmt.Printf("  Build Date: %s\n", BuildDate)
		fmt.Printf("  Git Commit: %s\n", GitCommit)
		fmt.Printf("  Go Version: %s\n", runtime.Version())
		fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// Setup logging
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	log.SetPrefix("[HesarTunnel] ")

	// Load config
	cfg, err := pkg.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[FATAL] Configuration error: %v", err)
	}

	if *validate {
		fmt.Println("Configuration is valid.")
		fmt.Printf("  Protocol:    %s\n", cfg.Tunnel.Protocol)
		fmt.Printf("  Tunnel Port: %d\n", cfg.Tunnel.TunnelPort)
		fmt.Printf("  Remote IP:   %s\n", cfg.Tunnel.RemoteIP)
		fmt.Printf("  Config Ports: %s\n", cfg.Tunnel.ConfigPorts)
		fmt.Printf("  Encryption:  %s\n", cfg.Crypto.Method)
		fmt.Printf("  Obfuscation: %s (enabled: %v)\n", cfg.Crypto.ObfsMode, cfg.Crypto.Obfuscation)
		ports, _ := pkg.ParsePorts(cfg.Tunnel.ConfigPorts)
		fmt.Printf("  Parsed Ports: %v\n", ports)
		os.Exit(0)
	}

	if *mode == "" {
		fmt.Fprintln(os.Stderr, "Error: --mode is required (server or client)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  hesar-tunnel --mode server --config /path/to/config.toml")
		fmt.Fprintln(os.Stderr, "  hesar-tunnel --mode client --config /path/to/config.toml")
		os.Exit(1)
	}

	if *mode != "server" && *mode != "client" {
		log.Fatalf("[FATAL] Invalid mode: %s (use 'server' or 'client')", *mode)
	}

	// Set GOMAXPROCS
	runtime.GOMAXPROCS(runtime.NumCPU())

	log.Printf("[INFO] HesarTunnel v%s starting in %s mode", Version, *mode)
	log.Printf("[INFO] Go routines: GOMAXPROCS=%d, NumCPU=%d", runtime.GOMAXPROCS(0), runtime.NumCPU())

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Error channel
	errChan := make(chan error, 1)

	switch *mode {
	case "server":
		srv, err := pkg.NewServer(cfg)
		if err != nil {
			log.Fatalf("[FATAL] Failed to create server: %v", err)
		}

		go func() {
			errChan <- srv.Run(ctx)
		}()

		select {
		case sig := <-sigChan:
			log.Printf("[INFO] Received signal: %v, shutting down...", sig)
			cancel()
			// Give goroutines time to cleanup
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer shutdownCancel()
			srv.Shutdown(shutdownCtx)

		case err := <-errChan:
			if err != nil {
				log.Fatalf("[FATAL] Server error: %v", err)
			}
		}

	case "client":
		cli, err := pkg.NewClient(cfg)
		if err != nil {
			log.Fatalf("[FATAL] Failed to create client: %v", err)
		}

		go func() {
			errChan <- cli.Run(ctx)
		}()

		select {
		case sig := <-sigChan:
			log.Printf("[INFO] Received signal: %v, shutting down...", sig)
			cancel()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer shutdownCancel()
			cli.Shutdown(shutdownCtx)

		case err := <-errChan:
			if err != nil {
				log.Fatalf("[FATAL] Client error: %v", err)
			}
		}
	}

	log.Println("[INFO] HesarTunnel stopped gracefully")
}
