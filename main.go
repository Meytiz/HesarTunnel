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

	"hesartunnel/pkg/client"
	"hesartunnel/pkg/server"
	"hesartunnel/pkg/config"
)

const (
	Version   = "1.2.0"
	Banner    = `
 ╦ ╦┌─┐┌─┐┌─┐┬─┐╔╦╗┬ ┬┌┐┌┌┐┌┌─┐┬  
 ╠═╣├┤ └─┐├─┤├┬┘ ║ │ │││││││├┤ │  
 ╩ ╩└─┘└─┘┴ ┴┴└─ ╩ └─┘┘└┘┘└┘└─┘┴─┘
 Secure Reverse Tunnel with Anti-DPI
`
)

var (
	mode       = flag.String("mode", "", "Run mode: 'server' (foreign) or 'client' (iran)")
	configPath = flag.String("config", "", "Path to config file (TOML)")
	serverAddr = flag.String("server", "", "Foreign server address (client mode)")
	serverPort = flag.Int("port", 4443, "Tunnel control port")
	localPort  = flag.Int("local", 0, "Local port to expose (client mode)")
	remotePort = flag.Int("remote", 0, "Remote listening port (client mode)")
	secretKey  = flag.String("key", "", "Pre-shared secret key (32+ chars)")
	logLevel   = flag.String("log", "info", "Log level: debug, info, warn, error")
	workers    = flag.Int("workers", 0, "Number of worker goroutines (0=auto)")
	showVer    = flag.Bool("version", false, "Show version and exit")
)

func main() {
	flag.Parse()
	fmt.Print(Banner)
	fmt.Printf("  Version: %s | Go: %s | OS: %s/%s\n\n",
		Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)

	if *showVer {
		os.Exit(0)
	}

	// Load config from file or flags
	cfg, err := config.Load(*configPath, config.Overrides{
		Mode:       *mode,
		ServerAddr: *serverAddr,
		ServerPort: *serverPort,
		LocalPort:  *localPort,
		RemotePort: *remotePort,
		SecretKey:  *secretKey,
		LogLevel:   *logLevel,
		Workers:    *workers,
	})
	if err != nil {
		log.Fatalf("[FATAL] Config error: %v", err)
	}

	// Set GOMAXPROCS for optimal performance
	if cfg.Workers > 0 {
		runtime.GOMAXPROCS(cfg.Workers)
	}

	// Context with graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("[INFO] Received signal %v, shutting down gracefully...", sig)
		cancel()
	}()

	// Run based on mode
	switch cfg.Mode {
	case "server":
		log.Println("[INFO] Starting HesarTunnel in SERVER mode (Foreign)")
		srv := server.New(cfg)
		if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
			log.Fatalf("[FATAL] Server error: %v", err)
		}
	case "client":
		log.Println("[INFO] Starting HesarTunnel in CLIENT mode (Iran/Reverse)")
		cli := client.New(cfg)
		if err := cli.Run(ctx); err != nil && ctx.Err() == nil {
			log.Fatalf("[FATAL] Client error: %v", err)
		}
	default:
		log.Fatal("[FATAL] Mode must be 'server' or 'client'. Use -mode flag.")
	}

	log.Println("[INFO] HesarTunnel stopped.")
}
