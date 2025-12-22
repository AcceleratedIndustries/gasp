package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/accelerated-industries/gasp/internal/auth"
	"github.com/accelerated-industries/gasp/internal/collectors"
	"github.com/accelerated-industries/gasp/internal/config"
	"github.com/accelerated-industries/gasp/internal/server"
)

var (
	version = "0.1.0-dev"
)

func main() {
	// Parse command-line flags
	port := flag.Int("port", 8080, "HTTP server port")
	configFile := flag.String("config", "", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	// Show version and exit if requested
	if *showVersion {
		log.Printf("GASP (General AI Specialized Process monitor) v%s", version)
		os.Exit(0)
	}

	// Load configuration
	var cfg *config.Config
	var err error

	configPath := *configFile
	if configPath == "" {
		// Default config path
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Failed to get home directory: %v", err)
		}
		configPath = filepath.Join(home, ".config", "gasp", "config.yaml")
	}

	cfg, err = config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config from %s: %v", configPath, err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	log.Printf("Starting GASP v%s", version)
	log.Printf("Loaded configuration from: %s", configPath)

	// Create collector manager
	manager, err := collectors.NewManager()
	if err != nil {
		log.Fatalf("Failed to create collector manager: %v", err)
	}

	// Register collectors
	log.Println("Registering collectors...")
	manager.Register(collectors.NewCPUCollector())
	manager.Register(collectors.NewMemoryCollector())
	log.Println("Registered CPU and Memory collectors")

	// Determine listen port from config or flag
	listenPort := *port
	if cfg.Server.ListenAddress != "" {
		// Parse port from listen_address if specified
		// For now, use flag-provided port
		// TODO: Parse port from cfg.Server.ListenAddress
	}

	// Create and start HTTP server
	serverConfig := server.Config{
		Port:    listenPort,
		Version: version,
	}

	srv := server.NewServer(manager, serverConfig)
	srv.SetConfig(cfg)

	// Initialize auth manager if auth is enabled
	if cfg.Auth.Enabled {
		// Determine state directory (XDG_STATE_HOME or ~/.local/state)
		stateDir := os.Getenv("XDG_STATE_HOME")
		if stateDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("Failed to get home directory: %v", err)
			}
			stateDir = filepath.Join(home, ".local", "state", "gasp")
		} else {
			stateDir = filepath.Join(stateDir, "gasp")
		}

		// Create state directory if it doesn't exist
		if err := os.MkdirAll(stateDir, 0700); err != nil {
			log.Fatalf("Failed to create state directory %s: %v", stateDir, err)
		}

		sessionsFile := filepath.Join(stateDir, "sessions.json")
		securityFile := filepath.Join(stateDir, "security-state.json")

		authManager, err := auth.NewAuthManager(cfg, sessionsFile, securityFile)
		if err != nil {
			log.Fatalf("Failed to create auth manager: %v", err)
		}

		srv.SetAuthManager(authManager)
		log.Println("Authentication enabled")
	} else {
		log.Println("Authentication disabled")
	}

	// Start server (blocking)
	log.Fatal(srv.Start())
}
