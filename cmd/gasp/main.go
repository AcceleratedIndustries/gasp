package main

import (
	"flag"
	"log"
	"os"

	"github.com/accelerated-industries/gasp/internal/collectors"
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

	// TODO: Load configuration from file if specified
	if *configFile != "" {
		log.Printf("Configuration file support not yet implemented")
	}

	log.Printf("Starting GASP v%s", version)

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

	// Create and start HTTP server
	serverConfig := server.Config{
		Port:    *port,
		Version: version,
	}

	srv := server.NewServer(manager, serverConfig)

	// Start server (blocking)
	log.Fatal(srv.Start())
}
