package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/rs/cors"
)

type Config struct {
	Addresses       []string `json:"addresses"`
	Port            int      `json:"port"`
	Directory       string   `json:"directory"`
	CertFile        string   `json:"cert_file"`
	KeyFile         string   `json:"key_file"`
	RateLimitKbps   int      `json:"rate_limit_kbps,omitempty"` // Optional rate limit in Kbps
	CORSAllowedOrigins []string `json:"cors_allowed_origins,omitempty"`
	CORSAllowedMethods []string `json:"cors_allowed_methods,omitempty"`
	CORSAllowedHeaders []string `json:"cors_allowed_headers,omitempty"`
	CORSAllowCredentials bool   `json:"cors_allow_credentials,omitempty"`
	CORSMaxAge         int      `json:"cors_max_age,omitempty"`
}

// RateLimiter is a custom http.ResponseWriter that wraps an existing ResponseWriter and limits the rate at which data is written.
type RateLimiter struct {
	http.ResponseWriter
	limitBytesPerSec int64
}

func (rl *RateLimiter) Write(data []byte) (int, error) {
	start := time.Now()
	n, err := rl.ResponseWriter.Write(data)
	if err != nil {
		return n, err
	}

	// Calculate how long the write should take
	elapsed := time.Since(start)
	expected := time.Duration(len(data)) * time.Second / time.Duration(rl.limitBytesPerSec)
	if elapsed < expected {
		time.Sleep(expected - elapsed)
	}

	return n, nil
}

func main() {
	// Default input file
	configFile := "input.json"

	// Check if a file was provided as an argument
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	// Read the JSON configuration file
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	// Parse the JSON file
	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}

	// Check if the directory to serve exists
	if _, err := os.Stat(config.Directory); os.IsNotExist(err) {
		log.Fatalf("Directory %s does not exist", config.Directory)
	}

	// Create a file server handler for the directory
	fs := http.FileServer(http.Dir(config.Directory))

	// Apply rate limiting if specified in the configuration
	if config.RateLimitKbps > 0 {
		limitBytesPerSec := int64(config.RateLimitKbps * 125) // Convert Kbps to Bytes per second
		fs = rateLimitHandler(fs, limitBytesPerSec)
	}

	// Apply CORS settings if provided in the configuration
	corsOptions := cors.Options{
		AllowedOrigins:   config.CORSAllowedOrigins,
		AllowedMethods:   config.CORSAllowedMethods,
		AllowedHeaders:   config.CORSAllowedHeaders,
		AllowCredentials: config.CORSAllowCredentials,
		MaxAge:           config.CORSMaxAge,
	}
	corsHandler := cors.New(corsOptions).Handler(fs)

	// Create a multiplexer for routing
	mux := http.NewServeMux()
	mux.Handle("/", corsHandler)

	// Use a map to track which IP addresses have already been used
	usedAddresses := make(map[string]struct{})

	// Serve HTTPS on each address
	for _, addr := range config.Addresses {
		// Resolve the hostname to an IP address
		ipAddrs, err := net.LookupIP(addr)
		if err != nil {
			log.Fatalf("Failed to resolve address %s: %v", addr, err)
		}

		for _, ip := range ipAddrs {
			ipStr := ip.String()
			fullAddr := net.JoinHostPort(ipStr, fmt.Sprintf("%d", config.Port))

			// Check if the IP address has already been used
			if _, exists := usedAddresses[fullAddr]; exists {
				log.Printf("Skipping duplicate address %s\n", fullAddr)
				continue
			}

			// Mark this IP address as used
			usedAddresses[fullAddr] = struct{}{}

			// Start the server
			go func(addr string) {
				log.Printf("Starting HTTPS server on %s\n", addr)
				err := http.ListenAndServeTLS(addr, config.CertFile, config.KeyFile, mux)
				if err != nil {
					log.Fatalf("Failed to start server on %s: %v", addr, err)
				}
			}(fullAddr)
		}
	}

	// Block main goroutine to prevent exit
	select {}
}

// rateLimitHandler is a middleware that limits the rate at which data is sent to the client.
func rateLimitHandler(next http.Handler, limitBytesPerSec int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limiter := &RateLimiter{
			ResponseWriter:  w,
			limitBytesPerSec: limitBytesPerSec,
		}
		next.ServeHTTP(limiter, r)
	})
}
