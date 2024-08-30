package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/rs/cors"
	"github.com/titanous/json5"
)

type Config struct {
	Addresses            []string `json:"addresses"`
	Port                 int      `json:"port"`
	AppURI               string   `json:"app_uri"`
	CertFile             string   `json:"cert_file"`
	KeyFile              string   `json:"key_file"`
	RateLimitKbps        int      `json:"rate_limit_kbps,omitempty"` // Optional rate limit in Kbps
	CORSAllowedOrigins   []string `json:"cors_allowed_origins,omitempty"`
	CORSAllowedMethods   []string `json:"cors_allowed_methods,omitempty"`
	CORSAllowedHeaders   []string `json:"cors_allowed_headers,omitempty"`
	CORSAllowCredentials bool     `json:"cors_allow_credentials,omitempty"`
	CORSMaxAge           int      `json:"cors_max_age,omitempty"`
}

func AppHandler(appURI string) (app_handler http.Handler) {
	if strings.HasPrefix(appURI, "http://") {
		// Parse the target URL
		appURL, err := url.Parse(appURI)
		if err != nil {
			log.Fatalf("Failed to parse appURI %s: %s", appURI, err)
		}
		// Create a reverse proxy handler
		app_handler = httputil.NewSingleHostReverseProxy(appURL)
		log.Printf("Serving application by proxy from URL: %s", appURL)
	} else {
		// Check if the directory to serve exists
		if _, err := os.Stat(appURI); os.IsNotExist(err) {
			log.Fatalf("AppURI path `%s` does not exist: %s", appURI, err)
		}

		// Create a file server handler for the directory
		app_dir := http.Dir(appURI)
		app_handler = http.FileServer(app_dir)
		log.Printf("Serving application from directory: %s", app_dir)
	}
	return
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

// rateLimitHandler is a middleware that limits the rate at which data is sent to the client.
func rateLimitHandler(next http.Handler, limitBytesPerSec int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limiter := &RateLimiter{
			ResponseWriter:   w,
			limitBytesPerSec: limitBytesPerSec,
		}
		next.ServeHTTP(limiter, r)
	})
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
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
	err = json5.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}

	appHandler := AppHandler(config.AppURI)

	// Apply rate limiting if specified in the configuration
	if config.RateLimitKbps > 0 {
		limitBytesPerSec := int64(config.RateLimitKbps * 125) // Convert Kbps to Bytes per second
		appHandler = rateLimitHandler(appHandler, limitBytesPerSec)
	}

	// Apply CORS settings if provided in the configuration
	corsOptions := cors.Options{
		AllowedOrigins:   config.CORSAllowedOrigins,
		AllowedMethods:   config.CORSAllowedMethods,
		AllowedHeaders:   config.CORSAllowedHeaders,
		AllowCredentials: config.CORSAllowCredentials,
		MaxAge:           config.CORSMaxAge,
	}
	corsHandler := cors.New(corsOptions).Handler(appHandler)

	// Create a multiplexer for routing
	mux := http.NewServeMux()
	mux.Handle("/", corsHandler)

	// Use a map to track which IP addresses have already been used
	usedAddresses := make(map[string]struct{})

	// Serve HTTPS on each address
	for i, addr := range config.Addresses {
		// Resolve the hostname to an IP address
		log.Printf("%d) Resolving host %s", i+1, addr)
		ipAddrs, err := net.LookupIP(addr)
		if err != nil {
			log.Fatalf("Failed to resolve address %s: %v", addr, err)
		}

		for j, ip := range ipAddrs {
			ipStr := ip.String()
			fullAddr := net.JoinHostPort(ipStr, fmt.Sprintf("%d", config.Port))
			log.Printf("%d:%d) Found address %s", i+1, j+1, ipStr)

			// Check if the IP address has already been used
			if _, exists := usedAddresses[fullAddr]; exists {
				log.Printf("Skipping duplicate address %s\n", fullAddr)
				continue
			}
			// Mark this IP address as used
			usedAddresses[fullAddr] = struct{}{}
		}
	}
	for fullAddr := range usedAddresses {
		// Start the server
		go func(addr string) {
			log.Printf("Starting HTTPS server on %s\n", addr)
			err := http.ListenAndServeTLS(addr, config.CertFile, config.KeyFile, mux)
			if err != nil {
				log.Fatalf("Failed to start server on %s: %v", addr, err)
			}
		}(fullAddr)
	}

	// Block main goroutine to prevent exit
	select {}
}

// CudaText: lexer_file="Go"; tab_size=4; tab_spaces=No;
