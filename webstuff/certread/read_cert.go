package main

import (
	"crypto/x509"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	//"path/filepath"
)

// Input structure for JSON file
type Input struct {
	CertPath string `json:"cert"`
	KeyPath  string `json:"key"`
}

// Function to read cert and key paths from a JSON file
func readPathsFromJSON(jsonPath string) (string, string) {
	file, err := ioutil.ReadFile(jsonPath)
	if err != nil {
		fmt.Printf("Failed to read JSON file: %v\n", err)
		os.Exit(1)
	}

	var input Input
	if err := json.Unmarshal(file, &input); err != nil {
		fmt.Printf("Failed to parse JSON file: %v\n", err)
		os.Exit(1)
	}

	// Ensure paths are valid and return them
	if input.CertPath == "" || input.KeyPath == "" {
		fmt.Println("Invalid JSON: must contain 'cert' and 'key' fields")
		os.Exit(1)
	}

	return input.CertPath, input.KeyPath
}

func main() {
	var certPath, keyPath string

	args := os.Args[1:]

	switch {
	case len(args) == 0:
		// No arguments, check for input.json
		if _, err := os.Stat("input.json"); err == nil {
			certPath, keyPath = readPathsFromJSON("input.json")
		} else {
			// Default to cert.pem and key.pem
			certPath = "cert.pem"
			keyPath = "key.pem"
		}

	case len(args) == 2 && args[0] == "--json":
		// --json /path/to/input.json
		certPath, keyPath = readPathsFromJSON(args[1])

	case len(args) == 4 && args[0] == "--cert" && args[2] == "--key":
		// --cert /path/to/cert.pem --key /path/to/key.pem
		certPath = args[1]
		keyPath = args[3]

	default:
		fmt.Println("Usage:")
		fmt.Println("  No arguments (default to cert.pem and key.pem or input.json if present)")
		fmt.Println("  --json /path/to/input.json")
		fmt.Println("  --cert /path/to/cert.pem --key /path/to/key.pem")
		return
	}

	// Load and parse the certificate and key files
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		fmt.Printf("Failed to read certificate file: %v\n", err)
		return
	}

	{
		_, err := ioutil.ReadFile(keyPath)
		if err != nil {
			fmt.Printf("Failed to read key file: %v\n", err)
			return
		}
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		fmt.Println("Failed to decode certificate PEM")
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("Failed to parse certificate: %v\n", err)
		return
	}

	fmt.Println("Certificate Information:")
	fmt.Printf("  Subject: %s\n", cert.Subject)
	fmt.Printf("  Issuer: %s\n", cert.Issuer)
	fmt.Printf("  Serial Number: %d\n", cert.SerialNumber)
	fmt.Printf("  Not Before: %s\n", cert.NotBefore)
	fmt.Printf("  Not After: %s\n", cert.NotAfter)
	fmt.Printf("  Key Usage: %v\n", cert.KeyUsage)
	fmt.Printf("  DNS Names: %v\n", cert.DNSNames)
	fmt.Printf("  Email Addresses: %v\n", cert.EmailAddresses)
	fmt.Printf("  IP Addresses: %v\n", cert.IPAddresses)

	if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		fmt.Printf("  Key Size: %d bits\n", rsaKey.Size()*8)
	} else {
		fmt.Println("  Key Size: (Unsupported key type)")
	}
}
