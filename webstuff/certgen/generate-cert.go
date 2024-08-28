package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

// CertConfig holds the configuration for the certificate
type CertConfig struct {
	CommonName         string   `json:"CommonName"`
	Country            string   `json:"Country"`
	Organization       string   `json:"Organization"`
	OrganizationalUnit string   `json:"OrganizationalUnit"`
	Locality           string   `json:"Locality"`
	Province           string   `json:"Province"`
	StreetAddress      string   `json:"StreetAddress"`
	PostalCode         string   `json:"PostalCode"`
	DNSNames           []string `json:"DNSNames"`
	IPAddresses        []string `json:"IPAddresses"`
	EmailAddresses     []string `json:"EmailAddresses"`
	ValidityDays       int      `json:"ValidityDays"`
	KeySize            int      `json:"KeySize"`
}

func main() {
	// Command line argument for the config file path
	configFile := flag.String("config", "input.json", "Path to the JSON config file")
	flag.Parse()

	// Read the configuration file
	configData, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	var config CertConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	// Set up the certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         config.CommonName,
			Country:            []string{config.Country},
			Organization:       []string{config.Organization},
			OrganizationalUnit: []string{config.OrganizationalUnit},
			Locality:           []string{config.Locality},
			Province:           []string{config.Province},
			StreetAddress:      []string{config.StreetAddress},
			PostalCode:         []string{config.PostalCode},
		},
		EmailAddresses:       config.EmailAddresses,
		NotBefore:            time.Now(),
		NotAfter:             time.Now().AddDate(0, 0, config.ValidityDays),
		KeyUsage:             x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:          []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, dnsName := range config.DNSNames {
		if dnsName != "" {
			template.DNSNames = append(template.DNSNames, dnsName)
		}
	}

	for _, ip := range config.IPAddresses {
		if ip != "" {
			template.IPAddresses = append(template.IPAddresses, net.ParseIP(ip))
		}
	}

	// Generate the private key based on the KeySize
	var privateKey interface{}
	switch config.KeySize {
	case 2048, 4096:
		privateKey, err = rsa.GenerateKey(rand.Reader, config.KeySize)
		if err != nil {
			log.Fatalf("Failed to generate RSA private key: %v", err)
		}
	default:
		// Default to ECDSA P-256 if no valid KeySize is provided
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("Failed to generate ECDSA private key: %v", err)
		}
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(privateKey), privateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// Write the certificate to cert.pem
	certOut, err := os.Create("cert.pem")
	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		log.Fatalf("Failed to write data to cert.pem: %v", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing cert.pem: %v", err)
	}
	log.Println("Wrote cert.pem")

	// Write the private key to key.pem
	keyOut, err := os.Create("key.pem")
	if err != nil {
		log.Fatalf("Failed to open key.pem for writing: %v", err)
	}

	var privBytes []byte
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		privBytes = x509.MarshalPKCS1PrivateKey(k)
		if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
			log.Fatalf("Failed to write data to key.pem: %v", err)
		}
	case *ecdsa.PrivateKey:
		privBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			log.Fatalf("Unable to marshal ECDSA private key: %v", err)
		}
		if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
			log.Fatalf("Failed to write data to key.pem: %v", err)
		}
	default:
		log.Fatalf("Unknown private key type")
	}

	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing key.pem: %v", err)
	}
	log.Println("Wrote key.pem")
}

// publicKey returns the public key associated with a private key.
func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}
