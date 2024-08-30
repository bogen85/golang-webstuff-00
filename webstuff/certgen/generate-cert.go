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
	"io/ioutil"
	"math/big"
	"os/user"
	"path/filepath"

	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/pflag"
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
	IsCA               bool     `json:"IsCA"`
	CAPath             string   `json:"CAPath"`
	CAKeyPath          string   `json:"CAKeyPath"`
	CertPath           string   `json:"CertPath"`
	CertKeyPath        string   `json:"CertKeyPath"`
	Overwrite          bool     `json:"Overwrite"`
}

func CheckOverwrite(path string, overwrite bool) {
	if overwrite {
		return
	}

	// Check if the path exists
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			// The path does not exist, which is fine
			return
		}
		// Some other error occurred
		log.Fatalf("Error checking if path `%s` exists: %s", path, err)
	}

	// If we get here, it means the path exists
	log.Fatalf("Path `%s` already exists", path)
}

// ExpandPath expands the `~` in a path to the user's home directory.
func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~") {
		usr, err := user.Current()
		if err != nil {
			log.Fatalf("Unable to get current user to expand path: %s", path)
		}

		// Handle the case for Windows where the path could start with `~/`.
		if runtime.GOOS == "windows" && len(path) > 1 && path[1] == '/' {
			return filepath.Join(usr.HomeDir, path[2:])
		}
		return filepath.Join(usr.HomeDir, path[1:])
	}
	return path
}

// randomSerialNumber generates a unique serial number by combining the current Unix timestamp and random bytes.
func randomSerialNumber() []byte {
	timestamp := uint32(time.Now().Unix())
	randomBytes := make([]byte, 12) // 12 random bytes
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Fatalf("Failed to generate random bytes for serial number: %v", err)
	}

	serial := make([]byte, 4+len(randomBytes))
	// Encode the Unix timestamp as a 4-byte big-endian integer
	serial[0] = byte((timestamp >> 24) & 0xFF)
	serial[1] = byte((timestamp >> 16) & 0xFF)
	serial[2] = byte((timestamp >> 8) & 0xFF)
	serial[3] = byte(timestamp & 0xFF)
	// Append random bytes
	copy(serial[4:], randomBytes)

	return serial
}

// writeCertificateAndKey writes the certificate and key to the specified paths
func writeCertificateAndKey(certDER []byte, privateKey interface{}, certPath, keyPath string) error {
	// Write the certificate
	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}
	if err := certOut.Close(); err != nil {
		return err
	}
	log.Printf("Wrote %s\n", certPath)

	// Write the private key
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}

	var privBytes []byte
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		privBytes = x509.MarshalPKCS1PrivateKey(k)
		if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
			return err
		}
	case *ecdsa.PrivateKey:
		privBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return err
		}
		if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
			return err
		}
	default:
		return err
	}

	if err := keyOut.Close(); err != nil {
		return err
	}
	log.Printf("Wrote %s\n", keyPath)

	return nil
}

// loadCA loads the CA certificate and private key from the given paths
func loadCA(caPath, caKeyPath string) (*x509.Certificate, interface{}, error) {
	caCertPEM, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, nil, err
	}

	caKeyPEM, err := ioutil.ReadFile(caKeyPath)
	if err != nil {
		return nil, nil, err
	}

	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil || caCertBlock.Type != "CERTIFICATE" {
		return nil, nil, err
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, nil, err
	}

	var caKey interface{}
	switch caKeyBlock.Type {
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	case "EC PRIVATE KEY":
		caKey, err = x509.ParseECPrivateKey(caKeyBlock.Bytes)
	default:
		return nil, nil, err
	}

	if err != nil {
		return nil, nil, err
	}

	return caCert, caKey, nil
}

// publicKey returns the public key associated with a private key
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

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var configFile string
	pflag.StringVarP(&configFile, "config", "c", "input.json", "Path to the JSON config file")
	pflag.Parse()

	log.Printf("Config file provided: %s", configFile)

	configFile = ExpandPath(configFile)

	// Read the configuration file
	configData, err := ioutil.ReadFile(configFile)
	if err != nil {
		pflag.Usage()
		log.Fatalf("Failed to read config file: %v", err)
	}

	var config CertConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	config.CAKeyPath = ExpandPath(config.CAKeyPath)
	config.CAPath = ExpandPath(config.CAPath)
	config.CertKeyPath = ExpandPath(config.CertKeyPath)
	config.CertPath = ExpandPath(config.CertPath)

	// Validate configuration based on IsCA flag
	if config.IsCA {
		CheckOverwrite(config.CAKeyPath, config.Overwrite)
		CheckOverwrite(config.CAPath, config.Overwrite)
		if config.CAPath == "" || config.CAKeyPath == "" {
			log.Fatalf("For CA certificates, both CAPath and CAKeyPath must be specified")
		}
	} else {
		CheckOverwrite(config.CertKeyPath, config.Overwrite)
		CheckOverwrite(config.CertPath, config.Overwrite)
		if config.CAPath == "" || config.CAKeyPath == "" || config.CertPath == "" || config.CertKeyPath == "" {
			log.Fatalf("For non-CA certificates, CAPath, CAKeyPath, CertPath, and CertKeyPath must all be specified")
		}
	}

	// Generate the private key based on the KeySize
	var privateKey interface{}
	switch config.KeySize {
	case 2048, 4096:
		log.Printf("Generating %d bit RSA private key", config.KeySize)
		privateKey, err = rsa.GenerateKey(rand.Reader, config.KeySize)
		if err != nil {
			log.Fatalf("Failed to generate RSA private key: %v", err)
		}
	default:
		curve := elliptic.P256()
		switch config.KeySize {
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			{
			}
		}
		description := fmt.Sprintf("Curve Name: %s, BitSize: %d", curve.Params().Name, curve.Params().BitSize)

		// Default to ECDSA P-256 if no valid KeySize is provided
		log.Printf("Generating `%s` due to %d == config KeySize", description, config.KeySize)
		privateKey, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			log.Fatalf("Failed to generate %s private key: %s", description, err)
		}
	}

	// Set up the certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(0).SetBytes(randomSerialNumber()),
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
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, config.ValidityDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  config.IsCA,
		BasicConstraintsValid: true,
	}

	if config.IsCA {
		template.KeyUsage |= x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
		template.IsCA = true
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

	for _, email := range config.EmailAddresses {
		if email != "" {
			template.EmailAddresses = append(template.EmailAddresses, email)
		}
	}

	var certDER []byte
	if config.IsCA {
		// Create a self-signed CA certificate
		certDER, err = x509.CreateCertificate(rand.Reader, &template, &template, publicKey(privateKey), privateKey)
		if err != nil {
			log.Fatalf("Failed to create CA certificate: %v", err)
		}

		// Write the CA certificate and key to specified paths
		err = writeCertificateAndKey(certDER, privateKey, config.CAPath, config.CAKeyPath)
		if err != nil {
			log.Fatalf("Failed to write CA certificate and key: %v", err)
		}
	} else {
		// Load the CA certificate and private key
		caCert, caKey, err := loadCA(config.CAPath, config.CAKeyPath)
		if err != nil {
			log.Fatalf("Failed to load CA: %v", err)
		}

		// Create a certificate signed by the CA
		certDER, err = x509.CreateCertificate(rand.Reader, &template, caCert, publicKey(privateKey), caKey)
		if err != nil {
			log.Fatalf("Failed to create signed certificate: %v", err)
		}

		// Write the server certificate and key to specified paths
		err = writeCertificateAndKey(certDER, privateKey, config.CertPath, config.CertKeyPath)
		if err != nil {
			log.Fatalf("Failed to write server certificate and key: %v", err)
		}
	}
}
