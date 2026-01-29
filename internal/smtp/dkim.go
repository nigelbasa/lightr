package smtp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/emersion/go-msgauth/dkim"
)

type DKIMSigner struct {
	domain   string
	selector string
	privKey  crypto.Signer
}

func NewDKIMSigner(domain, selector, pemKey string) (*DKIMSigner, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}
		var ok bool
		key, ok = k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("unsupported private key type (only RSA supported for now)")
		}
	}

	return &DKIMSigner{
		domain:   domain,
		selector: selector,
		privKey:  key,
	}, nil
}

func (s *DKIMSigner) Sign(msg []byte) ([]byte, error) {
	options := &dkim.SignOptions{
		Domain:   s.domain,
		Selector: s.selector,
		Signer:   s.privKey,
	}

	var b bytes.Buffer
	if err := dkim.Sign(&b, bytes.NewReader(msg), options); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// DKIMKeyPair holds generated DKIM keys
type DKIMKeyPair struct {
	PrivateKeyPEM string // PEM encoded private key for signing
	PublicKeyDNS  string // DNS TXT record value for verification
	Selector      string // DKIM selector
}

// GenerateDKIMKey generates a new RSA key pair for DKIM signing
func GenerateDKIMKey(bits int, selector string) (*DKIMKeyPair, error) {
	if bits < 1024 {
		bits = 2048 // Default to 2048 bits
	}

	// Generate RSA key pair
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode private key to PEM
	privBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	// Create DNS TXT record value for public key
	// Format: v=DKIM1; k=rsa; p=<base64 encoded public key>
	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pubBytes)
	dnsRecord := fmt.Sprintf("v=DKIM1; k=rsa; p=%s", pubB64)

	return &DKIMKeyPair{
		PrivateKeyPEM: string(privPEM),
		PublicKeyDNS:  dnsRecord,
		Selector:      selector,
	}, nil
}

// GetDNSRecord returns the full DNS record name for the given domain
func (k *DKIMKeyPair) GetDNSRecord(domain string) string {
	return fmt.Sprintf("%s._domainkey.%s", k.Selector, domain)
}
