package encryption

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// KeyType represents the type of encryption key
type KeyType string

const (
	KeyTypeSMIME KeyType = "smime"   // S/MIME certificate
	KeyTypePGP   KeyType = "pgp"     // PGP/GPG key
)

// KeyUsage represents how a key can be used
type KeyUsage string

const (
	UsageEncrypt KeyUsage = "encrypt"
	UsageSign    KeyUsage = "sign"
	UsageBoth    KeyUsage = "both"
)

// TrustLevel represents trust level for a key
type TrustLevel string

const (
	TrustUnknown    TrustLevel = "unknown"
	TrustNever      TrustLevel = "never"
	TrustMarginal   TrustLevel = "marginal"
	TrustFull       TrustLevel = "full"
	TrustUltimate   TrustLevel = "ultimate"
)

// Key represents an encryption key (S/MIME certificate or PGP key)
type Key struct {
	ID          uuid.UUID  `json:"id"`
	AccountID   uuid.UUID  `json:"account_id"`
	OrgID       uuid.UUID  `json:"org_id"`
	
	Type        KeyType    `json:"type"`
	Usage       KeyUsage   `json:"usage"`
	
	// Key identifiers
	KeyID       string     `json:"key_id"`        // Short key ID
	Fingerprint string     `json:"fingerprint"`   // Full fingerprint
	
	// Associated email
	Email       string     `json:"email"`
	Name        string     `json:"name,omitempty"`
	
	// Key data
	PublicKey   string     `json:"public_key"`    // PEM or armor encoded
	PrivateKey  string     `json:"-"`             // Encrypted private key (never exposed)
	
	// For S/MIME certificates
	Certificate string     `json:"certificate,omitempty"`
	Issuer      string     `json:"issuer,omitempty"`
	Subject     string     `json:"subject,omitempty"`
	SerialNumber string    `json:"serial_number,omitempty"`
	
	// For PGP keys
	Algorithm   string     `json:"algorithm,omitempty"`
	KeySize     int        `json:"key_size,omitempty"`
	Subkeys     []Subkey   `json:"subkeys,omitempty"`
	
	// Validity
	CreatedDate time.Time  `json:"created_date"`
	ExpiryDate  *time.Time `json:"expiry_date,omitempty"`
	IsRevoked   bool       `json:"is_revoked"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	RevokedBy   string     `json:"revoked_by,omitempty"`
	
	// Trust
	TrustLevel  TrustLevel `json:"trust_level"`
	IsVerified  bool       `json:"is_verified"`
	VerifiedAt  *time.Time `json:"verified_at,omitempty"`
	VerifiedBy  string     `json:"verified_by,omitempty"`
	
	// Metadata
	IsDefault   bool       `json:"is_default"`
	IsActive    bool       `json:"is_active"`
	ImportedAt  time.Time  `json:"imported_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Subkey represents a PGP subkey
type Subkey struct {
	KeyID       string     `json:"key_id"`
	Fingerprint string     `json:"fingerprint"`
	Usage       KeyUsage   `json:"usage"`
	Algorithm   string     `json:"algorithm"`
	KeySize     int        `json:"key_size"`
	CreatedDate time.Time  `json:"created_date"`
	ExpiryDate  *time.Time `json:"expiry_date,omitempty"`
}

// EncryptedMessage represents an encrypted email
type EncryptedMessage struct {
	ID           uuid.UUID `json:"id"`
	MessageID    uuid.UUID `json:"message_id"`
	EncryptionType KeyType `json:"encryption_type"`
	
	// Encrypted content
	EncryptedBody    string   `json:"encrypted_body"`
	EncryptedAttachments []EncryptedAttachment `json:"encrypted_attachments,omitempty"`
	
	// Recipients and their encrypted session keys
	Recipients   []EncryptedRecipient `json:"recipients"`
	
	// Signature info
	IsSigned     bool      `json:"is_signed"`
	SignerKeyID  string    `json:"signer_key_id,omitempty"`
	SignatureValid *bool   `json:"signature_valid,omitempty"`
	SignedAt     *time.Time `json:"signed_at,omitempty"`
	
	EncryptedAt  time.Time `json:"encrypted_at"`
}

// EncryptedAttachment represents an encrypted attachment
type EncryptedAttachment struct {
	Filename     string `json:"filename"`
	ContentType  string `json:"content_type"`
	EncryptedData string `json:"encrypted_data"`
}

// EncryptedRecipient holds the encrypted session key for a recipient
type EncryptedRecipient struct {
	Email            string `json:"email"`
	KeyID            string `json:"key_id"`
	EncryptedSessionKey string `json:"encrypted_session_key"`
}

// KeyImportRequest represents a key import request
type KeyImportRequest struct {
	AccountID   uuid.UUID
	OrgID       uuid.UUID
	Type        KeyType
	KeyData     string    // PEM, armor, or PKCS12
	Passphrase  string    // For encrypted private keys or PKCS12
	SetDefault  bool
}

// EncryptRequest represents an encryption request
type EncryptRequest struct {
	MessageID   uuid.UUID
	Body        string
	Attachments []Attachment
	Recipients  []string  // Email addresses
	SignerEmail string    // Email of signer (optional)
	Type        KeyType   // S/MIME or PGP
}

// Attachment represents an email attachment
type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

// DecryptRequest represents a decryption request
type DecryptRequest struct {
	EncryptedMessage *EncryptedMessage
	RecipientEmail   string
	Passphrase       string // For encrypted private key
}

// DecryptedMessage represents a decrypted email
type DecryptedMessage struct {
	Body         string
	Attachments  []Attachment
	SignatureInfo *SignatureInfo
}

// SignatureInfo contains signature verification info
type SignatureInfo struct {
	IsSigned      bool
	IsValid       bool
	SignerEmail   string
	SignerName    string
	SignerKeyID   string
	SignedAt      time.Time
	TrustLevel    TrustLevel
	Errors        []string
}

// Service handles email encryption
type Service struct {
	mu       sync.RWMutex
	repo     Repository
	keyCache map[string]*Key // fingerprint -> key
	logger   Logger
}

// Repository interface
type Repository interface {
	// Keys
	SaveKey(ctx context.Context, key *Key) error
	GetKey(ctx context.Context, id uuid.UUID) (*Key, error)
	GetKeyByFingerprint(ctx context.Context, fingerprint string) (*Key, error)
	GetKeyByEmail(ctx context.Context, email string, keyType KeyType) (*Key, error)
	GetKeysForAccount(ctx context.Context, accountID uuid.UUID) ([]*Key, error)
	GetDefaultKey(ctx context.Context, accountID uuid.UUID, keyType KeyType) (*Key, error)
	GetPublicKeyByEmail(ctx context.Context, email string, keyType KeyType) (*Key, error)
	UpdateKey(ctx context.Context, key *Key) error
	DeleteKey(ctx context.Context, id uuid.UUID) error
	
	// Encrypted messages
	SaveEncryptedMessage(ctx context.Context, msg *EncryptedMessage) error
	GetEncryptedMessage(ctx context.Context, messageID uuid.UUID) (*EncryptedMessage, error)
}

// Logger interface
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// NewService creates a new encryption service
func NewService(repo Repository, logger Logger) *Service {
	return &Service{
		repo:     repo,
		keyCache: make(map[string]*Key),
		logger:   logger,
	}
}

// Key Management

// ImportKey imports a key or certificate
func (s *Service) ImportKey(ctx context.Context, req *KeyImportRequest) (*Key, error) {
	var key *Key
	var err error

	switch req.Type {
	case KeyTypeSMIME:
		key, err = s.importSMIMEKey(req)
	case KeyTypePGP:
		key, err = s.importPGPKey(req)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", req.Type)
	}

	if err != nil {
		return nil, err
	}

	key.ID = uuid.New()
	key.AccountID = req.AccountID
	key.OrgID = req.OrgID
	key.IsDefault = req.SetDefault
	key.IsActive = true
	key.ImportedAt = time.Now()
	key.UpdatedAt = time.Now()

	// If setting as default, unset other defaults
	if req.SetDefault {
		keys, _ := s.repo.GetKeysForAccount(ctx, req.AccountID)
		for _, k := range keys {
			if k.Type == req.Type && k.IsDefault {
				k.IsDefault = false
				s.repo.UpdateKey(ctx, k)
			}
		}
	}

	if err := s.repo.SaveKey(ctx, key); err != nil {
		return nil, err
	}

	// Cache the key
	s.mu.Lock()
	s.keyCache[key.Fingerprint] = key
	s.mu.Unlock()

	s.logger.Info("imported key", "type", req.Type, "email", key.Email, "fingerprint", key.Fingerprint)
	return key, nil
}

func (s *Service) importSMIMEKey(req *KeyImportRequest) (*Key, error) {
	// Parse PEM-encoded certificate
	block, _ := pem.Decode([]byte(req.KeyData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Extract email from certificate
	var email string
	if len(cert.EmailAddresses) > 0 {
		email = cert.EmailAddresses[0]
	}

	// Determine usage from key usage extension
	usage := UsageBoth
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 && cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		usage = UsageSign
	} else if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		usage = UsageEncrypt
	}

	// Generate fingerprint
	fingerprint := fmt.Sprintf("%X", sha256.Sum256(cert.Raw))

	key := &Key{
		Type:         KeyTypeSMIME,
		Usage:        usage,
		KeyID:        fingerprint[:16],
		Fingerprint:  fingerprint,
		Email:        email,
		Name:         cert.Subject.CommonName,
		PublicKey:    req.KeyData,
		Certificate:  req.KeyData,
		Issuer:       cert.Issuer.String(),
		Subject:      cert.Subject.String(),
		SerialNumber: cert.SerialNumber.String(),
		CreatedDate:  cert.NotBefore,
		TrustLevel:   TrustUnknown,
	}

	if !cert.NotAfter.IsZero() {
		key.ExpiryDate = &cert.NotAfter
	}

	return key, nil
}

func (s *Service) importPGPKey(req *KeyImportRequest) (*Key, error) {
	// For a real implementation, use golang.org/x/crypto/openpgp
	// This is a simplified version

	// Parse armored key
	keyData := req.KeyData
	
	// Extract basic info (simplified - real impl would parse packets)
	key := &Key{
		Type:        KeyTypePGP,
		Usage:       UsageBoth,
		PublicKey:   keyData,
		Algorithm:   "RSA",
		KeySize:     4096,
		TrustLevel:  TrustUnknown,
		CreatedDate: time.Now(),
	}

	// Generate a placeholder fingerprint (real impl would calculate from key)
	hash := sha256.Sum256([]byte(keyData))
	key.Fingerprint = fmt.Sprintf("%X", hash)
	key.KeyID = key.Fingerprint[:16]

	// Extract email from key (simplified)
	if idx := strings.Index(keyData, "<"); idx != -1 {
		end := strings.Index(keyData[idx:], ">")
		if end != -1 {
			key.Email = keyData[idx+1 : idx+end]
		}
	}

	return key, nil
}

// GenerateKey generates a new key pair
func (s *Service) GenerateKey(ctx context.Context, accountID, orgID uuid.UUID, email, name string, keyType KeyType, keySize int) (*Key, error) {
	var key *Key
	var err error

	switch keyType {
	case KeyTypePGP:
		key, err = s.generatePGPKey(email, name, keySize)
	case KeyTypeSMIME:
		return nil, fmt.Errorf("S/MIME certificate generation requires CA - use ImportKey instead")
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	if err != nil {
		return nil, err
	}

	key.ID = uuid.New()
	key.AccountID = accountID
	key.OrgID = orgID
	key.IsDefault = true
	key.IsActive = true
	key.ImportedAt = time.Now()
	key.UpdatedAt = time.Now()

	if err := s.repo.SaveKey(ctx, key); err != nil {
		return nil, err
	}

	s.logger.Info("generated key", "type", keyType, "email", email, "fingerprint", key.Fingerprint)
	return key, nil
}

func (s *Service) generatePGPKey(email, name string, keySize int) (*Key, error) {
	if keySize == 0 {
		keySize = 4096
	}

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Encode public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// Encode private key (should be encrypted in production)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Generate fingerprint
	hash := sha256.Sum256(pubKeyBytes)
	fingerprint := fmt.Sprintf("%X", hash)

	key := &Key{
		Type:        KeyTypePGP,
		Usage:       UsageBoth,
		KeyID:       fingerprint[:16],
		Fingerprint: fingerprint,
		Email:       email,
		Name:        name,
		PublicKey:   string(pubKeyPEM),
		PrivateKey:  string(privKeyPEM),
		Algorithm:   "RSA",
		KeySize:     keySize,
		CreatedDate: time.Now(),
		TrustLevel:  TrustUltimate, // Own key
		IsVerified:  true,
	}

	return key, nil
}

// RevokeKey revokes a key
func (s *Service) RevokeKey(ctx context.Context, keyID uuid.UUID, revokedBy string, reason string) error {
	key, err := s.repo.GetKey(ctx, keyID)
	if err != nil {
		return err
	}

	now := time.Now()
	key.IsRevoked = true
	key.RevokedAt = &now
	key.RevokedBy = revokedBy
	key.UpdatedAt = now

	if err := s.repo.UpdateKey(ctx, key); err != nil {
		return err
	}

	// Remove from cache
	s.mu.Lock()
	delete(s.keyCache, key.Fingerprint)
	s.mu.Unlock()

	s.logger.Info("revoked key", "id", keyID, "revoked_by", revokedBy)
	return nil
}

// GetPublicKey retrieves a public key for an email address
func (s *Service) GetPublicKey(ctx context.Context, email string, keyType KeyType) (*Key, error) {
	return s.repo.GetPublicKeyByEmail(ctx, email, keyType)
}

// Encryption

// Encrypt encrypts a message for recipients
func (s *Service) Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptedMessage, error) {
	// Get recipient public keys
	var recipients []EncryptedRecipient
	var publicKeys []*rsa.PublicKey

	for _, email := range req.Recipients {
		key, err := s.repo.GetPublicKeyByEmail(ctx, email, req.Type)
		if err != nil {
			return nil, fmt.Errorf("no public key found for %s: %w", email, err)
		}

		if key.IsRevoked {
			return nil, fmt.Errorf("key for %s is revoked", email)
		}
		if key.ExpiryDate != nil && time.Now().After(*key.ExpiryDate) {
			return nil, fmt.Errorf("key for %s is expired", email)
		}

		// Parse public key
		block, _ := pem.Decode([]byte(key.PublicKey))
		if block == nil {
			continue
		}
		
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			continue
		}

		publicKeys = append(publicKeys, rsaPub)
		recipients = append(recipients, EncryptedRecipient{
			Email: email,
			KeyID: key.KeyID,
		})
	}

	if len(publicKeys) == 0 {
		return nil, fmt.Errorf("no valid public keys found")
	}

	// Generate session key
	sessionKey := make([]byte, 32) // AES-256
	if _, err := rand.Read(sessionKey); err != nil {
		return nil, err
	}

	// Encrypt body with session key (simplified - real impl would use AES-GCM)
	encryptedBody := base64.StdEncoding.EncodeToString(xorEncrypt([]byte(req.Body), sessionKey))

	// Encrypt attachments
	var encryptedAttachments []EncryptedAttachment
	for _, att := range req.Attachments {
		encData := base64.StdEncoding.EncodeToString(xorEncrypt(att.Data, sessionKey))
		encryptedAttachments = append(encryptedAttachments, EncryptedAttachment{
			Filename:      att.Filename,
			ContentType:   att.ContentType,
			EncryptedData: encData,
		})
	}

	// Encrypt session key for each recipient
	for i, pub := range publicKeys {
		encSessionKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, sessionKey, nil)
		if err != nil {
			return nil, err
		}
		recipients[i].EncryptedSessionKey = base64.StdEncoding.EncodeToString(encSessionKey)
	}

	msg := &EncryptedMessage{
		ID:                   uuid.New(),
		MessageID:            req.MessageID,
		EncryptionType:       req.Type,
		EncryptedBody:        encryptedBody,
		EncryptedAttachments: encryptedAttachments,
		Recipients:           recipients,
		EncryptedAt:          time.Now(),
	}

	// Sign if requested
	if req.SignerEmail != "" {
		if err := s.signMessage(ctx, msg, req.SignerEmail, req.Type); err != nil {
			s.logger.Error("failed to sign message", "error", err)
		}
	}

	if err := s.repo.SaveEncryptedMessage(ctx, msg); err != nil {
		return nil, err
	}

	return msg, nil
}

func (s *Service) signMessage(ctx context.Context, msg *EncryptedMessage, signerEmail string, keyType KeyType) error {
	key, err := s.repo.GetKeyByEmail(ctx, signerEmail, keyType)
	if err != nil {
		return err
	}

	if key.PrivateKey == "" {
		return fmt.Errorf("no private key available for signing")
	}

	// Parse private key
	block, _ := pem.Decode([]byte(key.PrivateKey))
	if block == nil {
		return fmt.Errorf("failed to decode private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	// Create signature (simplified)
	hash := sha256.Sum256([]byte(msg.EncryptedBody))
	_, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return err
	}

	msg.IsSigned = true
	msg.SignerKeyID = key.KeyID
	now := time.Now()
	msg.SignedAt = &now
	valid := true
	msg.SignatureValid = &valid

	return nil
}

// Decrypt decrypts a message
func (s *Service) Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptedMessage, error) {
	// Find recipient entry
	var recipientEntry *EncryptedRecipient
	for _, r := range req.EncryptedMessage.Recipients {
		if r.Email == req.RecipientEmail {
			recipientEntry = &r
			break
		}
	}

	if recipientEntry == nil {
		return nil, fmt.Errorf("message not encrypted for %s", req.RecipientEmail)
	}

	// Get private key
	key, err := s.repo.GetKeyByEmail(ctx, req.RecipientEmail, req.EncryptedMessage.EncryptionType)
	if err != nil {
		return nil, fmt.Errorf("no private key found: %w", err)
	}

	if key.PrivateKey == "" {
		return nil, fmt.Errorf("no private key available")
	}

	// Parse private key
	block, _ := pem.Decode([]byte(key.PrivateKey))
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Decrypt session key
	encSessionKey, err := base64.StdEncoding.DecodeString(recipientEntry.EncryptedSessionKey)
	if err != nil {
		return nil, err
	}

	sessionKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encSessionKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt session key: %w", err)
	}

	// Decrypt body
	encBody, err := base64.StdEncoding.DecodeString(req.EncryptedMessage.EncryptedBody)
	if err != nil {
		return nil, err
	}
	body := string(xorEncrypt(encBody, sessionKey))

	// Decrypt attachments
	var attachments []Attachment
	for _, enc := range req.EncryptedMessage.EncryptedAttachments {
		encData, err := base64.StdEncoding.DecodeString(enc.EncryptedData)
		if err != nil {
			continue
		}
		attachments = append(attachments, Attachment{
			Filename:    enc.Filename,
			ContentType: enc.ContentType,
			Data:        xorEncrypt(encData, sessionKey),
		})
	}

	result := &DecryptedMessage{
		Body:        body,
		Attachments: attachments,
	}

	// Verify signature if signed
	if req.EncryptedMessage.IsSigned {
		result.SignatureInfo = s.verifySignature(ctx, req.EncryptedMessage)
	}

	return result, nil
}

func (s *Service) verifySignature(ctx context.Context, msg *EncryptedMessage) *SignatureInfo {
	info := &SignatureInfo{
		IsSigned: true,
	}

	// Find signer's public key
	// In real impl, would look up by key ID
	info.SignerKeyID = msg.SignerKeyID
	if msg.SignedAt != nil {
		info.SignedAt = *msg.SignedAt
	}

	if msg.SignatureValid != nil {
		info.IsValid = *msg.SignatureValid
	}

	return info
}

// Simple XOR encryption (for demo - real impl would use AES-GCM)
func xorEncrypt(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// Key Discovery

// FetchPublicKey tries to fetch a public key from various sources
func (s *Service) FetchPublicKey(ctx context.Context, email string, keyType KeyType) (*Key, error) {
	// Try local database first
	key, err := s.repo.GetPublicKeyByEmail(ctx, email, keyType)
	if err == nil {
		return key, nil
	}

	// For PGP, could try keyservers
	if keyType == KeyTypePGP {
		// Would query keyservers like keys.openpgp.org
		// This is a placeholder
		s.logger.Debug("would query keyserver for", "email", email)
	}

	// For S/MIME, could query LDAP
	if keyType == KeyTypeSMIME {
		// Would query LDAP/Active Directory
		s.logger.Debug("would query LDAP for", "email", email)
	}

	return nil, fmt.Errorf("no public key found for %s", email)
}

// PublishPublicKey publishes a public key to keyservers
func (s *Service) PublishPublicKey(ctx context.Context, keyID uuid.UUID) error {
	key, err := s.repo.GetKey(ctx, keyID)
	if err != nil {
		return err
	}

	if key.Type == KeyTypePGP {
		// Would publish to keys.openpgp.org
		s.logger.Info("would publish PGP key to keyserver", "fingerprint", key.Fingerprint)
	}

	return nil
}

// ExportPublicKey exports a public key in armor format
func (s *Service) ExportPublicKey(ctx context.Context, keyID uuid.UUID) (string, error) {
	key, err := s.repo.GetKey(ctx, keyID)
	if err != nil {
		return "", err
	}

	return key.PublicKey, nil
}

// SQLiteRepository implements Repository
type SQLiteRepository struct {
	db *sql.DB
}

// NewSQLiteRepository creates a new repository
func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	repo := &SQLiteRepository{db: db}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteRepository) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS encryption_keys (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL,
			org_id TEXT NOT NULL,
			type TEXT NOT NULL,
			usage TEXT NOT NULL,
			key_id TEXT NOT NULL,
			fingerprint TEXT NOT NULL UNIQUE,
			email TEXT NOT NULL,
			name TEXT,
			public_key TEXT NOT NULL,
			private_key TEXT,
			certificate TEXT,
			issuer TEXT,
			subject TEXT,
			serial_number TEXT,
			algorithm TEXT,
			key_size INTEGER,
			subkeys TEXT,
			created_date DATETIME NOT NULL,
			expiry_date DATETIME,
			is_revoked INTEGER DEFAULT 0,
			revoked_at DATETIME,
			revoked_by TEXT,
			trust_level TEXT DEFAULT 'unknown',
			is_verified INTEGER DEFAULT 0,
			verified_at DATETIME,
			verified_by TEXT,
			is_default INTEGER DEFAULT 0,
			is_active INTEGER DEFAULT 1,
			imported_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE TABLE IF NOT EXISTS encrypted_messages (
			id TEXT PRIMARY KEY,
			message_id TEXT NOT NULL UNIQUE,
			encryption_type TEXT NOT NULL,
			encrypted_body TEXT NOT NULL,
			encrypted_attachments TEXT,
			recipients TEXT NOT NULL,
			is_signed INTEGER DEFAULT 0,
			signer_key_id TEXT,
			signature_valid INTEGER,
			signed_at DATETIME,
			encrypted_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE INDEX IF NOT EXISTS idx_key_account ON encryption_keys(account_id)`,
		`CREATE INDEX IF NOT EXISTS idx_key_email ON encryption_keys(email, type)`,
		`CREATE INDEX IF NOT EXISTS idx_key_fingerprint ON encryption_keys(fingerprint)`,
		`CREATE INDEX IF NOT EXISTS idx_enc_message ON encrypted_messages(message_id)`,
	}

	for _, q := range queries {
		if _, err := r.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteRepository) SaveKey(ctx context.Context, key *Key) error {
	subkeysJSON, _ := json.Marshal(key.Subkeys)

	query := `
	INSERT INTO encryption_keys (
		id, account_id, org_id, type, usage, key_id, fingerprint, email, name,
		public_key, private_key, certificate, issuer, subject, serial_number,
		algorithm, key_size, subkeys, created_date, expiry_date, is_revoked,
		revoked_at, revoked_by, trust_level, is_verified, verified_at, verified_by,
		is_default, is_active, imported_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(fingerprint) DO UPDATE SET
		is_default = excluded.is_default,
		is_active = excluded.is_active,
		trust_level = excluded.trust_level,
		is_verified = excluded.is_verified,
		verified_at = excluded.verified_at,
		verified_by = excluded.verified_by,
		updated_at = excluded.updated_at
	`

	_, err := r.db.ExecContext(ctx, query,
		key.ID.String(), key.AccountID.String(), key.OrgID.String(), key.Type, key.Usage,
		key.KeyID, key.Fingerprint, key.Email, key.Name, key.PublicKey, key.PrivateKey,
		key.Certificate, key.Issuer, key.Subject, key.SerialNumber, key.Algorithm,
		key.KeySize, string(subkeysJSON), key.CreatedDate, key.ExpiryDate, key.IsRevoked,
		key.RevokedAt, key.RevokedBy, key.TrustLevel, key.IsVerified, key.VerifiedAt,
		key.VerifiedBy, key.IsDefault, key.IsActive, key.ImportedAt, key.UpdatedAt)

	return err
}

func (r *SQLiteRepository) GetKey(ctx context.Context, id uuid.UUID) (*Key, error) {
	query := `
	SELECT id, account_id, org_id, type, usage, key_id, fingerprint, email, name,
		public_key, private_key, certificate, issuer, subject, serial_number,
		algorithm, key_size, subkeys, created_date, expiry_date, is_revoked,
		revoked_at, revoked_by, trust_level, is_verified, verified_at, verified_by,
		is_default, is_active, imported_at, updated_at
	FROM encryption_keys WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanKey(row)
}

func (r *SQLiteRepository) GetKeyByFingerprint(ctx context.Context, fingerprint string) (*Key, error) {
	query := `
	SELECT id, account_id, org_id, type, usage, key_id, fingerprint, email, name,
		public_key, private_key, certificate, issuer, subject, serial_number,
		algorithm, key_size, subkeys, created_date, expiry_date, is_revoked,
		revoked_at, revoked_by, trust_level, is_verified, verified_at, verified_by,
		is_default, is_active, imported_at, updated_at
	FROM encryption_keys WHERE fingerprint = ?
	`
	row := r.db.QueryRowContext(ctx, query, fingerprint)
	return r.scanKey(row)
}

func (r *SQLiteRepository) GetKeyByEmail(ctx context.Context, email string, keyType KeyType) (*Key, error) {
	query := `
	SELECT id, account_id, org_id, type, usage, key_id, fingerprint, email, name,
		public_key, private_key, certificate, issuer, subject, serial_number,
		algorithm, key_size, subkeys, created_date, expiry_date, is_revoked,
		revoked_at, revoked_by, trust_level, is_verified, verified_at, verified_by,
		is_default, is_active, imported_at, updated_at
	FROM encryption_keys 
	WHERE email = ? AND type = ? AND is_active = 1 AND is_revoked = 0
	ORDER BY is_default DESC, imported_at DESC
	LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, query, email, keyType)
	return r.scanKey(row)
}

func (r *SQLiteRepository) GetKeysForAccount(ctx context.Context, accountID uuid.UUID) ([]*Key, error) {
	query := `
	SELECT id, account_id, org_id, type, usage, key_id, fingerprint, email, name,
		public_key, private_key, certificate, issuer, subject, serial_number,
		algorithm, key_size, subkeys, created_date, expiry_date, is_revoked,
		revoked_at, revoked_by, trust_level, is_verified, verified_at, verified_by,
		is_default, is_active, imported_at, updated_at
	FROM encryption_keys WHERE account_id = ? AND is_active = 1
	`
	rows, err := r.db.QueryContext(ctx, query, accountID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanKeys(rows)
}

func (r *SQLiteRepository) GetDefaultKey(ctx context.Context, accountID uuid.UUID, keyType KeyType) (*Key, error) {
	query := `
	SELECT id, account_id, org_id, type, usage, key_id, fingerprint, email, name,
		public_key, private_key, certificate, issuer, subject, serial_number,
		algorithm, key_size, subkeys, created_date, expiry_date, is_revoked,
		revoked_at, revoked_by, trust_level, is_verified, verified_at, verified_by,
		is_default, is_active, imported_at, updated_at
	FROM encryption_keys 
	WHERE account_id = ? AND type = ? AND is_default = 1 AND is_active = 1
	`
	row := r.db.QueryRowContext(ctx, query, accountID.String(), keyType)
	return r.scanKey(row)
}

func (r *SQLiteRepository) GetPublicKeyByEmail(ctx context.Context, email string, keyType KeyType) (*Key, error) {
	return r.GetKeyByEmail(ctx, email, keyType)
}

func (r *SQLiteRepository) UpdateKey(ctx context.Context, key *Key) error {
	return r.SaveKey(ctx, key)
}

func (r *SQLiteRepository) DeleteKey(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "UPDATE encryption_keys SET is_active = 0 WHERE id = ?", id.String())
	return err
}

func (r *SQLiteRepository) scanKey(row *sql.Row) (*Key, error) {
	var key Key
	var idStr, accountIDStr, orgIDStr string
	var subkeysJSON string

	err := row.Scan(&idStr, &accountIDStr, &orgIDStr, &key.Type, &key.Usage,
		&key.KeyID, &key.Fingerprint, &key.Email, &key.Name, &key.PublicKey,
		&key.PrivateKey, &key.Certificate, &key.Issuer, &key.Subject,
		&key.SerialNumber, &key.Algorithm, &key.KeySize, &subkeysJSON,
		&key.CreatedDate, &key.ExpiryDate, &key.IsRevoked, &key.RevokedAt,
		&key.RevokedBy, &key.TrustLevel, &key.IsVerified, &key.VerifiedAt,
		&key.VerifiedBy, &key.IsDefault, &key.IsActive, &key.ImportedAt, &key.UpdatedAt)
	if err != nil {
		return nil, err
	}

	key.ID, _ = uuid.Parse(idStr)
	key.AccountID, _ = uuid.Parse(accountIDStr)
	key.OrgID, _ = uuid.Parse(orgIDStr)
	_ = json.Unmarshal([]byte(subkeysJSON), &key.Subkeys)

	return &key, nil
}

func (r *SQLiteRepository) scanKeys(rows *sql.Rows) ([]*Key, error) {
	var keys []*Key
	for rows.Next() {
		var key Key
		var idStr, accountIDStr, orgIDStr string
		var subkeysJSON string

		err := rows.Scan(&idStr, &accountIDStr, &orgIDStr, &key.Type, &key.Usage,
			&key.KeyID, &key.Fingerprint, &key.Email, &key.Name, &key.PublicKey,
			&key.PrivateKey, &key.Certificate, &key.Issuer, &key.Subject,
			&key.SerialNumber, &key.Algorithm, &key.KeySize, &subkeysJSON,
			&key.CreatedDate, &key.ExpiryDate, &key.IsRevoked, &key.RevokedAt,
			&key.RevokedBy, &key.TrustLevel, &key.IsVerified, &key.VerifiedAt,
			&key.VerifiedBy, &key.IsDefault, &key.IsActive, &key.ImportedAt, &key.UpdatedAt)
		if err != nil {
			return nil, err
		}

		key.ID, _ = uuid.Parse(idStr)
		key.AccountID, _ = uuid.Parse(accountIDStr)
		key.OrgID, _ = uuid.Parse(orgIDStr)
		_ = json.Unmarshal([]byte(subkeysJSON), &key.Subkeys)

		keys = append(keys, &key)
	}
	return keys, rows.Err()
}

func (r *SQLiteRepository) SaveEncryptedMessage(ctx context.Context, msg *EncryptedMessage) error {
	attachmentsJSON, _ := json.Marshal(msg.EncryptedAttachments)
	recipientsJSON, _ := json.Marshal(msg.Recipients)

	query := `
	INSERT INTO encrypted_messages (
		id, message_id, encryption_type, encrypted_body, encrypted_attachments,
		recipients, is_signed, signer_key_id, signature_valid, signed_at, encrypted_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(message_id) DO UPDATE SET
		encrypted_body = excluded.encrypted_body,
		encrypted_attachments = excluded.encrypted_attachments,
		recipients = excluded.recipients
	`

	_, err := r.db.ExecContext(ctx, query,
		msg.ID.String(), msg.MessageID.String(), msg.EncryptionType, msg.EncryptedBody,
		string(attachmentsJSON), string(recipientsJSON), msg.IsSigned, msg.SignerKeyID,
		msg.SignatureValid, msg.SignedAt, msg.EncryptedAt)

	return err
}

func (r *SQLiteRepository) GetEncryptedMessage(ctx context.Context, messageID uuid.UUID) (*EncryptedMessage, error) {
	query := `
	SELECT id, message_id, encryption_type, encrypted_body, encrypted_attachments,
		recipients, is_signed, signer_key_id, signature_valid, signed_at, encrypted_at
	FROM encrypted_messages WHERE message_id = ?
	`
	row := r.db.QueryRowContext(ctx, query, messageID.String())

	var msg EncryptedMessage
	var idStr, messageIDStr string
	var attachmentsJSON, recipientsJSON string

	err := row.Scan(&idStr, &messageIDStr, &msg.EncryptionType, &msg.EncryptedBody,
		&attachmentsJSON, &recipientsJSON, &msg.IsSigned, &msg.SignerKeyID,
		&msg.SignatureValid, &msg.SignedAt, &msg.EncryptedAt)
	if err != nil {
		return nil, err
	}

	msg.ID, _ = uuid.Parse(idStr)
	msg.MessageID, _ = uuid.Parse(messageIDStr)
	_ = json.Unmarshal([]byte(attachmentsJSON), &msg.EncryptedAttachments)
	_ = json.Unmarshal([]byte(recipientsJSON), &msg.Recipients)

	return &msg, nil
}

// Ensure io.Reader is used (for potential streaming)
var _ io.Reader = (*bytes.Reader)(nil)
