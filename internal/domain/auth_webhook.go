package domain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

func EnsureAuthWebhookSecret(dom *Domain) error {
	if dom == nil || strings.TrimSpace(dom.AuthWebhookSecret) != "" {
		return nil
	}
	secret, err := GenerateAuthWebhookSecret()
	if err != nil {
		return err
	}
	dom.AuthWebhookSecret = secret
	return nil
}

func GenerateAuthWebhookSecret() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate auth webhook secret: %w", err)
	}
	return "ltrwh_" + hex.EncodeToString(buf), nil
}

func ResetAuthWebhookVerification(dom *Domain) {
	if dom == nil {
		return
	}
	dom.AuthWebhookVerified = false
	dom.AuthWebhookVerifiedAt = nil
}

func MarkAuthWebhookVerified(dom *Domain) {
	if dom == nil {
		return
	}
	now := time.Now().UTC()
	dom.AuthWebhookVerified = true
	dom.AuthWebhookVerifiedAt = &now
}
