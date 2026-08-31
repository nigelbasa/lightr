package domain

import (
	"fmt"
	"strings"
)

func ValidateAccountAuthMode(dom *Domain, mode AuthMode) error {
	switch mode {
	case AuthModeNative:
		return nil
	case AuthModeOffloaded:
		if dom == nil {
			return fmt.Errorf("domain is required for offloaded authentication")
		}
		if strings.TrimSpace(dom.AuthWebhookURL) == "" {
			return fmt.Errorf("domain %s does not have an auth webhook configured", dom.Name)
		}
		if !dom.AuthWebhookVerified {
			return fmt.Errorf("domain %s auth webhook must be verified before using offloaded accounts", dom.Name)
		}
		return nil
	default:
		return fmt.Errorf("unsupported auth mode: %s", mode)
	}
}
