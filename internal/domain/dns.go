package domain

import (
	"fmt"
)

type DNSRecords struct {
	MX    []string `json:"mx"`
	SPF   string   `json:"spf"`
	DKIM  []string `json:"dkim"`
	DMARC string   `json:"dmarc"`
}

func GenerateRecommendedDNS(domainName, dkimSelector, dkimPublicKey string) *DNSRecords {
	return &DNSRecords{
		MX: []string{
			fmt.Sprintf("10 mail.%s", domainName),
		},
		SPF: fmt.Sprintf("v=spf1 mx ip4:%s -all", "YOUR_IP_HERE"), // SaaS would replace this
		DKIM: []string{
			fmt.Sprintf("%s._domainkey.%s IN TXT \"v=DKIM1; k=rsa; p=%s\"", dkimSelector, domainName, dkimPublicKey),
		},
		DMARC: fmt.Sprintf("_dmarc.%s IN TXT \"v=DMARC1; p=quarantine; adkim=s; aspf=s\"", domainName),
	}
}
