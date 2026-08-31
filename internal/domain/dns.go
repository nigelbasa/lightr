package domain

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"
)

type DNSRecords struct {
	MX    []string `json:"mx"`
	SPF   string   `json:"spf"`
	DKIM  []string `json:"dkim"`
	DMARC string   `json:"dmarc"`
	PTR   string   `json:"ptr,omitempty"`
}

type DNSVerification struct {
	MX              bool     `json:"mx"`
	SPF             bool     `json:"spf"`
	DKIM            bool     `json:"dkim"`
	DMARC           bool     `json:"dmarc"`
	PTR             bool     `json:"ptr"`
	MXRecords       []string `json:"mx_records,omitempty"`
	TXTRecords      []string `json:"txt_records,omitempty"`
	DKIMTXTRecords  []string `json:"dkim_txt_records,omitempty"`
	DMARCTXTRecords []string `json:"dmarc_txt_records,omitempty"`
	PTRRecords      []string `json:"ptr_records,omitempty"`
}

func GenerateRecommendedDNS(domainName, mailHostname, dkimSelector string, dkimPublicKey []byte) *DNSRecords {
	dkimValue := ""
	if len(dkimPublicKey) > 0 {
		dkimValue = fmt.Sprintf("v=DKIM1; k=rsa; p=%s", base64.StdEncoding.EncodeToString(dkimPublicKey))
	}
	return &DNSRecords{
		MX: []string{
			fmt.Sprintf("10 %s", mailHostname),
		},
		SPF: fmt.Sprintf("v=spf1 mx a:%s -all", mailHostname),
		DKIM: []string{
			fmt.Sprintf("%s._domainkey.%s IN TXT \"%s\"", dkimSelector, domainName, dkimValue),
		},
		DMARC: fmt.Sprintf("_dmarc.%s IN TXT \"v=DMARC1; p=quarantine; adkim=s; aspf=s\"", domainName),
		PTR:   mailHostname,
	}
}

func VerifyRecommendedDNS(domainName, mailHostname, dkimSelector string, dkimPublicKey []byte) *DNSVerification {
	out := &DNSVerification{}
	normalizedMailHost := normalizeDNSName(mailHostname)
	recommended := GenerateRecommendedDNS(domainName, normalizedMailHost, dkimSelector, dkimPublicKey)

	if mxRecords, err := net.LookupMX(domainName); err == nil {
		for _, mx := range mxRecords {
			host := normalizeDNSName(mx.Host)
			out.MXRecords = append(out.MXRecords, host)
			if host == normalizedMailHost {
				out.MX = true
			}
		}
	}

	if txtRecords, err := net.LookupTXT(domainName); err == nil {
		for _, record := range txtRecords {
			normalized := normalizeTXTRecord(record)
			out.TXTRecords = append(out.TXTRecords, normalized)
			if normalized == normalizeTXTRecord(recommended.SPF) || (strings.HasPrefix(normalized, "v=spf1") && strings.Contains(normalized, "a:"+normalizedMailHost)) {
				out.SPF = true
			}
		}
	}

	dkimName := fmt.Sprintf("%s._domainkey.%s", dkimSelector, domainName)
	if txtRecords, err := net.LookupTXT(dkimName); err == nil {
		expected := ""
		if len(recommended.DKIM) > 0 {
			expected = normalizeTXTRecord(extractTXTValue(recommended.DKIM[0]))
		}
		for _, record := range txtRecords {
			normalized := normalizeTXTRecord(record)
			out.DKIMTXTRecords = append(out.DKIMTXTRecords, normalized)
			if expected != "" && normalized == expected {
				out.DKIM = true
			}
		}
	}

	dmarcName := "_dmarc." + domainName
	if txtRecords, err := net.LookupTXT(dmarcName); err == nil {
		for _, record := range txtRecords {
			normalized := normalizeTXTRecord(record)
			out.DMARCTXTRecords = append(out.DMARCTXTRecords, normalized)
			if normalized == normalizeTXTRecord(extractTXTValue(recommended.DMARC)) || strings.HasPrefix(normalized, "v=dmarc1") {
				out.DMARC = true
			}
		}
	}

	if ptrHostnames, err := lookupPTRRecords(normalizedMailHost); err == nil {
		for _, ptr := range ptrHostnames {
			host := normalizeDNSName(ptr)
			out.PTRRecords = append(out.PTRRecords, host)
			if host == normalizedMailHost {
				out.PTR = true
			}
		}
	}

	return out
}

func normalizeTXTRecord(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(value)), " "))
}

func normalizeDNSName(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func extractTXTValue(record string) string {
	if idx := strings.Index(record, " IN TXT "); idx != -1 {
		record = record[idx+8:]
	}
	record = strings.TrimSpace(record)
	record = strings.TrimPrefix(record, "\"")
	record = strings.TrimSuffix(record, "\"")
	return record
}

func lookupPTRRecords(mailHostname string) ([]string, error) {
	ips, err := net.LookupHost(mailHostname)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ip := range ips {
		names, err := net.LookupAddr(ip)
		if err != nil {
			continue
		}
		out = append(out, names...)
	}
	return out, nil
}
