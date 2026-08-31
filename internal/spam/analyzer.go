package spam

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/authres"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"github.com/nigelbasa/lightr/internal/security"
)

type Verdict string

const (
	VerdictClean      Verdict = "clean"
	VerdictSuspicious Verdict = "suspicious"
	VerdictSpam       Verdict = "spam"
)

type Report struct {
	RemoteIP        string
	Helo            string
	EnvelopeFrom    string
	HeaderFrom      string
	Date            string
	MessageID       string
	ReturnPath      string
	MailedBy        string
	SignedBy        []string
	ReplyTo         string
	Sender          string
	SPFResult       string
	DKIMResult      string
	DMARCResult     string
	DMARCPolicy     string
	DNSBLHits       []string
	Links           []string
	ExternalScore   float64
	ExternalSource  string
	ExternalVerdict string
	AuthResults     string
	SpamScore       float64
	Verdict         Verdict
	Reasons         []string
	HeaderSummaries map[string]string
}

type SPFChecker interface {
	Check(ctx context.Context, ip net.IP, domain, helo string) (security.SPFResult, string)
}

type DNSResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type ExternalScanner interface {
	Check(ctx context.Context, req *CheckRequest) (*ExternalCheckResult, error)
}

type FeedbackStore interface {
	FeedbackScore(ctx context.Context, senderEmail, senderDomain string) (float64, []string, error)
	RecordFeedback(ctx context.Context, senderEmail, senderDomain string, isSpam bool) error
}

type Config struct {
	SuspiciousThreshold float64
	JunkThreshold       float64
	DNSBLZones          []string
	Timeout             time.Duration
}

type CheckRequest struct {
	Raw          []byte
	RemoteIP     string
	Helo         string
	EnvelopeFrom string
	HeaderFrom   string
}

type ExternalCheckResult struct {
	Source  string
	Score   float64
	Verdict string
	Reasons []string
}

type Analyzer struct {
	cfg      Config
	spf      SPFChecker
	resolver DNSResolver
	external ExternalScanner
	feedback FeedbackStore
}

func NewAnalyzer() *Analyzer {
	return NewAnalyzerWithConfig(Config{})
}

func NewAnalyzerWithConfig(cfg Config) *Analyzer {
	if cfg.SuspiciousThreshold == 0 {
		cfg.SuspiciousThreshold = 2.0
	}
	if cfg.JunkThreshold == 0 {
		cfg.JunkThreshold = 4.0
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.JunkThreshold < cfg.SuspiciousThreshold {
		cfg.JunkThreshold = cfg.SuspiciousThreshold
	}
	return &Analyzer{
		cfg:      cfg,
		spf:      security.NewSPFChecker(),
		resolver: net.DefaultResolver,
	}
}

func (a *Analyzer) WithResolver(resolver DNSResolver) *Analyzer {
	if resolver != nil {
		a.resolver = resolver
	}
	return a
}

func (a *Analyzer) WithSPFChecker(spf SPFChecker) *Analyzer {
	if spf != nil {
		a.spf = spf
	}
	return a
}

func (a *Analyzer) WithExternalScanner(scanner ExternalScanner) *Analyzer {
	a.external = scanner
	return a
}

func (a *Analyzer) WithFeedbackStore(store FeedbackStore) *Analyzer {
	a.feedback = store
	return a
}

func (a *Analyzer) Analyze(ctx context.Context, raw []byte, envelopeFrom string, remoteIP net.IP, helo, authservID string) *Report {
	if a == nil {
		a = NewAnalyzer()
	}
	if a.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.cfg.Timeout)
		defer cancel()
	}
	report := &Report{
		RemoteIP:        ipString(remoteIP),
		Helo:            helo,
		EnvelopeFrom:    strings.TrimSpace(envelopeFrom),
		HeaderSummaries: map[string]string{},
	}

	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err == nil {
		report.HeaderFrom = msg.Header.Get("From")
		report.Date = msg.Header.Get("Date")
		report.MessageID = msg.Header.Get("Message-Id")
		if report.MessageID == "" {
			report.MessageID = msg.Header.Get("Message-ID")
		}
		report.ReturnPath = trimAddress(msg.Header.Get("Return-Path"))
		report.ReplyTo = trimAddress(msg.Header.Get("Reply-To"))
		report.Sender = trimAddress(msg.Header.Get("Sender"))
		for _, key := range []string{"From", "To", "Cc", "Bcc", "Subject", "Date", "Message-ID", "Message-Id", "Return-Path", "Reply-To", "Sender", "Received-SPF", "DKIM-Signature", "ARC-Seal", "ARC-Message-Signature", "ARC-Authentication-Results"} {
			if value := msg.Header.Get(key); value != "" {
				report.HeaderSummaries[key] = value
			}
		}
	}

	mailFromDomain := addressDomain(firstNonEmpty(report.ReturnPath, report.EnvelopeFrom))
	fromDomain := addressDomain(report.HeaderFrom)
	report.MailedBy = firstNonEmpty(mailFromDomain, fromDomain)

	if remoteIP != nil && a.spf != nil {
		spfResult, _ := a.spf.Check(ctx, remoteIP, mailFromDomain, helo)
		report.SPFResult = string(spfResult)
	}

	verifications, verifyErr := dkim.Verify(bytes.NewReader(raw))
	dkimPass := false
	if verifyErr == nil || len(verifications) > 0 {
		for _, verification := range verifications {
			if verification == nil {
				continue
			}
			if verification.Domain != "" {
				report.SignedBy = appendIfMissing(report.SignedBy, verification.Domain)
			}
			if verification.Err == nil {
				dkimPass = true
			}
		}
	}
	report.DKIMResult = "none"
	switch {
	case dkimPass:
		report.DKIMResult = "pass"
	case verifyErr != nil:
		report.DKIMResult = "fail"
	}

	report.DMARCResult = "none"
	report.DMARCPolicy = "none"
	if fromDomain != "" {
		if record, err := dmarc.Lookup(fromDomain); err == nil && record != nil {
			report.DMARCPolicy = string(record.Policy)
			spfAligned := aligned(fromDomain, mailFromDomain)
			dkimAligned := false
			for _, domain := range report.SignedBy {
				if aligned(fromDomain, domain) && report.DKIMResult == "pass" {
					dkimAligned = true
					break
				}
			}
			if spfAligned || dkimAligned {
				report.DMARCResult = "pass"
			} else {
				report.DMARCResult = "fail"
			}
		}
	}

	report.DNSBLHits = a.lookupDNSBL(ctx, remoteIP)
	report.Links = extractLinks(raw)
	if a.feedback != nil {
		if score, reasons, err := a.feedback.FeedbackScore(ctx, trimAddress(firstNonEmpty(report.HeaderFrom, report.ReturnPath, report.EnvelopeFrom)), fromDomain); err == nil {
			report.ExternalScore += score
			if score != 0 {
				report.ExternalSource = firstNonEmpty(report.ExternalSource, "lightr-feedback")
			}
			for _, reason := range reasons {
				report.Reasons = appendIfMissing(report.Reasons, reason)
			}
		}
	}
	if a.external != nil {
		if ext, err := a.external.Check(ctx, &CheckRequest{
			Raw:          raw,
			RemoteIP:     report.RemoteIP,
			Helo:         report.Helo,
			EnvelopeFrom: report.EnvelopeFrom,
			HeaderFrom:   report.HeaderFrom,
		}); err == nil && ext != nil {
			report.ExternalScore = ext.Score
			report.ExternalSource = ext.Source
			report.ExternalVerdict = ext.Verdict
			for _, reason := range ext.Reasons {
				report.Reasons = appendIfMissing(report.Reasons, reason)
			}
		}
	}

	a.scoreAndClassify(raw, report)
	report.AuthResults = formatAuthResults(authservID, report, mailFromDomain, fromDomain)
	return report
}

func Annotate(raw []byte, report *Report) []byte {
	if report == nil {
		return raw
	}
	var buf bytes.Buffer
	writeHeader(&buf, "Authentication-Results", report.AuthResults)
	writeHeader(&buf, "X-Spam-Score", fmt.Sprintf("%.2f", report.SpamScore))
	writeHeader(&buf, "X-Spam-Status", fmt.Sprintf("%s, verdict=%s", spamYesNo(report.Verdict), report.Verdict))
	writeHeader(&buf, "X-Lightr-Mailed-By", report.MailedBy)
	if len(report.SignedBy) > 0 {
		writeHeader(&buf, "X-Lightr-Signed-By", strings.Join(report.SignedBy, ", "))
	}
	if report.RemoteIP != "" {
		writeHeader(&buf, "X-Lightr-Remote-IP", report.RemoteIP)
	}
	if len(report.DNSBLHits) > 0 {
		writeHeader(&buf, "X-Lightr-DNSBL-Hits", strings.Join(report.DNSBLHits, ", "))
	}
	if report.ExternalSource != "" {
		writeHeader(&buf, "X-Lightr-External-Spam-Source", report.ExternalSource)
		writeHeader(&buf, "X-Lightr-External-Spam-Score", fmt.Sprintf("%.2f", report.ExternalScore))
	}
	if len(report.Reasons) > 0 {
		writeHeader(&buf, "X-Lightr-Spam-Reasons", strings.Join(report.Reasons, "; "))
	}
	buf.Write(raw)
	return buf.Bytes()
}

func (a *Analyzer) scoreAndClassify(raw []byte, report *Report) {
	score := 0.0
	switch report.SPFResult {
	case "fail":
		score += 2.5
		report.Reasons = append(report.Reasons, "spf failed")
	case "softfail":
		score += 1.5
		report.Reasons = append(report.Reasons, "spf softfail")
	case "none":
		score += 0.4
	}
	switch report.DKIMResult {
	case "fail":
		score += 1.5
		report.Reasons = append(report.Reasons, "dkim failed")
	case "none":
		score += 0.6
	}
	if report.DMARCResult == "fail" {
		score += 2.0
		report.Reasons = append(report.Reasons, "dmarc failed")
		if report.DMARCPolicy == "reject" || report.DMARCPolicy == "quarantine" {
			score += 1.0
		}
	}
	if len(report.DNSBLHits) > 0 {
		score += 1.5 * float64(len(report.DNSBLHits))
		report.Reasons = append(report.Reasons, "listed on dnsbl")
	}
	if len(report.Links) >= 6 {
		score += 0.8
		report.Reasons = append(report.Reasons, "many links")
	}
	if report.ReplyTo != "" && report.HeaderFrom != "" && !aligned(addressDomain(report.HeaderFrom), addressDomain(report.ReplyTo)) {
		score += 0.8
		report.Reasons = append(report.Reasons, "from/reply-to mismatch")
	}
	if report.ExternalScore != 0 {
		score += report.ExternalScore
		if report.ExternalSource != "" {
			report.Reasons = appendIfMissing(report.Reasons, "external spam scanner: "+report.ExternalSource)
		}
	}
	if report.MessageID == "" {
		score += 0.7
		report.Reasons = append(report.Reasons, "missing message-id")
	}
	if report.Date == "" {
		score += 0.4
		report.Reasons = append(report.Reasons, "missing date")
	}
	bodyPreview := extractBodyPreview(raw)
	suspiciousTokens := []string{"viagra", "winner", "lottery", "urgent action", "crypto investment", "click here", "act now"}
	lowerBody := strings.ToLower(bodyPreview)
	for _, token := range suspiciousTokens {
		if strings.Contains(lowerBody, token) {
			score += 0.8
			report.Reasons = append(report.Reasons, "suspicious content")
			break
		}
	}
	if report.HeaderFrom != "" && report.ReturnPath != "" && !aligned(addressDomain(report.HeaderFrom), addressDomain(report.ReturnPath)) {
		score += 0.6
		report.Reasons = append(report.Reasons, "from/return-path mismatch")
	}

	report.SpamScore = score
	suspiciousThreshold := 2.0
	junkThreshold := 4.0
	if a != nil {
		if a.cfg.SuspiciousThreshold > 0 {
			suspiciousThreshold = a.cfg.SuspiciousThreshold
		}
		if a.cfg.JunkThreshold > 0 {
			junkThreshold = a.cfg.JunkThreshold
		}
	}
	switch {
	case score >= junkThreshold:
		report.Verdict = VerdictSpam
	case score >= suspiciousThreshold:
		report.Verdict = VerdictSuspicious
	default:
		report.Verdict = VerdictClean
	}
}

func formatAuthResults(authservID string, report *Report, mailFromDomain, fromDomain string) string {
	results := []authres.Result{}
	if report.SPFResult != "" {
		results = append(results, &authres.SPFResult{
			Value:  authres.ResultValue(report.SPFResult),
			From:   mailFromDomain,
			Helo:   report.Helo,
			Reason: strings.Join(report.Reasons, ", "),
		})
	}
	if report.DKIMResult != "" && report.DKIMResult != "none" {
		domain := ""
		if len(report.SignedBy) > 0 {
			domain = report.SignedBy[0]
		}
		results = append(results, &authres.DKIMResult{
			Value:  authres.ResultValue(report.DKIMResult),
			Domain: domain,
		})
	}
	if report.DMARCResult != "" && report.DMARCResult != "none" {
		results = append(results, &authres.DMARCResult{
			Value: authres.ResultValue(report.DMARCResult),
			From:  fromDomain,
		})
	}
	if len(results) == 0 {
		return ""
	}
	return authres.Format(firstNonEmpty(authservID, "lightr"), results)
}

func extractBodyPreview(raw []byte) string {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return string(raw)
	}
	body, _ := io.ReadAll(msg.Body)
	if len(body) > 4096 {
		body = body[:4096]
	}
	return string(body)
}

func extractLinks(raw []byte) []string {
	preview := extractBodyPreview(raw)
	fields := strings.Fields(preview)
	seen := map[string]bool{}
	var out []string
	for _, field := range fields {
		field = strings.Trim(field, "\"'()<>[],.;")
		if !strings.Contains(field, "://") {
			continue
		}
		if u, err := url.Parse(field); err == nil && u.Host != "" {
			key := strings.ToLower(u.Host)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, u.Host)
		}
	}
	return out
}

func ApplyUserClassification(raw []byte, folder string) []byte {
	classification := ""
	status := ""
	switch strings.ToUpper(strings.TrimSpace(folder)) {
	case "JUNK", "SPAM":
		classification = "spam"
		status = "Yes, verdict=spam, user=true"
	case "INBOX":
		classification = "ham"
		status = "No, verdict=clean, user=true"
	default:
		return raw
	}

	header, body := splitMessage(raw)
	filtered := make([]string, 0, len(header))
	for _, line := range header {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "x-lightr-user-classification:") || strings.HasPrefix(lower, "x-spam-status:") {
			continue
		}
		filtered = append(filtered, line)
	}

	var buf bytes.Buffer
	writeHeader(&buf, "X-Lightr-User-Classification", classification)
	writeHeader(&buf, "X-Spam-Status", status)
	for _, line := range filtered {
		buf.WriteString(line)
		buf.WriteString("\r\n")
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
}

func SenderIdentity(raw []byte, envelopeFrom string) (string, string) {
	headerFrom := ""
	if msg, err := mail.ReadMessage(bytes.NewReader(raw)); err == nil {
		headerFrom = trimAddress(firstNonEmpty(msg.Header.Get("From"), msg.Header.Get("Reply-To"), msg.Header.Get("Sender")))
	}
	senderEmail := trimAddress(firstNonEmpty(headerFrom, envelopeFrom))
	return senderEmail, addressDomain(senderEmail)
}

func addressDomain(raw string) string {
	raw = trimAddress(raw)
	parts := strings.Split(raw, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parts[1]))
}

func trimAddress(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if addr, err := mail.ParseAddress(raw); err == nil {
		return addr.Address
	}
	return strings.Trim(raw, "<>")
}

func aligned(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if a == "" || b == "" {
		return false
	}
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

func appendIfMissing(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if strings.EqualFold(existing, value) {
			return values
		}
	}
	return append(values, value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func writeHeader(buf *bytes.Buffer, key, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	buf.WriteString(key)
	buf.WriteString(": ")
	buf.WriteString(value)
	buf.WriteString("\r\n")
}

func spamYesNo(verdict Verdict) string {
	if verdict == VerdictSpam {
		return "Yes"
	}
	return "No"
}

func HeaderMetadata(raw []byte) map[string]string {
	out := map[string]string{}
	msg, err := mail.ReadMessage(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return out
	}
	for _, key := range []string{
		"Authentication-Results", "X-Spam-Score", "X-Spam-Status", "X-Lightr-Mailed-By",
		"X-Lightr-Signed-By", "X-Lightr-Remote-IP", "X-Lightr-DNSBL-Hits",
		"X-Lightr-External-Spam-Source", "X-Lightr-External-Spam-Score", "X-Lightr-Spam-Reasons", "X-Lightr-User-Classification",
		"Date", "Message-ID", "Message-Id", "Return-Path", "Reply-To", "Sender", "Received-SPF",
		"DKIM-Signature", "ARC-Seal", "ARC-Message-Signature", "ARC-Authentication-Results",
	} {
		if value := msg.Header.Get(key); value != "" {
			out[key] = value
		}
	}
	return out
}

func (a *Analyzer) lookupDNSBL(ctx context.Context, ip net.IP) []string {
	if a == nil || a.resolver == nil || len(a.cfg.DNSBLZones) == 0 || ip == nil {
		return nil
	}
	reversed := reverseIPv4(ip)
	if reversed == "" {
		return nil
	}
	var hits []string
	for _, zone := range a.cfg.DNSBLZones {
		zone = strings.TrimSpace(zone)
		if zone == "" {
			continue
		}
		if addrs, err := a.resolver.LookupHost(ctx, reversed+"."+zone); err == nil && len(addrs) > 0 {
			hits = append(hits, zone)
		}
	}
	return hits
}

func reverseIPv4(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0])
}

func splitMessage(raw []byte) ([]string, []byte) {
	normalized := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	parts := bytes.SplitN(normalized, []byte("\n\n"), 2)
	if len(parts) != 2 {
		return strings.Split(string(bytes.TrimSpace(parts[0])), "\n"), nil
	}
	headerLines := strings.Split(string(parts[0]), "\n")
	body := bytes.ReplaceAll(parts[1], []byte("\n"), []byte("\r\n"))
	return headerLines, body
}
