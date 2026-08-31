package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"
	"github.com/nigelbasa/lightr/internal/config"
	"gopkg.in/yaml.v3"
)

type testInstall struct {
	root       string
	repoRoot   string
	exePath    string
	configPath string
	cfg        *config.Config
	httpURL    string
	smtpAddr   string
	submitAddr string
	imapAddr   string
}

type postgresContainer struct {
	dataDir string
	logFile string
	dsn     string
	port    string
}

type smtpSink struct {
	addr     string
	listener net.Listener
	server   *gosmtp.Server
	messages chan string
}

func TestEndToEndSQLiteAndPostgres(t *testing.T) {
	repoRoot := repoRootFromCaller(t)
	exePath := buildBinary(t, repoRoot)

	t.Run("sqlite", func(t *testing.T) {
		runEndToEndSuite(t, repoRoot, exePath, "sqlite", "")
	})

	t.Run("postgres", func(t *testing.T) {
		pg := startPostgresContainer(t)
		defer stopPostgresContainer(t, pg)
		runEndToEndSuite(t, repoRoot, exePath, "postgres", pg.dsn)
	})
}

func runEndToEndSuite(t *testing.T, repoRoot, exePath, driver, dsn string) {
	t.Helper()
	install := prepareInstall(t, repoRoot, exePath, driver, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	serverCmd, serverLogs := startServer(t, ctx, install)
	defer stopServer(t, serverCmd)
	waitForHealth(t, install.httpURL, install.cfg.API.AdminKey, serverLogs)

	adminKey := install.cfg.API.AdminKey

	domainID := createDomainViaAPI(t, install.httpURL, adminKey, map[string]any{
		"name": "mail.acme.test",
	})
	domainKey := createScopedKeyViaAPI(t, install.httpURL, adminKey, map[string]any{
		"name":   "domain-scope",
		"type":   "domain",
		"domain": "mail.acme.test",
	})

	createAccountViaAPI(t, install.httpURL, domainKey, map[string]any{
		"domain":      "mail.acme.test",
		"email":       "alice@mail.acme.test",
		"auth_mode":   "native",
		"password":    "secret123",
		"quota_bytes": 1048576,
	})
	createAccountViaAPI(t, install.httpURL, domainKey, map[string]any{
		"domain":      "mail.acme.test",
		"email":       "bob@mail.acme.test",
		"auth_mode":   "native",
		"password":    "secret123",
		"quota_bytes": 1048576,
	})
	aliceKey := createScopedKeyViaAPI(t, install.httpURL, adminKey, map[string]any{
		"name":    "alice-scope",
		"type":    "account",
		"account": "alice@mail.acme.test",
	})
	bobKey := createScopedKeyViaAPI(t, install.httpURL, adminKey, map[string]any{
		"name":    "bob-scope",
		"type":    "account",
		"account": "bob@mail.acme.test",
	})
	bridgeInbox := startSMTPSink(t)
	defer bridgeInbox.Close()
	_ = doJSONRequest(t, http.MethodPatch, fmt.Sprintf("%s/v1/domains/%s", install.httpURL, domainID), domainKey, map[string]any{
		"relay_enabled": true,
		"relay_host":    "127.0.0.1",
		"relay_port":    portFromAddr(t, bridgeInbox.addr),
	})
	runCLI(t, repoRoot, exePath, "--config", install.configPath, "alias", "create",
		"--domain", "mail.acme.test",
		"--source", "alice",
		"--type", "bridge",
		"--destinations", "alice.bridge@example.net",
	)

	sendInboundSMTP(t, install.smtpAddr, "sender@localhost", "alice@mail.acme.test", "Inbound hello")
	waitForMailboxCount(t, install.imapAddr, "alice@mail.acme.test", "secret123", 1)
	bridgedMirror := bridgeInbox.WaitForMessage(t)
	replyAddr := headerValueFromRaw(t, bridgedMirror, "Reply-To")
	if replyAddr == "" {
		t.Fatalf("expected Reply-To bridge token in mirrored message, got:\n%s", bridgedMirror)
	}

	aliceMessages := mailboxList(t, install.httpURL, aliceKey, "alice@mail.acme.test", "INBOX")
	if len(aliceMessages) != 1 {
		t.Fatalf("expected 1 alice message, got %d\nserver logs:\n%s", len(aliceMessages), serverLogs.String())
	}
	aliceMsgID := aliceMessages[0]["id"].(string)

	sendAuthenticatedSMTP(t, install.submitAddr, "alice@mail.acme.test", "secret123", "bob@mail.acme.test", "Local delivery")
	waitForMailboxCount(t, install.imapAddr, "bob@mail.acme.test", "secret123", 1)

	bobMessages := mailboxList(t, install.httpURL, bobKey, "bob@mail.acme.test", "INBOX")
	if len(bobMessages) != 1 {
		t.Fatalf("expected 1 bob message, got %d\nserver logs:\n%s", len(bobMessages), serverLogs.String())
	}

	markRead(t, install.httpURL, aliceKey, aliceMsgID, "alice@mail.acme.test", true)
	aliceMessages = mailboxList(t, install.httpURL, aliceKey, "alice@mail.acme.test", "INBOX")
	if read, ok := aliceMessages[0]["read"].(bool); !ok || !read {
		t.Fatalf("expected alice message to be marked read, got %#v", aliceMessages[0]["read"])
	}
	if status := stringValue(aliceMessages[0]["spam_status"]); !strings.Contains(strings.ToLower(status), "no") {
		t.Fatalf("expected clean inbound message in inbox, got spam_status=%q", status)
	}

	sendInboundSpamSMTP(t, install.smtpAddr, "spammer@example.net", "alice@mail.acme.test", "Urgent action")
	junkMessages := waitForMailboxFolderCount(t, install.httpURL, aliceKey, "alice@mail.acme.test", "Junk", 1)
	spamMsgID := stringValue(junkMessages[0]["id"])
	spamMessage := mailboxGet(t, install.httpURL, aliceKey, "alice@mail.acme.test", spamMsgID)
	metadata, _ := spamMessage["metadata"].(map[string]any)
	if metadata == nil {
		t.Fatalf("expected spam message metadata in mailbox get response")
	}
	if !strings.Contains(strings.ToLower(stringValue(metadata["spam_status"])), "yes") {
		t.Fatalf("expected spam_status=yes-like metadata, got %#v", metadata["spam_status"])
	}
	if stringValue(metadata["authentication_results"]) == "" {
		t.Fatalf("expected authentication_results metadata, got %#v", metadata)
	}
	if stringValue(metadata["remote_ip"]) == "" {
		t.Fatalf("expected remote_ip metadata, got %#v", metadata)
	}

	moveMessage(t, install.httpURL, aliceKey, aliceMsgID, "alice@mail.acme.test", "Junk")
	junkMessages = waitForMailboxFolderCount(t, install.httpURL, aliceKey, "alice@mail.acme.test", "Junk", 2)
	sendInboundSMTP(t, install.smtpAddr, "sender@localhost", "alice@mail.acme.test", "Trained sender")
	trainedSpam := waitForMailboxFolderCount(t, install.httpURL, aliceKey, "alice@mail.acme.test", "Junk", 3)
	latestTrained := mailboxGet(t, install.httpURL, aliceKey, "alice@mail.acme.test", stringValue(trainedSpam[len(trainedSpam)-1]["id"]))
	trainedMeta, _ := latestTrained["metadata"].(map[string]any)
	if trainedMeta == nil || !strings.Contains(strings.ToLower(stringValue(trainedMeta["spam_reasons"])), "user feedback") {
		t.Fatalf("expected user feedback to influence future sender classification, got %#v", trainedMeta)
	}
	moveMessage(t, install.httpURL, aliceKey, aliceMsgID, "alice@mail.acme.test", "INBOX")
	sendInboundSMTP(t, install.smtpAddr, "sender@localhost", "alice@mail.acme.test", "Sender restored")
	inboxMessages := waitForMailboxFolderCount(t, install.httpURL, aliceKey, "alice@mail.acme.test", "INBOX", 2)
	restored := mailboxGet(t, install.httpURL, aliceKey, "alice@mail.acme.test", stringValue(inboxMessages[len(inboxMessages)-1]["id"]))
	restoredMeta, _ := restored["metadata"].(map[string]any)
	if restoredMeta == nil || strings.Contains(strings.ToLower(stringValue(restoredMeta["spam_status"])), "yes") {
		t.Fatalf("expected sender to recover after ham training, got %#v", restoredMeta)
	}

	_ = doJSONRequest(t, http.MethodPatch, fmt.Sprintf("%s/v1/domains/%s", install.httpURL, domainID), domainKey, map[string]any{
		"spam_policy": "quarantine",
	})
	sendInboundSpamSMTP(t, install.smtpAddr, "quarantine@example.net", "alice@mail.acme.test", "Quarantine me")
	quarantineMessages := waitForMailboxFolderCount(t, install.httpURL, aliceKey, "alice@mail.acme.test", "Quarantine", 1)
	if len(quarantineMessages) < 1 {
		t.Fatalf("expected spam to land in quarantine")
	}

	_ = doJSONRequest(t, http.MethodPatch, fmt.Sprintf("%s/v1/domains/%s", install.httpURL, domainID), domainKey, map[string]any{
		"spam_policy": "reject",
	})
	sendInboundSpamSMTPExpectError(t, install.smtpAddr, "reject@example.net", "alice@mail.acme.test", "Reject me")
	_ = doJSONRequest(t, http.MethodPatch, fmt.Sprintf("%s/v1/domains/%s", install.httpURL, domainID), domainKey, map[string]any{
		"spam_policy": "junk",
	})

	stats := healthStats(t, repoRoot, exePath, install.configPath)
	if got := intFromAny(stats["total_orgs"]); got != 0 {
		t.Fatalf("expected totalorgs=0, got %d", got)
	}
	if got := intFromAny(stats["total_accounts"]); got != 2 {
		t.Fatalf("expected totalaccounts=2, got %d", got)
	}
	if got := intFromAny(stats["total_emails"]); got < 2 {
		t.Fatalf("expected totalemails>=2, got %d", got)
	}
	if got := intFromAny(stats["total_domains"]); got != 1 {
		t.Fatalf("expected totaldomains=1, got %d", got)
	}

	sink := startSMTPSink(t)
	defer sink.Close()

	_ = doJSONRequest(t, http.MethodPatch, fmt.Sprintf("%s/v1/domains/%s", install.httpURL, domainID), domainKey, map[string]any{
		"relay_enabled": true,
		"relay_host":    "127.0.0.1",
		"relay_port":    portFromAddr(t, sink.addr),
	})
	sendAuthenticatedSMTP(t, install.submitAddr, "alice@mail.acme.test", "secret123", "outside@example.net", "Relayed outbound")
	relayed := sink.WaitForMessage(t)
	if !strings.Contains(relayed, "Subject: Relayed outbound") {
		t.Fatalf("expected relayed message subject, got:\n%s", relayed)
	}
	if !strings.Contains(relayed, "outside@example.net") {
		t.Fatalf("expected relayed recipient in sink message, got:\n%s", relayed)
	}

	replySink := startSMTPSink(t)
	defer replySink.Close()
	_ = doJSONRequest(t, http.MethodPatch, fmt.Sprintf("%s/v1/domains/%s", install.httpURL, domainID), domainKey, map[string]any{
		"relay_enabled": true,
		"relay_host":    "127.0.0.1",
		"relay_port":    portFromAddr(t, replySink.addr),
	})
	sendInboundSMTP(t, install.smtpAddr, "alice.bridge@example.net", replyAddr, "Re: Inbound hello")
	bridgedReply := replySink.WaitForMessage(t)
	if !strings.Contains(bridgedReply, "sender@localhost") {
		t.Fatalf("expected bridged reply to target original sender, got:\n%s", bridgedReply)
	}
	if !strings.Contains(bridgedReply, "Re: Inbound hello") {
		t.Fatalf("expected bridged reply subject, got:\n%s", bridgedReply)
	}

	tlsSink := startSecureSMTPSink(t, "relay-user", "relay-pass")
	defer tlsSink.Close()
	_ = doJSONRequest(t, http.MethodPatch, fmt.Sprintf("%s/v1/domains/%s", install.httpURL, domainID), domainKey, map[string]any{
		"relay_enabled":         true,
		"relay_host":            "127.0.0.1",
		"relay_port":            portFromAddr(t, tlsSink.addr),
		"relay_username":        "relay-user",
		"relay_password":        "relay-pass",
		"relay_use_tls":         true,
		"relay_tls_skip_verify": true,
	})
	sendAuthenticatedSMTP(t, install.submitAddr, "alice@mail.acme.test", "secret123", "secure@example.net", "Secure relayed outbound")
	secureRelayed := tlsSink.WaitForMessage(t)
	if !strings.Contains(secureRelayed, "Subject: Secure relayed outbound") {
		t.Fatalf("expected secure relayed message subject, got:\n%s", secureRelayed)
	}
	if !strings.Contains(secureRelayed, "secure@example.net") {
		t.Fatalf("expected secure relayed recipient in sink message, got:\n%s", secureRelayed)
	}

}

func repoRootFromCaller(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve caller")
	}
	return filepath.Dir(filepath.Dir(file))
}

func buildBinary(t *testing.T, repoRoot string) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "lightr-e2e.exe")
	cmd := exec.Command("go", "build", "-o", exe, "./cmd/lightr")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build binary: %v\n%s", err, out)
	}
	return exe
}

func prepareInstall(t *testing.T, repoRoot, exePath, driver, dsn string) *testInstall {
	t.Helper()
	root := t.TempDir()
	cfgPath := filepath.Join(root, "lightr.yaml")
	runCLI(t, repoRoot, exePath, "--config", cfgPath, "init", "--data-dir", filepath.Join(root, "data"))

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	httpPort := freePort(t)
	smtpPort := freePort(t)
	submitPort := freePort(t)
	imapPort := freePort(t)

	cfg.Server.Hostname = "localhost"
	cfg.HTTP.Addr = fmt.Sprintf("127.0.0.1:%d", httpPort)
	cfg.SMTP.Addr = fmt.Sprintf("127.0.0.1:%d", smtpPort)
	cfg.SMTP.SubmissionAddr = fmt.Sprintf("127.0.0.1:%d", submitPort)
	cfg.SMTP.Domain = "mail.acme.test"
	cfg.SMTP.AllowInsecure = true
	cfg.IMAP.Addr = fmt.Sprintf("127.0.0.1:%d", imapPort)
	cfg.IMAP.TLSAddr = ""
	cfg.IMAP.AllowInsecure = true
	cfg.Security.RequireTLSForAuth = false
	cfg.Logging.File = filepath.Join(root, "lightr.log")
	cfg.Database.Driver = config.DatabaseDriver(strings.ToLower(driver))
	if driver == "postgres" {
		cfg.Database.DSN = dsn
		cfg.Database.Path = ""
	} else {
		cfg.Database.Path = filepath.Join(root, "data", "lightr.db")
	}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save config: %v", err)
	}

	return &testInstall{
		root:       root,
		repoRoot:   repoRoot,
		exePath:    exePath,
		configPath: cfgPath,
		cfg:        cfg,
		httpURL:    "http://" + cfg.HTTP.Addr,
		smtpAddr:   cfg.SMTP.Addr,
		submitAddr: cfg.SMTP.SubmissionAddr,
		imapAddr:   cfg.IMAP.Addr,
	}
}

func runCLI(t *testing.T, repoRoot, exePath string, args ...string) string {
	t.Helper()
	cmd := exec.Command(exePath, args...)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func startServer(t *testing.T, ctx context.Context, install *testInstall) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	cmd := exec.CommandContext(ctx, install.exePath, "--config", install.configPath, "serve")
	cmd.Dir = install.repoRoot
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	return cmd, &logs
}

func stopServer(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}

func waitForHealth(t *testing.T, baseURL, adminKey string, logs *bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/health", nil)
		if adminKey != "" {
			req.Header.Set("Authorization", "Bearer "+adminKey)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(200 * time.Millisecond)
	}
	if logs != nil {
		t.Fatalf("server at %s did not become healthy\nlogs:\n%s", baseURL, logs.String())
	}
	t.Fatalf("server at %s did not become healthy", baseURL)
}

func doJSONRequest(t *testing.T, method, url, apiKey string, body any) map[string]any {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		t.Fatalf("%s %s: status=%d body=%s", method, url, resp.StatusCode, string(data))
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal response: %v body=%s", err, data)
	}
	return out
}

func createScopedKeyViaAPI(t *testing.T, baseURL, apiKey string, body map[string]any) string {
	resp := doJSONRequest(t, http.MethodPost, baseURL+"/v1/apikeys", apiKey, body)
	secret := stringValue(resp["secret"])
	if secret == "" {
		t.Fatalf("expected secret in api key response, got %#v", resp)
	}
	return secret
}

func createDomainViaAPI(t *testing.T, baseURL, apiKey string, body map[string]any) string {
	resp := doJSONRequest(t, http.MethodPost, baseURL+"/v1/domains", apiKey, body)
	return stringValue(resp["id"])
}

func createAccountViaAPI(t *testing.T, baseURL, apiKey string, body map[string]any) {
	_ = doJSONRequest(t, http.MethodPost, baseURL+"/v1/accounts", apiKey, body)
}

func sendInboundSMTP(t *testing.T, addr, from, to, subject string) {
	t.Helper()
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s>\r\n\r\nhello inbound\r\n",
		from,
		to,
		subject,
		time.Now().Format(time.RFC1123Z),
		strings.ReplaceAll(fmt.Sprintf("%d@localhost", time.Now().UnixNano()), " ", ""),
	)
	if err := smtp.SendMail(addr, nil, from, []string{to}, []byte(msg)); err != nil {
		t.Fatalf("send inbound smtp: %v", err)
	}
}

func sendInboundSpamSMTP(t *testing.T, addr, from, to, subject string) {
	t.Helper()
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\nurgent action required click here for crypto investment lottery winner\r\n", from, to, subject)
	if err := smtp.SendMail(addr, nil, from, []string{to}, []byte(msg)); err != nil {
		t.Fatalf("send inbound spam smtp: %v", err)
	}
}

func sendInboundSpamSMTPExpectError(t *testing.T, addr, from, to, subject string) {
	t.Helper()
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\nurgent action required click here for crypto investment lottery winner\r\n", from, to, subject)
	if err := smtp.SendMail(addr, nil, from, []string{to}, []byte(msg)); err == nil {
		t.Fatalf("expected spam smtp send to be rejected")
	}
}

func sendAuthenticatedSMTP(t *testing.T, addr, username, password, to, subject string) {
	t.Helper()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	auth := smtp.PlainAuth("", username, password, host)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\nhello local outbound\r\n", username, to, subject)
	if err := smtp.SendMail(addr, auth, username, []string{to}, []byte(msg)); err != nil {
		t.Fatalf("send authenticated smtp: %v", err)
	}
}

func waitForMailboxCount(t *testing.T, addr, username, password string, expected int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		count, err := imapInboxCount(addr, username, password)
		if err == nil && count >= expected {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	count, err := imapInboxCount(addr, username, password)
	t.Fatalf("mailbox %s expected >= %d messages, got %d err=%v", username, expected, count, err)
}

func imapInboxCount(addr, username, password string) (int, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		return 0, err
	}
	if err := imapCommand(conn, reader, "a1 LOGIN %s %s\r\n", username, password); err != nil {
		return 0, err
	}
	count, err := imapSelect(conn, reader, "a2", "INBOX")
	if err != nil {
		return 0, err
	}
	_ = imapCommand(conn, reader, "a3 LOGOUT\r\n")
	return count, nil
}

func imapCommand(conn net.Conn, reader *bufio.Reader, format string, args ...any) error {
	tag := strings.Fields(fmt.Sprintf(format, args...))[0]
	if _, err := fmt.Fprintf(conn, format, args...); err != nil {
		return err
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.HasPrefix(line, tag+" ") {
			if strings.Contains(line, " OK ") || strings.HasSuffix(strings.TrimSpace(line), " OK") {
				return nil
			}
			if strings.Contains(line, " OK") {
				return nil
			}
			return errors.New(strings.TrimSpace(line))
		}
	}
}

func imapSelect(conn net.Conn, reader *bufio.Reader, tag, mailbox string) (int, error) {
	if _, err := fmt.Fprintf(conn, "%s SELECT %s\r\n", tag, mailbox); err != nil {
		return 0, err
	}
	count := 0
	re := regexp.MustCompile(`\* ([0-9]+) EXISTS`)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return 0, err
		}
		if match := re.FindStringSubmatch(line); len(match) == 2 {
			fmt.Sscanf(match[1], "%d", &count)
		}
		if strings.HasPrefix(line, tag+" ") {
			if strings.Contains(line, " OK ") || strings.Contains(line, " OK [") || strings.Contains(line, " OK\r") {
				return count, nil
			}
			return 0, errors.New(strings.TrimSpace(line))
		}
	}
}

func mailboxList(t *testing.T, baseURL, apiKey, email, folder string) []map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+"/v1/mailbox/messages?email="+email+"&folder="+folder, nil)
	if err != nil {
		t.Fatalf("mailbox list request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("mailbox list: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		t.Fatalf("mailbox list status=%d body=%s", resp.StatusCode, data)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("mailbox list decode: %v body=%s", err, data)
	}
	items, ok := out["messages"].([]any)
	if !ok {
		return nil
	}
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		result = append(result, item.(map[string]any))
	}
	return result
}

func waitForMailboxFolderCount(t *testing.T, baseURL, apiKey, email, folder string, expected int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		items := mailboxList(t, baseURL, apiKey, email, folder)
		if len(items) >= expected {
			return items
		}
		time.Sleep(250 * time.Millisecond)
	}
	items := mailboxList(t, baseURL, apiKey, email, folder)
	t.Fatalf("mailbox %s folder %s expected >= %d messages, got %d", email, folder, expected, len(items))
	return nil
}

func mailboxGet(t *testing.T, baseURL, apiKey, email, msgID string) map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/mailbox/messages/%s?email=%s", baseURL, msgID, email), nil)
	if err != nil {
		t.Fatalf("mailbox get request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("mailbox get: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		t.Fatalf("mailbox get status=%d body=%s", resp.StatusCode, data)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("mailbox get decode: %v body=%s", err, data)
	}
	return out
}

func markRead(t *testing.T, baseURL, apiKey, msgID, email string, read bool) {
	t.Helper()
	_ = doJSONRequest(t, http.MethodPatch, fmt.Sprintf("%s/v1/mailbox/messages/%s", baseURL, msgID), apiKey, map[string]any{
		"email": email,
		"read":  read,
	})
}

func moveMessage(t *testing.T, baseURL, apiKey, msgID, email, folder string) {
	t.Helper()
	_ = doJSONRequest(t, http.MethodPatch, fmt.Sprintf("%s/v1/mailbox/messages/%s", baseURL, msgID), apiKey, map[string]any{
		"email":  email,
		"read":   true,
		"folder": folder,
	})
}

func healthStats(t *testing.T, repoRoot, exePath, configPath string) map[string]any {
	t.Helper()
	cmd := exec.Command(exePath, "--config", configPath, "health", "stats")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("health stats: %v\n%s", err, out)
	}
	var result map[string]any
	if err := yaml.Unmarshal(out, &result); err != nil {
		t.Fatalf("decode health stats: %v\n%s", err, out)
	}
	return result
}

func startSMTPSink(t *testing.T) *smtpSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start smtp sink: %v", err)
	}
	sink := &smtpSink{
		addr:     ln.Addr().String(),
		listener: ln,
		messages: make(chan string, 4),
	}
	sink.server = gosmtp.NewServer(newSinkBackend(sink.messages, "", ""))
	sink.server.Domain = "sink.local"
	sink.server.AllowInsecureAuth = true
	go func() {
		_ = sink.server.Serve(ln)
	}()
	return sink
}

func startSecureSMTPSink(t *testing.T, username, password string) *smtpSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start secure smtp sink: %v", err)
	}
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate self-signed cert: %v", err)
	}
	sink := &smtpSink{
		addr:     ln.Addr().String(),
		listener: ln,
		messages: make(chan string, 4),
	}
	sink.server = gosmtp.NewServer(newSinkBackend(sink.messages, username, password))
	sink.server.Domain = "sink.local"
	sink.server.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	sink.server.AllowInsecureAuth = false
	go func() {
		_ = sink.server.Serve(ln)
	}()
	return sink
}

func (s *smtpSink) Close() {
	if s == nil {
		return
	}
	if s.server != nil {
		_ = s.server.Close()
		return
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
}

func (s *smtpSink) WaitForMessage(t *testing.T) string {
	t.Helper()
	select {
	case msg := <-s.messages:
		return msg
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for relayed SMTP message")
		return ""
	}
}

type sinkBackend struct {
	messages chan string
	username string
	password string
}

func newSinkBackend(messages chan string, username, password string) *sinkBackend {
	return &sinkBackend{messages: messages, username: username, password: password}
}

func (b *sinkBackend) NewSession(c *gosmtp.Conn) (gosmtp.Session, error) {
	return &sinkSession{backend: b}, nil
}

type sinkSession struct {
	backend *sinkBackend
	auth    bool
}

func (s *sinkSession) Reset() {}

func (s *sinkSession) Logout() error { return nil }

func (s *sinkSession) Mail(from string, opts *gosmtp.MailOptions) error {
	if s.backend.username != "" && !s.auth {
		return gosmtp.ErrAuthRequired
	}
	return nil
}

func (s *sinkSession) Rcpt(to string, opts *gosmtp.RcptOptions) error {
	if s.backend.username != "" && !s.auth {
		return gosmtp.ErrAuthRequired
	}
	return nil
}

func (s *sinkSession) Data(r io.Reader) error {
	if s.backend.username != "" && !s.auth {
		return gosmtp.ErrAuthRequired
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.backend.messages <- string(data)
	return nil
}

func (s *sinkSession) AuthMechanisms() []string {
	if s.backend.username == "" {
		return nil
	}
	return []string{sasl.Plain}
}

func (s *sinkSession) Auth(mech string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(identity, username, password string) error {
		if username != s.backend.username || password != s.backend.password {
			return errors.New("invalid username or password")
		}
		s.auth = true
		return nil
	}), nil
}

func portFromAddr(t *testing.T, addr string) int {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host/port for %s: %v", addr, err)
	}
	var out int
	if _, err := fmt.Sscanf(port, "%d", &out); err != nil {
		t.Fatalf("parse port %q: %v", port, err)
	}
	return out
}

func headerValueFromRaw(t *testing.T, raw, name string) string {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parse raw message headers: %v\n%s", err, raw)
	}
	value := strings.TrimSpace(msg.Header.Get(name))
	if value == "" {
		return ""
	}
	if addr, err := mail.ParseAddress(value); err == nil {
		return addr.Address
	}
	return value
}

func generateSelfSignedCert() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
	}, nil
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func startPostgresContainer(t *testing.T) *postgresContainer {
	t.Helper()
	port := fmt.Sprintf("%d", freePort(t))
	baseDir := t.TempDir()
	dataDir := filepath.Join(baseDir, "pgdata")
	logFile := filepath.Join(baseDir, "postgres.log")
	init := exec.Command("initdb", "-D", dataDir, "-U", "postgres", "-A", "trust", "--no-locale")
	out, err := init.CombinedOutput()
	if err != nil {
		t.Fatalf("initdb: %v\n%s", err, out)
	}
	start := exec.Command("pg_ctl", "-D", dataDir, "-o", fmt.Sprintf("-F -p %s", port), "-l", logFile, "start")
	if err := start.Run(); err != nil {
		logData, _ := os.ReadFile(logFile)
		t.Fatalf("pg_ctl start: %v\n%s", err, logData)
	}
	dsn := fmt.Sprintf("postgres://postgres@127.0.0.1:%s/postgres?sslmode=disable", port)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		check := exec.Command("psql", dsn, "-c", "select 1")
		if err := check.Run(); err == nil {
			return &postgresContainer{dataDir: dataDir, logFile: logFile, dsn: dsn, port: port}
		}
		time.Sleep(500 * time.Millisecond)
	}
	stopPostgresContainer(t, &postgresContainer{dataDir: dataDir, logFile: logFile})
	t.Fatalf("postgres cluster did not become ready")
	return nil
}

func stopPostgresContainer(t *testing.T, pg *postgresContainer) {
	t.Helper()
	if pg == nil || strings.TrimSpace(pg.dataDir) == "" {
		return
	}
	_ = exec.Command("pg_ctl", "-D", pg.dataDir, "stop", "-m", "immediate").Run()
}

func stringValue(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func intFromAny(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}
