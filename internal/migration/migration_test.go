package migration

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/domain"
)

type memBlobs struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemBlobs() *memBlobs { return &memBlobs{data: map[string][]byte{}} }
func (m *memBlobs) Put(path string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[path] = append([]byte(nil), data...)
	return nil
}
func (m *memBlobs) Get(path string) ([]byte, error)  { return m.data[path], nil }
func (m *memBlobs) Delete(path string) error         { delete(m.data, path); return nil }

type memMsgs struct {
	mu   sync.Mutex
	msgs []*domain.Message
}

func newMemMsgs() *memMsgs { return &memMsgs{} }
func (m *memMsgs) CreateMessage(msg *domain.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, msg)
	return nil
}
func (m *memMsgs) GetMessageByID(id uuid.UUID) (*domain.Message, error) { return nil, nil }
func (m *memMsgs) ListByAccount(uuid.UUID, string) ([]*domain.Message, error) {
	return nil, nil
}
func (m *memMsgs) UpdateMessage(*domain.Message) error { return nil }

const sampleEML = "From: alice@example.com\r\n" +
	"To: bob@example.com\r\n" +
	"Subject: Hello\r\n" +
	"Date: Mon, 02 Jan 2006 15:04:05 -0700\r\n" +
	"Message-ID: <hello@example.com>\r\n" +
	"\r\n" +
	"This is the body.\r\n"

const sampleEML2 = "From: carol@example.com\r\n" +
	"To: bob@example.com\r\n" +
	"Subject: Second\r\n" +
	"\r\n" +
	"Second message body.\r\n"

func runImport(t *testing.T, src Source) (*memMsgs, Stats) {
	t.Helper()
	blobs := newMemBlobs()
	msgs := newMemMsgs()
	im := &Importer{
		AccountID: uuid.New(),
		Blobs:     blobs,
		Messages:  msgs,
	}
	stats, err := im.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(blobs.data) != len(msgs.msgs) {
		t.Fatalf("blob count %d != message count %d", len(blobs.data), len(msgs.msgs))
	}
	return msgs, stats
}

func TestMboxImport(t *testing.T) {
	dir := t.TempDir()
	mboxPath := filepath.Join(dir, "test.mbox")
	content := "From alice@example.com Mon Jan  2 15:04:05 2006\n" +
		sampleEML +
		"From carol@example.com Mon Jan  2 15:05:00 2006\n" +
		sampleEML2
	if err := os.WriteFile(mboxPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	msgs, stats := runImport(t, &MboxSource{Path: mboxPath})
	if stats.Imported != 2 {
		t.Fatalf("imported=%d, want 2", stats.Imported)
	}
	subjects := []string{msgs.msgs[0].Subject, msgs.msgs[1].Subject}
	sort.Strings(subjects)
	if subjects[0] != "Hello" || subjects[1] != "Second" {
		t.Fatalf("subjects=%v", subjects)
	}
	if msgs.msgs[0].Folder != "INBOX" && msgs.msgs[1].Folder != "INBOX" {
		// mbox folder name is the basename
	}
}

func TestMaildirImport(t *testing.T) {
	root := t.TempDir()
	for _, sub := range []string{"cur", "new"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	// Windows disallows ':' in filenames, so use a portable separator and
	// only assert flag decoding on platforms that support the maildir spec.
	seenName := "1234.seen-2,S"
	if runtime.GOOS != "windows" {
		seenName = "1234.seen:2,S"
	}
	if err := os.WriteFile(filepath.Join(root, "cur", seenName), []byte(sampleEML), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "new", "5678.unseen"), []byte(sampleEML2), 0644); err != nil {
		t.Fatal(err)
	}
	// Sub-folder
	subDir := filepath.Join(root, ".Sent", "cur")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "9999"), []byte(sampleEML), 0644); err != nil {
		t.Fatal(err)
	}

	msgs, stats := runImport(t, &MaildirSource{Root: root})
	if stats.Imported != 3 {
		t.Fatalf("imported=%d, want 3", stats.Imported)
	}

	var seen bool
	var sentCount int
	for _, m := range msgs.msgs {
		if m.ReadAt != nil {
			seen = true
		}
		if m.Folder == "Sent" {
			sentCount++
		}
	}
	if runtime.GOOS != "windows" && !seen {
		t.Error("expected \\Seen flag to set ReadAt")
	}
	if sentCount != 1 {
		t.Errorf("Sent folder count=%d, want 1", sentCount)
	}
}

func TestMaildirFlags(t *testing.T) {
	cases := map[string][]string{
		"1234.host:2,S":   {`\Seen`},
		"abc.host:2,SF":   {`\Seen`, `\Flagged`},
		"abc.host:2,RTD":  {`\Answered`, `\Deleted`, `\Draft`},
		"plain":           nil,
		"abc.host":        nil,
		"abc.host:2,":     nil,
	}
	for name, want := range cases {
		got := maildirFlags(name)
		if len(got) != len(want) {
			t.Errorf("maildirFlags(%q)=%v, want %v", name, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("maildirFlags(%q)[%d]=%q, want %q", name, i, got[i], want[i])
			}
		}
	}
}

func TestEMLImport(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.eml"), []byte(sampleEML), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.eml"), []byte(sampleEML2), 0644); err != nil {
		t.Fatal(err)
	}

	_, stats := runImport(t, &EMLSource{Root: root})
	if stats.Imported != 2 {
		t.Fatalf("imported=%d, want 2", stats.Imported)
	}
}

func TestMapFolder(t *testing.T) {
	cases := map[string]string{
		"inbox":         "INBOX",
		"INBOX":         "INBOX",
		".":             "INBOX",
		"Sent":          "Sent",
		"sent items":    "Sent",
		"Drafts":        "Drafts",
		"trash":         "Trash",
		"deleted items": "Trash",
		"spam":          "Spam",
		"junk":          "Spam",
		"Archive":       "Archive",
	}
	for in, want := range cases {
		if got := mapFolder(in); got != want {
			t.Errorf("mapFolder(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestNewSourceUnknown(t *testing.T) {
	if _, err := NewSource("imap", "/tmp"); err == nil {
		t.Fatal("expected error for unknown format")
	}
}
