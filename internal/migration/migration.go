// Package migration imports email from external mailbox formats (mbox, maildir,
// raw .eml directories) into a lightr account.
//
// Imported mail bypasses spam scanning, alias routing, and webhook delivery —
// bulk operator-initiated imports are trusted and shouldn't trigger user-facing
// notifications. Quota accounting still happens via the message rows.
package migration

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/domain"
)

// Source iterates messages from an external mailbox format.
type Source interface {
	// Folders returns the folder identifiers available in this source.
	Folders(ctx context.Context) ([]string, error)
	// Iterate calls fn for each message in folder. fn receives the raw RFC822
	// bytes and any IMAP flags decoded from the source. Iteration stops on
	// context cancellation or fn returning a non-nil error.
	Iterate(ctx context.Context, folder string, fn func(raw []byte, flags []string) error) error
}

// Stats summarizes the outcome of an import run.
type Stats struct {
	Folders  int
	Imported int
	Failed   int
}

// Importer drives a Source into lightr's storage layer.
type Importer struct {
	AccountID uuid.UUID
	// Folder, if set, overrides the per-source folder mapping; every message
	// goes here instead.
	Folder   string
	Blobs    domain.BlobStorage
	Messages domain.MessageRepository
	// OnError is called for non-fatal per-message failures. May be nil.
	OnError func(folder string, err error)
}

// Run drives the import. Returns when the source is exhausted or ctx is
// cancelled.
func (im *Importer) Run(ctx context.Context, src Source) (Stats, error) {
	var st Stats
	folders, err := src.Folders(ctx)
	if err != nil {
		return st, fmt.Errorf("list folders: %w", err)
	}
	for _, folder := range folders {
		if err := ctx.Err(); err != nil {
			return st, err
		}
		st.Folders++
		target := im.Folder
		if target == "" {
			target = mapFolder(folder)
		}
		err := src.Iterate(ctx, folder, func(raw []byte, flags []string) error {
			if err := im.store(raw, target, flags); err != nil {
				st.Failed++
				if im.OnError != nil {
					im.OnError(folder, err)
				}
				return nil
			}
			st.Imported++
			return nil
		})
		if err != nil {
			return st, fmt.Errorf("folder %q: %w", folder, err)
		}
	}
	return st, nil
}

func (im *Importer) store(raw []byte, folder string, flags []string) error {
	id := uuid.New()
	path := id.String() + ".eml"
	if err := im.Blobs.Put(path, raw); err != nil {
		return fmt.Errorf("put blob: %w", err)
	}

	subject, from, to, receivedAt := parseHeaders(raw)

	var readAt *time.Time
	for _, f := range flags {
		if f == `\Seen` {
			now := time.Now()
			readAt = &now
			break
		}
	}

	msg := &domain.Message{
		ID:          id,
		AccountID:   im.AccountID,
		Folder:      folder,
		SizeBytes:   int64(len(raw)),
		StoragePath: path,
		Subject:     subject,
		From:        from,
		To:          to,
		ReceivedAt:  receivedAt,
		ReadAt:      readAt,
	}
	return im.Messages.CreateMessage(msg)
}

func parseHeaders(raw []byte) (subject, from, to string, received time.Time) {
	received = time.Now()
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return
	}
	subject = msg.Header.Get("Subject")
	from = msg.Header.Get("From")
	to = msg.Header.Get("To")
	if d, err := mail.ParseDate(msg.Header.Get("Date")); err == nil {
		received = d
	}
	return
}

// mapFolder maps common source folder names to lightr's canonical folders.
func mapFolder(name string) string {
	switch strings.ToLower(name) {
	case "", ".", "inbox", "cur", "new":
		return "INBOX"
	case "sent", "sent items", "sent mail":
		return "Sent"
	case "drafts":
		return "Drafts"
	case "trash", "deleted items", "deleted":
		return "Trash"
	case "spam", "junk":
		return "Spam"
	default:
		return name
	}
}

// MboxSource imports from an mbox file.
type MboxSource struct {
	Path string
}

func (s *MboxSource) Folders(_ context.Context) ([]string, error) {
	if _, err := os.Stat(s.Path); err != nil {
		return nil, err
	}
	return []string{filepath.Base(s.Path)}, nil
}

func (s *MboxSource) Iterate(ctx context.Context, _ string, fn func(raw []byte, flags []string) error) error {
	f, err := os.Open(s.Path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 64*1024*1024)

	var current strings.Builder
	inMessage := false
	flush := func() error {
		if !inMessage || current.Len() == 0 {
			return nil
		}
		return fn([]byte(current.String()), nil)
	}

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := scanner.Text()
		if strings.HasPrefix(line, "From ") {
			if err := flush(); err != nil {
				return err
			}
			current.Reset()
			inMessage = true
			continue
		}
		if inMessage {
			current.WriteString(line)
			current.WriteByte('\n')
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return flush()
}

// MaildirSource imports from a Maildir++ tree.
type MaildirSource struct {
	Root string
}

func (s *MaildirSource) Folders(_ context.Context) ([]string, error) {
	var folders []string
	if hasDir(filepath.Join(s.Root, "cur")) || hasDir(filepath.Join(s.Root, "new")) {
		folders = append(folders, ".")
	}
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), ".") {
			continue
		}
		name := strings.TrimPrefix(e.Name(), ".")
		if name == "" {
			continue
		}
		folders = append(folders, name)
	}
	return folders, nil
}

func (s *MaildirSource) Iterate(ctx context.Context, folder string, fn func(raw []byte, flags []string) error) error {
	base := s.Root
	if folder != "." {
		base = filepath.Join(s.Root, "."+folder)
	}
	for _, sub := range []string{"cur", "new"} {
		dir := filepath.Join(base, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.IsDir() {
				continue
			}
			full := filepath.Join(dir, entry.Name())
			data, err := os.ReadFile(full)
			if err != nil {
				continue
			}
			if err := fn(data, maildirFlags(entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func maildirFlags(name string) []string {
	idx := strings.Index(name, ":2,")
	if idx < 0 {
		return nil
	}
	var flags []string
	for _, c := range name[idx+3:] {
		switch c {
		case 'S':
			flags = append(flags, `\Seen`)
		case 'F':
			flags = append(flags, `\Flagged`)
		case 'R':
			flags = append(flags, `\Answered`)
		case 'T':
			flags = append(flags, `\Deleted`)
		case 'D':
			flags = append(flags, `\Draft`)
		}
	}
	return flags
}

// EMLSource imports from a directory of .eml files. Each directory containing
// at least one .eml becomes a folder; nested directories become nested folders.
type EMLSource struct {
	Root string
}

func (s *EMLSource) Folders(_ context.Context) ([]string, error) {
	var folders []string
	err := filepath.WalkDir(s.Root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		entries, _ := os.ReadDir(path)
		for _, e := range entries {
			if strings.HasSuffix(strings.ToLower(e.Name()), ".eml") {
				rel, _ := filepath.Rel(s.Root, path)
				folders = append(folders, rel)
				return nil
			}
		}
		return nil
	})
	return folders, err
}

func (s *EMLSource) Iterate(ctx context.Context, folder string, fn func(raw []byte, flags []string) error) error {
	dir := filepath.Join(s.Root, folder)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".eml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		if err := fn(data, nil); err != nil {
			return err
		}
	}
	return nil
}

// NewSource constructs a Source for the named format. Recognized formats:
// "mbox", "maildir", "eml".
func NewSource(format, path string) (Source, error) {
	switch strings.ToLower(format) {
	case "mbox":
		return &MboxSource{Path: path}, nil
	case "maildir":
		return &MaildirSource{Root: path}, nil
	case "eml":
		return &EMLSource{Root: path}, nil
	default:
		return nil, fmt.Errorf("unsupported source format %q (want mbox, maildir, or eml)", format)
	}
}

func hasDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
