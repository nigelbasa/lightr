package imap

import "testing"

func TestValidateMailboxName(t *testing.T) {
	rejects := []string{
		"",
		"../escape",
		"foo/bar",
		"foo\\bar",
		"foo\x00bar",
		"..",
		".",
		" leading",
		"trailing ",
	}
	for _, name := range rejects {
		if err := validateMailboxName(name); err == nil {
			t.Errorf("validateMailboxName(%q) accepted, want rejection", name)
		}
	}

	accepts := []string{
		"INBOX",
		"Sent",
		"Drafts",
		"Trash",
		"Junk",
		"Quarantine",
		"Custom Folder",
		"Archive 2024",
		"Project-X",
	}
	for _, name := range accepts {
		if err := validateMailboxName(name); err != nil {
			t.Errorf("validateMailboxName(%q) rejected: %v", name, err)
		}
	}
}
