package security

import "testing"

func TestBindPostgresPlaceholders(t *testing.T) {
	repo := &SQLiteOrgRepository{driver: "postgres"}

	got := repo.bind("SELECT * FROM known_organizations WHERE id = ? AND name = ?")
	want := "SELECT * FROM known_organizations WHERE id = $1 AND name = $2"
	if got != want {
		t.Fatalf("bind() = %q, want %q", got, want)
	}
}
