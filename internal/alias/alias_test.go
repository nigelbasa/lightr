package alias

import "testing"

func TestBindPostgresPlaceholders(t *testing.T) {
	repo := &SQLiteRepository{driver: "postgres"}

	got := repo.bind("SELECT * FROM aliases WHERE domain_id = ? AND source = ?")
	want := "SELECT * FROM aliases WHERE domain_id = $1 AND source = $2"
	if got != want {
		t.Fatalf("bind() = %q, want %q", got, want)
	}
}
