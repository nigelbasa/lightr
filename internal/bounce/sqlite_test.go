package bounce

import "testing"

func TestBindPostgresPlaceholders(t *testing.T) {
	repo := &SQLiteRepository{driver: "postgres"}

	got := repo.bind("SELECT COUNT(*) FROM bounces WHERE recipient_email = ? AND bounce_type = ?")
	want := "SELECT COUNT(*) FROM bounces WHERE recipient_email = $1 AND bounce_type = $2"
	if got != want {
		t.Fatalf("bind() = %q, want %q", got, want)
	}
}
