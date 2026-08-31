package queue

import "testing"

func TestBindRewritesPlaceholdersForPostgres(t *testing.T) {
	repo := &SQLiteRepository{driver: "postgres"}
	got := repo.bind(`SELECT id FROM email_queue WHERE org_id = ? AND status = ? LIMIT ?`)
	want := `SELECT id FROM email_queue WHERE org_id = $1 AND status = $2 LIMIT $3`
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNowExprIsPortable(t *testing.T) {
	repo := &SQLiteRepository{driver: "sqlite"}
	if got := repo.nowExpr(); got != "CURRENT_TIMESTAMP" {
		t.Fatalf("unexpected sqlite now expr %q", got)
	}

	repo.driver = "postgres"
	if got := repo.nowExpr(); got != "CURRENT_TIMESTAMP" {
		t.Fatalf("unexpected postgres now expr %q", got)
	}
}
