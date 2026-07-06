package collectors

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTempPSIFile writes content to a temp file and returns its path.
func writeTempPSIFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pressure")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp psi file: %v", err)
	}
	return path
}

func TestParsePSI_WellFormed(t *testing.T) {
	content := `some avg10=0.00 avg60=12.34 avg300=8.50 total=12345678
full avg10=1.11 avg60=5.10 avg300=3.20 total=456789
`
	path := writeTempPSIFile(t, content)

	stats, available, err := ParsePSI(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available {
		t.Fatal("expected available=true")
	}

	if stats.Some.Avg60 != 12.34 {
		t.Errorf("some.avg60: got %v, want 12.34", stats.Some.Avg60)
	}
	if stats.Some.Avg300 != 8.50 {
		t.Errorf("some.avg300: got %v, want 8.50", stats.Some.Avg300)
	}
	if stats.Some.TotalSeconds != 12.345678 {
		t.Errorf("some.total: got %v s, want 12.345678 s", stats.Some.TotalSeconds)
	}
	if stats.Full.Avg10 != 1.11 {
		t.Errorf("full.avg10: got %v, want 1.11", stats.Full.Avg10)
	}
	if stats.Full.TotalSeconds != 0.456789 {
		t.Errorf("full.total: got %v s, want 0.456789 s", stats.Full.TotalSeconds)
	}
}

func TestParsePSI_MissingFileIsUnavailableNotError(t *testing.T) {
	stats, available, err := ParsePSI(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("missing file should not error, got: %v", err)
	}
	if available {
		t.Error("expected available=false for missing file")
	}
	if stats != nil {
		t.Error("expected nil stats for missing file")
	}
}

func TestParsePSI_MalformedValueErrors(t *testing.T) {
	path := writeTempPSIFile(t, "some avg10=not-a-number avg60=0.00 avg300=0.00 total=0\n")
	_, available, err := ParsePSI(path)
	if err == nil {
		t.Fatal("expected error for malformed value")
	}
	if !available {
		t.Error("a present-but-malformed file is still 'available'")
	}
}

func TestParsePSI_IgnoresUnknownLines(t *testing.T) {
	content := `some avg10=0.50 avg60=0.00 avg300=0.00 total=100 future_key=9.9
weird ignored=1
full avg10=0.00 avg60=0.00 avg300=0.00 total=0
`
	path := writeTempPSIFile(t, content)
	stats, available, err := ParsePSI(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available || stats.Some.Avg10 != 0.50 {
		t.Errorf("expected some.avg10=0.50 available, got %v avail=%v", stats.Some.Avg10, available)
	}
}
