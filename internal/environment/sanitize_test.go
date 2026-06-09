package environment

import "testing"

func TestSanitizeValue(t *testing.T) {
	got := SanitizeValue("line1\\nline2\\tTabbed\\rReturn")
	want := "line1\nline2\tTabbed\rReturn"

	if got != want {
		t.Fatalf("SanitizeValue() = %q, want %q", got, want)
	}
}
