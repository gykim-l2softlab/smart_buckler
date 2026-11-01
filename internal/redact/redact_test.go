package redact

import "testing"

func TestString(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"resident number", "/users/900101-1234567", "/users/" + Mask},
		{"resident number no hyphen", "/u/9001011234567/x", "/u/" + Mask + "/x"},
		{"card with hyphens", "/pay/1234-5678-9012-3456", "/pay/" + Mask},
		{"card with spaces", "card 1234 5678 9012 3456", "card " + Mask},
		{"mobile phone", "/call/010-1234-5678", "/call/" + Mask},
		{"seoul phone", "/call/02-123-4567", "/call/" + Mask},
		{"bank account", "/acct/110-123-456789", "/acct/" + Mask},
		{"short numbers kept", "/posts/12345678/comments/42", "/posts/12345678/comments/42"},
		{"date kept", "/archive/2026-11-01", "/archive/2026-11-01"},
		{"no digits", "/index.html", "/index.html"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := String(tt.in); got != tt.want {
				t.Errorf("String(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
