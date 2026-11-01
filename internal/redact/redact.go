// Package redact masks personal data before it is written to logs or the event store.
package redact

import "regexp"

// Mask is the replacement for redacted values.
const Mask = "[REDACTED]"

// longDigits matches 9 or more digits, optionally separated by single '-' or ' '.
// This covers Korean resident registration numbers (13), card numbers (15 to 16),
// bank account numbers (10 to 14) and phone numbers (10 to 11) without
// maintaining per-format patterns. Over-masking other long numbers is acceptable.
var longDigits = regexp.MustCompile(`\d(?:[- ]?\d){8,}`)

// String returns s with personal number patterns masked.
func String(s string) string {
	return longDigits.ReplaceAllString(s, Mask)
}
