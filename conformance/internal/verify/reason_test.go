package verify

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestRulesListEveryReason keeps the closed list in rules.md and the
// verifier's Reasons the same, in the same order.
func TestRulesListEveryReason(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "verification", "rules.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(raw), "\n## Reason codes\n")
	if !ok {
		t.Fatal(`rules.md has no "## Reason codes" section`)
	}
	section, _, _ = strings.Cut(section, "\n## ")
	var listed []Reason
	for _, line := range strings.Split(section, "\n") {
		if code, ok := strings.CutPrefix(line, "| `"); ok {
			code, _, _ = strings.Cut(code, "`")
			listed = append(listed, Reason(code))
		}
	}
	if !slices.Equal(listed, Reasons) {
		t.Fatalf("rules.md lists %v\nthe verifier has %v", listed, Reasons)
	}
}

func TestErrorNamesTheReason(t *testing.T) {
	err := refuse(Expired, "exp %d is past", 5)
	if err.Error() != "token refused: expired: exp 5 is past" {
		t.Fatalf("got %q", err.Error())
	}
}
