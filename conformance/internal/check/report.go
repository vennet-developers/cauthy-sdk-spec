package check

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Text renders one line per check: the status padded to 8 columns, the id,
// then the detail.
func (rep *Report) Text() string {
	var b strings.Builder
	counts := map[string]int{}
	for _, g := range rep.Results {
		counts[g.Status]++
		fmt.Fprintf(&b, "%-8s %s  %s\n", strings.ToUpper(g.Status), g.ID, g.Detail)
	}
	fmt.Fprintf(&b, "\n%d passed, %d failed, %d skipped, %d advisory — protocol %d, level %s\n",
		counts[StatusPass], counts[StatusFail], counts[StatusSkip], counts[StatusAdvisory], rep.Protocol, rep.Level)
	if n := rep.skipped(); n > 0 {
		noun := "checks"
		if n == 1 {
			noun = "check"
		}
		fmt.Fprintf(&b, "INCOMPLETE: %d %s skipped\n", n, noun)
	}
	return b.String()
}

// JSON renders the report with its verdict (passed, complete) and counts.
func (rep *Report) JSON() []byte {
	counts := map[string]int{StatusPass: 0, StatusFail: 0, StatusSkip: 0, StatusAdvisory: 0}
	for _, g := range rep.Results {
		counts[g.Status]++
	}
	raw, _ := json.MarshalIndent(struct {
		*Report
		Passed   bool           `json:"passed"`
		Complete bool           `json:"complete"`
		Counts   map[string]int `json:"counts"`
	}{rep, rep.Passed(), rep.Complete(), counts}, "", "  ")
	return raw
}
