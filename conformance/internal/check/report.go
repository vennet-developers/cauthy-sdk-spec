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
		counts["pass"], counts["fail"], counts["skip"], counts["advisory"], rep.Protocol, rep.Level)
	return b.String()
}

func (rep *Report) JSON() []byte {
	raw, _ := json.MarshalIndent(rep, "", "  ")
	return raw
}
