package apicheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/oas"
)

// Options says where to send the probes and with what.
type Options struct {
	Base   string // Cauthy's address, e.g. http://localhost:8080
	Tenant string // the workspace's slug, sent as X-Tenant-Key
	Doc    *oas.Doc
	File   *File
	// Vars are the run's inputs. Values are never printed.
	Vars map[string]string
	// HTTP sends the requests; nil is a client that never follows a
	// redirect and gives each request 20 seconds.
	HTTP *http.Client
}

// Result is one probe's verdict.
type Result struct {
	ID       string   `json:"id"`
	Op       string   `json:"op"`
	Status   int      `json:"status"` // 0 when nothing was answered
	Passed   bool     `json:"passed"`
	Problems []string `json:"problems"`
}

// Report is a finished run.
type Report struct {
	Results []Result `json:"results"`
	Passed  bool     `json:"passed"`
}

const maxBody = 4 << 20

// Run sends the probes in order. Each sees the variables the ones before it
// captured, plus {run} and {tenant}. Once ctx is done no probe is sent; the
// ones left fail.
func Run(ctx context.Context, o Options) *Report {
	hc := o.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	vars := map[string]string{}
	for k, v := range o.Vars {
		vars[k] = v
	}
	vars["run"] = suffix()
	vars["tenant"] = o.Tenant
	rep := &Report{Passed: true, Results: []Result{}}
	for _, p := range o.File.Probes {
		r := Result{ID: p.ID, Op: p.Op, Problems: []string{}}
		if ctx.Err() != nil {
			r.Problems = append(r.Problems, "not sent: the run stopped")
		} else {
			r.Status, r.Problems = send(ctx, hc, o, p, vars)
		}
		r.Passed = len(r.Problems) == 0
		rep.Passed = rep.Passed && r.Passed
		rep.Results = append(rep.Results, r)
	}
	return rep
}

func send(ctx context.Context, hc *http.Client, o Options, p Probe, vars map[string]string) (int, []string) {
	problems := []string{}
	op := o.Doc.Ops[p.Op]
	if op == nil {
		return 0, append(problems, p.Op+" is not in the document")
	}
	req, err := build(ctx, o, p, vars)
	if err != nil {
		return 0, append(problems, err.Error())
	}
	res, err := hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // without the URL, which may carry a variable
		}
		return 0, append(problems, "the request failed: "+err.Error())
	}
	defer res.Body.Close()
	ct, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	var body []byte
	if ct != "text/event-stream" {
		if body, err = io.ReadAll(io.LimitReader(res.Body, maxBody)); err != nil {
			return res.StatusCode, append(problems, "reading the answer: "+err.Error())
		}
	}
	status := res.StatusCode
	expected := slices.Contains(p.Expect, status)
	if !expected {
		problems = append(problems, fmt.Sprintf("answered %d; the probe expects %s", status, p.Expect))
	}
	doc := documented(op, status)
	if doc == nil {
		return status, append(problems, fmt.Sprintf("answered %d, which the document does not list for %s", status, p.Op))
	}
	var parsed any
	isJSON := false
	if len(doc.Content) == 0 {
		if len(body) > 0 && (status < 300 || status >= 400) {
			problems = append(problems, fmt.Sprintf("answered %d with a body (%s), which the document says has none", status, orNone(ct)))
		}
	} else if media, listed := doc.Content[ct]; !listed {
		problems = append(problems, fmt.Sprintf("answered %d as %s; the document lists %s", status, orNone(ct), strings.Join(keys(doc.Content), ", ")))
	} else if ct == "application/json" || strings.HasSuffix(ct, "+json") {
		if err := json.Unmarshal(body, &parsed); err != nil {
			problems = append(problems, "the body is not JSON")
		} else {
			isJSON = true
			if media.Schema != nil {
				for _, pr := range o.Doc.Validate(parsed, media.Schema) {
					problems = append(problems, "body "+pr)
				}
			}
		}
	}
	if expected {
		for _, name := range keys(p.Capture) {
			path := p.Capture[name]
			if !isJSON {
				problems = append(problems, fmt.Sprintf("capture %s: the answer is not JSON", name))
				continue
			}
			v, ok := lookup(parsed, path)
			if !ok {
				problems = append(problems, fmt.Sprintf("capture %s: %s is not in the answer", name, path))
				continue
			}
			vars[name] = v
		}
	}
	return status, problems
}

func build(ctx context.Context, o Options, p Probe, vars map[string]string) (*http.Request, error) {
	method, path, _ := strings.Cut(p.Op, " ")
	var perr error
	path = pathParamRE.ReplaceAllStringFunc(path, func(m string) string {
		v, err := expand(p.Params[m[1:len(m)-1]], vars)
		if err != nil && perr == nil {
			perr = fmt.Errorf("params %s: %w", m[1:len(m)-1], err)
		}
		return url.PathEscape(v)
	})
	if perr != nil {
		return nil, perr
	}
	target := strings.TrimSuffix(o.Base, "/") + path
	if len(p.Query) > 0 {
		q := url.Values{}
		for _, k := range keys(p.Query) {
			v, err := expand(p.Query[k], vars)
			if err != nil {
				return nil, fmt.Errorf("query %s: %w", k, err)
			}
			q.Set(k, v)
		}
		target += "?" + q.Encode()
	}
	var body io.Reader
	contentType := ""
	switch {
	case p.Body != nil:
		v, err := expandAny(p.Body, vars)
		if err != nil {
			return nil, fmt.Errorf("body: %w", err)
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("body: %w", err)
		}
		body, contentType = bytes.NewReader(raw), "application/json"
	case p.Form != nil:
		f := url.Values{}
		for _, k := range keys(p.Form) {
			v, err := expand(p.Form[k], vars)
			if err != nil {
				return nil, fmt.Errorf("form %s: %w", k, err)
			}
			f.Set(k, v)
		}
		body, contentType = strings.NewReader(f.Encode()), "application/x-www-form-urlencoded"
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, errors.New("the request cannot be built")
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if p.Tenant == nil || *p.Tenant {
		req.Header.Set("X-Tenant-Key", o.Tenant)
	}
	if p.Auth != "" {
		token := vars[p.Auth]
		if token == "" {
			return nil, fmt.Errorf("auth: {%s} is not set", p.Auth)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, k := range keys(p.Headers) {
		v, err := expand(p.Headers[k], vars)
		if err != nil {
			return nil, fmt.Errorf("header %s: %w", k, err)
		}
		req.Header.Set(k, v)
	}
	return req, nil
}

// documented is the response the document lists for status: exact, then
// its class (2XX), then default.
func documented(op *oas.Operation, status int) *oas.Response {
	for _, key := range []string{strconv.Itoa(status), strconv.Itoa(status/100) + "XX", "default"} {
		if r := op.Responses[key]; r != nil {
			return r
		}
	}
	return nil
}

// lookup reads a dotted path (data.id, data.0.id) as text.
func lookup(v any, path string) (string, bool) {
	for _, part := range strings.Split(path, ".") {
		switch t := v.(type) {
		case map[string]any:
			next, ok := t[part]
			if !ok {
				return "", false
			}
			v = next
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(t) {
				return "", false
			}
			v = t[i]
		default:
			return "", false
		}
	}
	switch t := v.(type) {
	case string:
		return t, true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(t), true
	}
	return "", false
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func orNone(ct string) string {
	if ct == "" {
		return "no content type"
	}
	return ct
}

func suffix() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Text is one line per probe, its problems under it, then the counts.
func (r *Report) Text() string {
	var b strings.Builder
	passed := 0
	for _, res := range r.Results {
		mark := "FAIL"
		if res.Passed {
			mark = "PASS"
			passed++
		}
		status := "-"
		if res.Status != 0 {
			status = strconv.Itoa(res.Status)
		}
		fmt.Fprintf(&b, "%-4s %-3s %s  %s\n", mark, status, res.ID, res.Op)
		for _, p := range res.Problems {
			fmt.Fprintf(&b, "         %s\n", p)
		}
	}
	fmt.Fprintf(&b, "\n%d passed, %d failed\n", passed, len(r.Results)-passed)
	return b.String()
}

// JSON is the report as a JSON object.
func (r *Report) JSON() []byte {
	raw, _ := json.MarshalIndent(r, "", "  ")
	return raw
}
