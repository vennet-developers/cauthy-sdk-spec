package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/client"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/routes"
)

// provider picks the provider id the probe puts in {provider}: the first one
// /methods lists (an object with an id, or a plain string), else google.
func provider(c *check.Ctx) string {
	if m, err := c.Methods(); err == nil && m.JSON != nil {
		if list, ok := m.JSON["providers"].([]any); ok {
			for _, p := range list {
				switch v := p.(type) {
				case string:
					if v != "" {
						return v
					}
				case map[string]any:
					if id, _ := v["id"].(string); id != "" {
						return id
					}
				}
			}
		}
	}
	return "google"
}

// probePath fills path parameters with a harmless value and adds the required
// query parameters, so the route is reached even when it then refuses the input.
func probePath(r *routes.Route, prov string) string {
	path := strings.ReplaceAll(r.Path, "{provider}", prov)
	names := make([]string, 0, len(r.Query))
	for name := range r.Query {
		names = append(names, name)
	}
	sort.Strings(names) // a stable URL, run after run
	var q []string
	for _, name := range names {
		if f := r.Query[name]; f.Required {
			v := "x"
			if f.Type == "uuid" {
				v = "00000000-0000-4000-8000-000000000000"
			}
			q = append(q, name+"="+v)
		}
	}
	if len(q) > 0 {
		path += "?" + strings.Join(q, "&")
	}
	return path
}

// served says whether the answer came from the route. 405 never does. A 404
// does only when it carries a JSON error (the route ran and refused a thing, such
// as an unknown id); the plain-text 404 is what a missing route answers.
func served(res *client.Response) bool {
	switch res.Status {
	case 405:
		return false
	case 404:
		_, ok := res.JSON["error"].(map[string]any)
		return ok
	}
	return true
}

func RegisterTable(reg *check.Registry) {
	hdr := map[string]string{"X-Cauthy-Request": "1"}
	probe := func(c *check.Ctx, only func(*routes.Route) bool) check.Result {
		prov := provider(c)
		var missing []string
		for _, r := range c.Table.Routes {
			if !only(r) {
				continue
			}
			var res *client.Response
			var err error
			path := probePath(r, prov)
			switch {
			case r.Method == "GET":
				res, err = c.Client.Fresh().Get(path, nil)
			case r.Needs("json"):
				// An array is not an object: the protocol answers 400 bad_request
				// before any call to Cauthy, so the probe creates nothing.
				res, err = c.Client.Fresh().PostRaw(path, []byte("[]"), hdr)
			default:
				res, err = c.Client.Fresh().PostJSON(path, map[string]any{}, hdr)
			}
			if err != nil {
				return check.Fail(fmt.Sprintf("%s %s: %v", r.Method, r.Path, err))
			}
			if !served(res) {
				missing = append(missing, fmt.Sprintf("%s %s → %d", r.Method, r.Path, res.Status))
			}
		}
		if len(missing) > 0 {
			return check.Fail("not served: " + strings.Join(missing, "; "))
		}
		return check.Pass("every route answers its method")
	}
	reg.Add(check.Check{ID: "table.every_route_answers", Group: "table", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		return probe(c, func(r *routes.Route) bool { return !r.Deprecated })
	}})
	reg.Add(check.Check{ID: "table.deprecated_still_answer", Group: "table", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		return probe(c, func(r *routes.Route) bool { return r.Deprecated })
	}})
	reg.Add(check.Check{ID: "table.methods_fields", Group: "table", Level: check.Basic, Run: func(c *check.Ctx) check.Result {
		res, err := c.Client.Fresh().Get("/methods", nil)
		if err != nil {
			return check.Fail(err.Error())
		}
		if res.Status != 200 || res.JSON == nil {
			return check.Fail(fmt.Sprintf("GET /methods: %d %s", res.Status, res.Body))
		}
		r := c.Table.ByID("other.methods")
		if r == nil {
			return check.Fail("the route table has no other.methods")
		}
		var missing []string
		for name, typ := range r.Success.Fields {
			if strings.HasSuffix(typ, "?") {
				continue
			}
			if _, ok := res.JSON[name]; !ok {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			return check.Fail("/methods lacks " + strings.Join(missing, ", "))
		}
		return check.Pass("/methods carries every required field")
	}})
}
