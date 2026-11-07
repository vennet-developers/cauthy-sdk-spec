package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/check"
	"github.com/vennet-developers/cauthy-sdk-spec/conformance/internal/routes"
)

// probePath fills path parameters with a harmless value and adds the required
// query parameters, so the route is reached even when it then refuses the input.
func probePath(r *routes.Route) string {
	path := strings.ReplaceAll(r.Path, "{provider}", "google")
	names := make([]string, 0, len(r.Query))
	for name := range r.Query {
		names = append(names, name)
	}
	sort.Strings(names) // a stable URL, run after run
	var q []string
	for _, name := range names {
		f := r.Query[name]
		if f.Required {
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

func RegisterTable(reg *check.Registry) {
	hdr := map[string]string{"X-Cauthy-Request": "1"}
	probe := func(c *check.Ctx, only func(*routes.Route) bool) check.Result {
		var missing []string
		for _, r := range c.Table.Routes {
			if !only(r) {
				continue
			}
			var status int
			var err error
			if r.Method == "GET" {
				res, e := c.Client.Fresh().Get(probePath(r), nil)
				err = e
				if res != nil {
					status = res.Status
				}
			} else {
				res, e := c.Client.Fresh().PostJSON(probePath(r), map[string]any{}, hdr)
				err = e
				if res != nil {
					status = res.Status
				}
			}
			if err != nil {
				return check.Fail(fmt.Sprintf("%s %s: %v", r.Method, r.Path, err))
			}
			if status == 404 || status == 405 {
				missing = append(missing, fmt.Sprintf("%s %s → %d", r.Method, r.Path, status))
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
