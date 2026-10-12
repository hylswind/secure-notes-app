package app

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

func mustNote(t *testing.T, c *client, in map[string]any) map[string]any {
	code, n, raw := c.do("POST", "/api/notes", in)
	if code != 201 {
		t.Fatalf("create: %d %s", code, raw)
	}
	return n
}

func TestNotesCRUD(t *testing.T) {
	e := newTestEnv(t)
	c := e.login("u1", "u1@example.com")
	n := mustNote(t, c, map[string]any{"title": "Hello", "body": "# World", "tags": []string{"a", "b-1"}})
	id := n["id"].(string)
	if n["owned"] != true || n["deleted_at"] != nil || n["body"] != "# World" || len(n["tags"].([]any)) != 2 {
		t.Fatalf("created %v", n)
	}
	if _, err := time.Parse(time.RFC3339, n["created_at"].(string)); err != nil {
		t.Errorf("created_at not RFC3339: %v", err)
	}
	code, got, _ := c.do("GET", "/api/notes/"+id, nil)
	if code != 200 || got["title"] != "Hello" {
		t.Fatalf("get %d %v", code, got)
	}
	// update
	code, up, raw := c.do("PUT", "/api/notes/"+id, map[string]any{"title": "Hello2", "body": "b", "tags": []string{"z"}, "updated_at": n["updated_at"]})
	if code != 200 || up["title"] != "Hello2" || up["updated_at"] == n["updated_at"] {
		t.Fatalf("update %d %s", code, raw)
	}
	// stale update -> 409 with current note
	code, conf, _ := c.do("PUT", "/api/notes/"+id, map[string]any{"title": "stale", "body": "x", "tags": []string{}, "updated_at": n["updated_at"]})
	if code != 409 || conf["error"] != "conflict" || conf["note"].(map[string]any)["title"] != "Hello2" {
		t.Fatalf("conflict %d %v", code, conf)
	}
	// missing updated_at
	if code, b, _ := c.do("PUT", "/api/notes/"+id, map[string]any{"title": "x"}); code != 400 || !strings.HasPrefix(b["error"].(string), "updated_at:") {
		t.Fatalf("missing updated_at %d %v", code, b)
	}
	// trash
	if code, _, _ := c.do("DELETE", "/api/notes/"+id, nil); code != 204 {
		t.Fatalf("trash %d", code)
	}
	_, list, _ := c.do("GET", "/api/notes", nil)
	if list["total"].(float64) != 0 {
		t.Fatalf("trashed note still listed: %v", list)
	}
	_, tl, _ := c.do("GET", "/api/notes?trash=1", nil)
	if tl["total"].(float64) != 1 {
		t.Fatalf("trash list: %v", tl)
	}
	_, tn, _ := c.do("GET", "/api/notes/"+id, nil)
	if tn["deleted_at"] == nil {
		t.Fatal("deleted_at not set")
	}
	if code, _, _ := c.do("PUT", "/api/notes/"+id, map[string]any{"title": "x", "updated_at": tn["updated_at"]}); code != 400 {
		t.Fatalf("update of trashed: %d", code)
	}
	// restore
	if code, r, _ := c.do("POST", "/api/notes/"+id+"/restore", nil); code != 200 || r["deleted_at"] != nil {
		t.Fatalf("restore %d %v", code, r)
	}
	// permanent
	if code, _, _ := c.do("DELETE", "/api/notes/"+id+"?permanent=1", nil); code != 204 {
		t.Fatalf("permanent %d", code)
	}
	if code, _, _ := c.do("GET", "/api/notes/"+id, nil); code != 404 {
		t.Fatalf("after permanent %d", code)
	}
	if code, _, _ := c.do("DELETE", "/api/notes/"+id, nil); code != 404 {
		t.Fatalf("delete missing %d", code)
	}
}

func TestNoteValidation(t *testing.T) {
	e := newTestEnv(t)
	c := e.login("u1", "u1@example.com")
	tags21 := make([]string, 21)
	for i := range tags21 {
		tags21[i] = fmt.Sprintf("t%d", i)
	}
	cases := []struct {
		name  string
		in    map[string]any
		field string
	}{
		{"no title", map[string]any{"body": "x"}, "title"},
		{"empty title", map[string]any{"title": ""}, "title"},
		{"blank title", map[string]any{"title": "   "}, "title"},
		{"long title", map[string]any{"title": strings.Repeat("x", 201)}, "title"},
		{"title type", map[string]any{"title": 5}, "title"},
		{"long body", map[string]any{"title": "t", "body": strings.Repeat("x", 100*1024+1)}, "body"},
		{"too many tags", map[string]any{"title": "t", "tags": tags21}, "tags"},
		{"upper tag", map[string]any{"title": "t", "tags": []string{"Abc"}}, "tags"},
		{"long tag", map[string]any{"title": "t", "tags": []string{strings.Repeat("a", 31)}}, "tags"},
		{"empty tag", map[string]any{"title": "t", "tags": []string{""}}, "tags"},
		{"dup tag", map[string]any{"title": "t", "tags": []string{"a", "a"}}, "tags"},
		{"tags type", map[string]any{"title": "t", "tags": "a"}, "tags"},
	}
	for _, tc := range cases {
		code, b, raw := c.do("POST", "/api/notes", tc.in)
		if code != 400 || !strings.HasPrefix(fmt.Sprint(b["error"]), tc.field+":") {
			t.Errorf("%s: %d %s", tc.name, code, raw)
		}
	}
	// boundaries accepted
	ok := map[string]any{"title": strings.Repeat("é", 200), "body": strings.Repeat("x", 100*1024), "tags": append(tags21[:19:19], strings.Repeat("a", 30))}
	mustNote(t, c, ok)
	if code, _, _ := c.do("POST", "/api/notes", nil); code != 400 {
		t.Errorf("empty body: %d", code)
	}
}

func TestSearchTagsPagination(t *testing.T) {
	e := newTestEnv(t)
	c := e.login("u1", "u1@example.com")
	for i := 0; i < 5; i++ {
		mustNote(t, c, map[string]any{"title": fmt.Sprintf("note %d", i), "body": "common text", "tags": []string{"all"}})
	}
	mustNote(t, c, map[string]any{"title": "Needle", "body": "in a haystack 100%", "tags": []string{"special", "all"}})
	titles := func(path string) []string {
		code, l, raw := c.do("GET", path, nil)
		if code != 200 {
			t.Fatalf("%s: %d %s", path, code, raw)
		}
		var out []string
		for _, n := range l["notes"].([]any) {
			out = append(out, n.(map[string]any)["title"].(string))
		}
		return out
	}
	if got := titles("/api/notes?q=needle"); len(got) != 1 || got[0] != "Needle" {
		t.Errorf("title search %v", got)
	}
	if got := titles("/api/notes?q=HAYSTACK"); len(got) != 1 {
		t.Errorf("body search %v", got)
	}
	if got := titles("/api/notes?q=" + url.QueryEscape("100%")); len(got) != 1 {
		t.Errorf("percent search %v", got)
	}
	if got := titles("/api/notes?q=" + url.QueryEscape("hay needle")); len(got) != 1 {
		t.Errorf("multi-term %v", got)
	}
	if got := titles("/api/notes?tag=special"); len(got) != 1 {
		t.Errorf("tag filter %v", got)
	}
	if got := titles("/api/notes?tag=all"); len(got) != 6 {
		t.Errorf("tag all %v", got)
	}
	if got := titles("/api/notes"); got[0] != "Needle" {
		t.Errorf("sort by updated_at desc: %v", got)
	}
	code, l, _ := c.do("GET", "/api/notes?page_size=4&page=2", nil)
	if code != 200 || len(l["notes"].([]any)) != 2 || l["total"].(float64) != 6 || l["page"].(float64) != 2 {
		t.Errorf("page 2: %v", l)
	}
	_, l, _ = c.do("GET", "/api/notes?page_size=1000", nil)
	if l["page_size"].(float64) != 200 {
		t.Errorf("page_size cap: %v", l["page_size"])
	}
	_, l, _ = c.do("GET", "/api/notes", nil)
	if l["page_size"].(float64) != 50 {
		t.Errorf("default page size")
	}
	for _, p := range []string{"page=0", "page=x", "page_size=0", "page_size=-1"} {
		if code, _, _ := c.do("GET", "/api/notes?"+p, nil); code != 400 {
			t.Errorf("%s: %d", p, code)
		}
	}
}

func TestSharing(t *testing.T) {
	e := newTestEnv(t)
	alice := e.login("alice-sub", "alice@example.com")
	bob := e.login("bob-sub", "bob@example.com")
	n := mustNote(t, alice, map[string]any{"title": "Secret", "body": "s", "tags": []string{"t"}})
	id := n["id"].(string)

	if code, _, _ := bob.do("GET", "/api/notes/"+id, nil); code != 404 {
		t.Fatalf("non-owner read: %d", code)
	}
	for _, req := range []struct{ m, p string }{
		{"PUT", "/api/notes/" + id}, {"DELETE", "/api/notes/" + id}, {"POST", "/api/notes/" + id + "/restore"},
		{"GET", "/api/notes/" + id + "/shares"}, {"POST", "/api/notes/" + id + "/shares"}, {"DELETE", "/api/notes/" + id + "/shares/x@y.zz"},
	} {
		var body any
		if req.m == "PUT" {
			body = map[string]any{"title": "hack", "updated_at": n["updated_at"]}
		} else if req.m == "POST" && strings.HasSuffix(req.p, "shares") {
			body = map[string]any{"email": "eve@example.com"}
		}
		if code, _, _ := bob.do(req.m, req.p, body); code != 404 {
			t.Errorf("non-owner %s %s: %d", req.m, req.p, code)
		}
	}
	// validation
	if code, b, _ := alice.do("POST", "/api/notes/"+id+"/shares", map[string]any{"email": "ALICE@example.com"}); code != 400 {
		t.Errorf("self share: %d %v", code, b)
	}
	if code, _, _ := alice.do("POST", "/api/notes/"+id+"/shares", map[string]any{"email": "nope"}); code != 400 {
		t.Errorf("bad email: %d", code)
	}
	if code, _, _ := alice.do("POST", "/api/notes/"+id+"/shares", map[string]any{}); code != 400 {
		t.Errorf("missing email: %d", code)
	}
	// share (case-insensitive match)
	if code, sh, raw := alice.do("POST", "/api/notes/"+id+"/shares", map[string]any{"email": " Bob@Example.com "}); code != 201 || sh["email"] != "bob@example.com" {
		t.Fatalf("share: %d %s", code, raw)
	}
	_, sl, _ := alice.do("GET", "/api/notes/"+id+"/shares", nil)
	_ = sl
	code, shares, raw := alice.do("GET", "/api/notes/"+id+"/shares", nil)
	_ = shares
	if code != 200 || !strings.Contains(raw, "bob@example.com") || !strings.Contains(raw, "created_at") {
		t.Fatalf("list shares %d %s", code, raw)
	}
	// bob sees it, read-only
	code, got, _ := bob.do("GET", "/api/notes/"+id, nil)
	if code != 200 || got["owned"] != false || got["owner_email"] != "alice@example.com" {
		t.Fatalf("shared read: %d %v", code, got)
	}
	if code, _, _ := bob.do("PUT", "/api/notes/"+id, map[string]any{"title": "x", "updated_at": got["updated_at"]}); code != 404 {
		t.Errorf("sharee write: %d", code)
	}
	_, sharedList, _ := bob.do("GET", "/api/shared", nil)
	if sharedList["total"].(float64) != 1 {
		t.Fatalf("shared list %v", sharedList)
	}
	if _, l, _ := bob.do("GET", "/api/shared?q=secret&tag=t", nil); l["total"].(float64) != 1 {
		t.Errorf("shared filters %v", l)
	}
	if _, l, _ := bob.do("GET", "/api/shared?q=zzz", nil); l["total"].(float64) != 0 {
		t.Errorf("shared filter miss %v", l)
	}
	if _, l, _ := bob.do("GET", "/api/notes", nil); l["total"].(float64) != 0 {
		t.Errorf("shared note in own list")
	}
	// trash hides from sharee
	alice.do("DELETE", "/api/notes/"+id, nil)
	if code, _, _ := bob.do("GET", "/api/notes/"+id, nil); code != 404 {
		t.Errorf("trashed shared visible: %d", code)
	}
	alice.do("POST", "/api/notes/"+id+"/restore", nil)
	// revoke
	if code, _, _ := alice.do("DELETE", "/api/notes/"+id+"/shares/"+url.PathEscape("bob@example.com"), nil); code != 204 {
		t.Fatalf("revoke %d", code)
	}
	if code, _, _ := alice.do("DELETE", "/api/notes/"+id+"/shares/bob@example.com", nil); code != 404 {
		t.Errorf("revoke twice %d", code)
	}
	if code, _, _ := bob.do("GET", "/api/notes/"+id, nil); code != 404 {
		t.Errorf("after revoke %d", code)
	}
	// a share made before the sharee ever logged in works once they do
	n2 := mustNote(t, alice, map[string]any{"title": "Later"})
	alice.do("POST", "/api/notes/"+n2["id"].(string)+"/shares", map[string]any{"email": "carol@example.com"})
	carol := e.login("carol-sub", "carol@example.com")
	if _, l, _ := carol.do("GET", "/api/shared", nil); l["total"].(float64) != 1 {
		t.Errorf("late sharee %v", l)
	}
}

func TestPurgeTrash(t *testing.T) {
	e := newTestEnv(t)
	c := e.login("u1", "u1@example.com")
	a := mustNote(t, c, map[string]any{"title": "old"})["id"].(string)
	b := mustNote(t, c, map[string]any{"title": "recent"})["id"].(string)
	keep := mustNote(t, c, map[string]any{"title": "kept"})["id"].(string)
	now := time.Now()
	s := e.app.store
	if err := s.Trash(a, "u1", false, now.Add(-31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Trash(b, "u1", false, now.Add(-29*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	e.app.now = func() time.Time { return now }
	e.app.Purge()
	if code, _, _ := c.do("GET", "/api/notes/"+a, nil); code != 404 {
		t.Error("old trashed note not purged")
	}
	if code, _, _ := c.do("GET", "/api/notes/"+b, nil); code != 200 {
		t.Error("recent trashed note purged")
	}
	if code, _, _ := c.do("GET", "/api/notes/"+keep, nil); code != 200 {
		t.Error("live note purged")
	}
	// clock injection: 31 days later the recent one goes too
	n, err := s.PurgeTrash(now.Add(2 * 24 * time.Hour))
	if err != nil || n != 1 {
		t.Errorf("purge later: %d %v", n, err)
	}
}

func TestUpdatedAtMonotonic(t *testing.T) {
	e := newTestEnv(t)
	c := e.login("u1", "u1@example.com")
	n := mustNote(t, c, map[string]any{"title": "x"})
	cur := n["updated_at"].(string)
	for i := 0; i < 5; i++ {
		_, up, _ := c.do("PUT", "/api/notes/"+n["id"].(string), map[string]any{"title": "x", "updated_at": cur})
		next := up["updated_at"].(string)
		if next <= cur {
			t.Fatalf("updated_at not increasing: %s -> %s", cur, next)
		}
		cur = next
	}
}

func TestCrossOriginRefused(t *testing.T) {
	e := newTestEnv(t)
	c := e.login("u1", "u1@example.com")
	req, _ := newReq("POST", c.base+"/api/notes", `{"title":"x"}`)
	req.Header.Set("Origin", "https://evil.example")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("cross-origin POST: %d", resp.StatusCode)
	}
}
