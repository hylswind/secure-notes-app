package app

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
)

type userHandler func(w http.ResponseWriter, r *http.Request, u User)

// authed requires a valid session; API requests get 401, pages get a redirect.
func (a *App) authed(page bool, h userHandler) http.HandlerFunc {
	return a.gated(func(w http.ResponseWriter, r *http.Request) {
		u, ok := a.currentUser(r)
		if !ok {
			if page {
				http.Redirect(w, r, "/", http.StatusFound)
			} else {
				httpError(w, 401, "unauthorized")
			}
			return
		}
		h(w, r, u)
	})
}

func (a *App) currentUser(r *http.Request) (User, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return User{}, false
	}
	sub, err := VerifySession(a.sessionKey, c.Value, a.now())
	if err != nil {
		return User{}, false
	}
	u, err := a.store.GetUser(sub)
	if err != nil {
		return User{}, false
	}
	return u, true
}

func (a *App) apiRoutes(mux *http.ServeMux) {
	api := func(pattern string, h userHandler) { mux.HandleFunc(pattern, a.authed(false, h)) }
	api("GET /api/me", a.apiMe)
	api("GET /api/status", a.apiStatus)
	api("GET /api/notes", a.apiListNotes)
	api("POST /api/notes", a.apiCreateNote)
	api("GET /api/notes/{id}", a.apiGetNote)
	api("PUT /api/notes/{id}", a.apiUpdateNote)
	api("DELETE /api/notes/{id}", a.apiDeleteNote)
	api("POST /api/notes/{id}/restore", a.apiRestoreNote)
	api("GET /api/notes/{id}/shares", a.apiListShares)
	api("POST /api/notes/{id}/shares", a.apiAddShare)
	api("DELETE /api/notes/{id}/shares/{email}", a.apiRemoveShare)
	api("GET /api/shared", a.apiShared)
}

func (a *App) apiMe(w http.ResponseWriter, r *http.Request, u User) {
	writeJSON(w, 200, map[string]string{"sub_suffix": suffix(u.Sub), "email": u.Email, "name": u.Name})
}

func (a *App) apiStatus(w http.ResponseWriter, r *http.Request, u User) {
	st, reason := a.volumeState()
	var exp any
	if a.certs != nil {
		if t, ok := a.certs.Expiry(); ok {
			exp = t.UTC().Format(time.RFC3339)
		}
	}
	writeJSON(w, 200, map[string]any{"volume": st, "volume_reason": reason, "certificate_expires_at": exp, "version": Version})
}

type noteReq struct {
	Title     *string   `json:"title"`
	Body      *string   `json:"body"`
	Tags      *[]string `json:"tags"`
	UpdatedAt *string   `json:"updated_at"`
}

type shareReq struct {
	Email *string `json:"email"`
}

func decode(r *http.Request, v any) error {
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 1<<20))
	if err != nil {
		return &ValidationError{"request", "body too large or unreadable"}
	}
	if err := json.Unmarshal(body, v); err != nil {
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) && te.Field != "" {
			return &ValidationError{te.Field, "has the wrong type"}
		}
		return &ValidationError{"request", "invalid JSON"}
	}
	return nil
}

func (a *App) storeError(w http.ResponseWriter, err error) {
	var ve *ValidationError
	switch {
	case errors.As(err, &ve):
		httpError(w, 400, ve.Error())
	case errors.Is(err, ErrNotFound):
		httpError(w, 404, "not found")
	default:
		Event("internal_error", "error", err.Error())
		httpError(w, 500, "internal error")
	}
}

func listQuery(r *http.Request) (ListQuery, error) {
	q := r.URL.Query()
	lq := ListQuery{Q: q.Get("q"), Tag: q.Get("tag"), Trash: q.Get("trash") == "1", Page: 1, PageSize: 50}
	if v := q.Get("page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return lq, &ValidationError{"page", "must be a positive integer"}
		}
		lq.Page = n
	}
	if v := q.Get("page_size"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return lq, &ValidationError{"page_size", "must be a positive integer"}
		}
		if n > 200 {
			n = 200
		}
		lq.PageSize = n
	}
	return lq, nil
}

func (a *App) apiListNotes(w http.ResponseWriter, r *http.Request, u User) {
	lq, err := listQuery(r)
	if err != nil {
		a.storeError(w, err)
		return
	}
	res, err := a.store.ListOwn(u.Sub, lq)
	if err != nil {
		a.storeError(w, err)
		return
	}
	writeJSON(w, 200, res)
}

func (a *App) apiShared(w http.ResponseWriter, r *http.Request, u User) {
	lq, err := listQuery(r)
	if err != nil {
		a.storeError(w, err)
		return
	}
	res, err := a.store.ListShared(u.Sub, lq)
	if err != nil {
		a.storeError(w, err)
		return
	}
	writeJSON(w, 200, res)
}

func (a *App) apiCreateNote(w http.ResponseWriter, r *http.Request, u User) {
	var req noteReq
	if err := decode(r, &req); err != nil {
		a.storeError(w, err)
		return
	}
	n, err := a.store.CreateNote(u.Sub, NoteInput{Title: req.Title, Body: req.Body, Tags: req.Tags}, a.now())
	if err != nil {
		a.storeError(w, err)
		return
	}
	writeJSON(w, 201, n)
}

func (a *App) apiGetNote(w http.ResponseWriter, r *http.Request, u User) {
	n, err := a.store.GetNote(r.PathValue("id"), u.Sub)
	if err != nil {
		a.storeError(w, err)
		return
	}
	writeJSON(w, 200, n)
}

func (a *App) apiUpdateNote(w http.ResponseWriter, r *http.Request, u User) {
	var req noteReq
	if err := decode(r, &req); err != nil {
		a.storeError(w, err)
		return
	}
	id := r.PathValue("id")
	n, err := a.store.UpdateNote(id, u.Sub, NoteInput{Title: req.Title, Body: req.Body, Tags: req.Tags, UpdatedAt: req.UpdatedAt}, a.now())
	if errors.Is(err, ErrConflict) {
		cur, gerr := a.store.GetNote(id, u.Sub)
		if gerr != nil {
			a.storeError(w, gerr)
			return
		}
		writeJSON(w, 409, map[string]any{"error": "conflict", "note": cur})
		return
	}
	if err != nil {
		a.storeError(w, err)
		return
	}
	writeJSON(w, 200, n)
}

func (a *App) apiDeleteNote(w http.ResponseWriter, r *http.Request, u User) {
	err := a.store.Trash(r.PathValue("id"), u.Sub, r.URL.Query().Get("permanent") == "1", a.now())
	if err != nil {
		a.storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) apiRestoreNote(w http.ResponseWriter, r *http.Request, u User) {
	n, err := a.store.Restore(r.PathValue("id"), u.Sub)
	if err != nil {
		a.storeError(w, err)
		return
	}
	writeJSON(w, 200, n)
}

func (a *App) apiListShares(w http.ResponseWriter, r *http.Request, u User) {
	s, err := a.store.ListShares(r.PathValue("id"), u.Sub)
	if err != nil {
		a.storeError(w, err)
		return
	}
	writeJSON(w, 200, s)
}

func (a *App) apiAddShare(w http.ResponseWriter, r *http.Request, u User) {
	var req shareReq
	if err := decode(r, &req); err != nil {
		a.storeError(w, err)
		return
	}
	id := r.PathValue("id")
	if _, err := a.store.ListShares(id, u.Sub); err != nil {
		a.storeError(w, err)
		return
	}
	if req.Email == nil {
		a.storeError(w, &ValidationError{"email", "is required"})
		return
	}
	sh, err := a.store.AddShare(id, u.Sub, u.Email, *req.Email, a.now())
	if err != nil {
		a.storeError(w, err)
		return
	}
	writeJSON(w, 201, sh)
}

func (a *App) apiRemoveShare(w http.ResponseWriter, r *http.Request, u User) {
	if err := a.store.RemoveShare(r.PathValue("id"), u.Sub, r.PathValue("email")); err != nil {
		a.storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- pages ----

func (a *App) servePage(file string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := webFS.ReadFile("web/" + file)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(b)
	}
}

func (a *App) pageRoutes(mux *http.ServeMux) {
	landing := a.servePage("index.html")
	mux.HandleFunc("GET /{$}", a.gated(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := a.currentUser(r); ok {
			http.Redirect(w, r, "/app", http.StatusFound)
			return
		}
		landing(w, r)
	}))
	mux.HandleFunc("GET /app", a.authed(true, func(w http.ResponseWriter, r *http.Request, u User) { a.servePage("app.html")(w, r) }))
	mux.HandleFunc("GET /app/settings", a.authed(true, func(w http.ResponseWriter, r *http.Request, u User) { a.servePage("settings.html")(w, r) }))
	static := http.StripPrefix("/static/", http.FileServerFS(mustSub()))
	mux.HandleFunc("GET /static/{file}", a.gated(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		static.ServeHTTP(w, r)
	}))
}
