package app

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

const (
	tsFormat      = "2006-01-02T15:04:05.000000Z"
	maxBodyBytes  = 100 * 1024
	trashRetainer = 30 * 24 * time.Hour
)

var tagRe = regexp.MustCompile(`^[a-z0-9-]{1,30}$`)

type Note struct {
	ID         string   `json:"id"`
	Owner      string   `json:"owner"`
	OwnerEmail string   `json:"owner_email,omitempty"`
	Owned      bool     `json:"owned"`
	Title      string   `json:"title"`
	Body       string   `json:"body,omitempty"`
	Snippet    string   `json:"snippet,omitempty"`
	Tags       []string `json:"tags"`
	CreatedAt  string   `json:"created_at"`
	UpdatedAt  string   `json:"updated_at"`
	DeletedAt  *string  `json:"deleted_at"`
}

type User struct {
	Sub, Email, Name string
}

type Share struct {
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
}

type ValidationError struct{ Field, Msg string }

func (e *ValidationError) Error() string { return e.Field + ": " + e.Msg }

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type Store struct{ db *sql.DB }

func OpenStore(dir string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "notes.db")+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS users (
  sub TEXT PRIMARY KEY, email TEXT NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS users_email ON users(email);
CREATE TABLE IF NOT EXISTS notes (
  id TEXT PRIMARY KEY, owner TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, deleted_at TEXT);
CREATE INDEX IF NOT EXISTS notes_owner ON notes(owner, updated_at);
CREATE TABLE IF NOT EXISTS note_tags (
  note_id TEXT NOT NULL REFERENCES notes(id) ON DELETE CASCADE, tag TEXT NOT NULL,
  PRIMARY KEY (note_id, tag));
CREATE INDEX IF NOT EXISTS note_tags_tag ON note_tags(tag);
CREATE TABLE IF NOT EXISTS shares (
  note_id TEXT NOT NULL REFERENCES notes(id) ON DELETE CASCADE, email TEXT NOT NULL,
  created_at TEXT NOT NULL, PRIMARY KEY (note_id, email));
CREATE INDEX IF NOT EXISTS shares_email ON shares(email);`)
	return err
}

func ts(t time.Time) string { return t.UTC().Format(tsFormat) }

func normEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

func (s *Store) UpsertUser(u User, now time.Time) error {
	_, err := s.db.Exec(`INSERT INTO users(sub,email,name,created_at) VALUES(?,?,?,?)
ON CONFLICT(sub) DO UPDATE SET email=excluded.email, name=excluded.name`, u.Sub, normEmail(u.Email), u.Name, ts(now))
	return err
}

func (s *Store) GetUser(sub string) (User, error) {
	var u User
	err := s.db.QueryRow(`SELECT sub,email,name FROM users WHERE sub=?`, sub).Scan(&u.Sub, &u.Email, &u.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

// NoteInput is the client-supplied part of a note.
type NoteInput struct {
	Title     *string
	Body      *string
	Tags      *[]string
	UpdatedAt *string
}

func validateTitle(t string) error {
	n := utf8.RuneCountInString(t)
	if strings.TrimSpace(t) == "" {
		return &ValidationError{"title", "is required"}
	}
	if n > 200 {
		return &ValidationError{"title", "must be at most 200 characters"}
	}
	return nil
}

func validateBody(b string) error {
	if len(b) > maxBodyBytes {
		return &ValidationError{"body", "must be at most 100 KB"}
	}
	if !utf8.ValidString(b) {
		return &ValidationError{"body", "must be valid UTF-8"}
	}
	return nil
}

func validateTags(tags []string) error {
	if len(tags) > 20 {
		return &ValidationError{"tags", "at most 20 tags are allowed"}
	}
	seen := map[string]bool{}
	for _, t := range tags {
		if !tagRe.MatchString(t) {
			return &ValidationError{"tags", fmt.Sprintf("invalid tag %q: use 1-30 characters of a-z, 0-9 and -", t)}
		}
		if seen[t] {
			return &ValidationError{"tags", fmt.Sprintf("duplicate tag %q", t)}
		}
		seen[t] = true
	}
	return nil
}

func newID() string { return randomString(16) }

func (s *Store) CreateNote(owner string, in NoteInput, now time.Time) (*Note, error) {
	if in.Title == nil {
		return nil, &ValidationError{"title", "is required"}
	}
	if err := validateTitle(*in.Title); err != nil {
		return nil, err
	}
	body := ""
	if in.Body != nil {
		body = *in.Body
	}
	if err := validateBody(body); err != nil {
		return nil, err
	}
	tags := []string{}
	if in.Tags != nil {
		tags = *in.Tags
	}
	if err := validateTags(tags); err != nil {
		return nil, err
	}
	id := newID()
	t := ts(now)
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO notes(id,owner,title,body,created_at,updated_at) VALUES(?,?,?,?,?,?)`,
		id, owner, *in.Title, body, t, t); err != nil {
		return nil, err
	}
	if err := setTags(tx, id, tags); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.loadNote(id, owner)
}

type execer interface {
	Exec(string, ...any) (sql.Result, error)
}

func setTags(tx execer, id string, tags []string) error {
	if _, err := tx.Exec(`DELETE FROM note_tags WHERE note_id=?`, id); err != nil {
		return err
	}
	for _, t := range tags {
		if _, err := tx.Exec(`INSERT INTO note_tags(note_id,tag) VALUES(?,?)`, id, t); err != nil {
			return err
		}
	}
	return nil
}

const noteCols = `n.id,n.owner,n.title,n.body,n.created_at,n.updated_at,n.deleted_at,COALESCE(u.email,'')`

type scanner interface{ Scan(...any) error }

func scanNote(r scanner, viewer string, withBody bool) (*Note, error) {
	var n Note
	var del sql.NullString
	var body string
	if err := r.Scan(&n.ID, &n.Owner, &n.Title, &body, &n.CreatedAt, &n.UpdatedAt, &del, &n.OwnerEmail); err != nil {
		return nil, err
	}
	if del.Valid {
		n.DeletedAt = &del.String
	}
	n.Owned = n.Owner == viewer
	if n.Owned {
		n.OwnerEmail = ""
	}
	n.Owner = suffix(n.Owner)
	if withBody {
		n.Body = body
	} else {
		n.Snippet = snippet(body)
	}
	return &n, nil
}

func snippet(b string) string {
	r := []rune(strings.Join(strings.Fields(b), " "))
	if len(r) > 160 {
		r = r[:160]
	}
	return string(r)
}

func suffix(sub string) string {
	if len(sub) > 6 {
		return sub[len(sub)-6:]
	}
	return sub
}

func (s *Store) tagsFor(id string) ([]string, error) {
	rows, err := s.db.Query(`SELECT tag FROM note_tags WHERE note_id=? ORDER BY tag`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tags := []string{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		tags = append(tags, t)
	}
	return tags, rows.Err()
}

// loadNote loads a note visible to the viewer (owner, or shared with them and not trashed).
func (s *Store) loadNote(id, viewer string) (*Note, error) {
	n, err := s.loadAny(id, viewer)
	if err != nil {
		return nil, err
	}
	return n, nil
}

func (s *Store) loadAny(id, viewer string) (*Note, error) {
	row := s.db.QueryRow(`SELECT `+noteCols+` FROM notes n LEFT JOIN users u ON u.sub=n.owner WHERE n.id=?
AND (n.owner=? OR (n.deleted_at IS NULL AND EXISTS (SELECT 1 FROM shares sh JOIN users me ON me.email=sh.email WHERE sh.note_id=n.id AND me.sub=?)))`, id, viewer, viewer)
	n, err := scanNote(row, viewer, true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	n.Tags, err = s.tagsFor(id)
	return n, err
}

func (s *Store) GetNote(id, viewer string) (*Note, error) { return s.loadNote(id, viewer) }

func (s *Store) ownerOf(id string) (string, *string, string, error) {
	var owner, upd string
	var del sql.NullString
	err := s.db.QueryRow(`SELECT owner,deleted_at,updated_at FROM notes WHERE id=?`, id).Scan(&owner, &del, &upd)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, "", ErrNotFound
	}
	var d *string
	if del.Valid {
		d = &del.String
	}
	return owner, d, upd, err
}

// UpdateNote replaces title/body/tags when the client's updated_at is current.
// On conflict it returns ErrConflict together with the current note.
func (s *Store) UpdateNote(id, owner string, in NoteInput, now time.Time) (*Note, error) {
	o, del, cur, err := s.ownerOf(id)
	if err != nil || o != owner {
		return nil, ErrNotFound
	}
	if in.Title == nil {
		return nil, &ValidationError{"title", "is required"}
	}
	if err := validateTitle(*in.Title); err != nil {
		return nil, err
	}
	body := ""
	if in.Body != nil {
		body = *in.Body
	}
	if err := validateBody(body); err != nil {
		return nil, err
	}
	tags := []string{}
	if in.Tags != nil {
		tags = *in.Tags
	}
	if err := validateTags(tags); err != nil {
		return nil, err
	}
	if in.UpdatedAt == nil || *in.UpdatedAt == "" {
		return nil, &ValidationError{"updated_at", "is required"}
	}
	if del != nil {
		return nil, &ValidationError{"note", "is in the trash; restore it first"}
	}
	newTS := nextTS(cur, now)
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE notes SET title=?,body=?,updated_at=? WHERE id=? AND owner=? AND updated_at=?`,
		*in.Title, body, newTS, id, owner, *in.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		tx.Rollback()
		return nil, ErrConflict
	}
	if err := setTags(tx, id, tags); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.loadNote(id, owner)
}

// nextTS returns a timestamp strictly greater than prev.
func nextTS(prev string, now time.Time) string {
	t := now.UTC().Truncate(time.Microsecond)
	if p, err := time.Parse(tsFormat, prev); err == nil && !t.After(p) {
		t = p.Add(time.Microsecond)
	}
	return ts(t)
}

func (s *Store) Trash(id, owner string, permanent bool, now time.Time) error {
	o, _, _, err := s.ownerOf(id)
	if err != nil || o != owner {
		return ErrNotFound
	}
	if permanent {
		_, err = s.db.Exec(`DELETE FROM notes WHERE id=?`, id)
		return err
	}
	_, err = s.db.Exec(`UPDATE notes SET deleted_at=COALESCE(deleted_at,?) WHERE id=?`, ts(now), id)
	return err
}

func (s *Store) Restore(id, owner string) (*Note, error) {
	o, _, _, err := s.ownerOf(id)
	if err != nil || o != owner {
		return nil, ErrNotFound
	}
	if _, err := s.db.Exec(`UPDATE notes SET deleted_at=NULL WHERE id=?`, id); err != nil {
		return nil, err
	}
	return s.loadNote(id, owner)
}

// PurgeTrash permanently removes notes trashed more than 30 days before now.
func (s *Store) PurgeTrash(now time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM notes WHERE deleted_at IS NOT NULL AND deleted_at < ?`, ts(now.Add(-trashRetainer)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) CountNotes() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM notes WHERE deleted_at IS NULL`).Scan(&n)
	return n, err
}

type ListQuery struct {
	Q        string
	Tag      string
	Trash    bool
	Page     int
	PageSize int
}

type ListResult struct {
	Notes    []*Note `json:"notes"`
	Page     int     `json:"page"`
	PageSize int     `json:"page_size"`
	Total    int     `json:"total"`
}

func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func (q ListQuery) filters(args *[]any) string {
	var w []string
	for _, term := range strings.Fields(q.Q) {
		p := "%" + likeEscape(term) + "%"
		w = append(w, `(n.title LIKE ? ESCAPE '\' OR n.body LIKE ? ESCAPE '\')`)
		*args = append(*args, p, p)
	}
	if q.Tag != "" {
		w = append(w, `EXISTS (SELECT 1 FROM note_tags t WHERE t.note_id=n.id AND t.tag=?)`)
		*args = append(*args, q.Tag)
	}
	if len(w) == 0 {
		return ""
	}
	return " AND " + strings.Join(w, " AND ")
}

func (s *Store) list(base string, baseArgs []any, q ListQuery, viewer string) (*ListResult, error) {
	args := append([]any{}, baseArgs...)
	where := base + q.filters(&args)
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM notes n WHERE `+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	args = append(args, q.PageSize, (q.Page-1)*q.PageSize)
	rows, err := s.db.Query(`SELECT `+noteCols+` FROM notes n LEFT JOIN users u ON u.sub=n.owner WHERE `+where+
		` ORDER BY n.updated_at DESC, n.id LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, err
	}
	res := &ListResult{Notes: []*Note{}, Page: q.Page, PageSize: q.PageSize, Total: total}
	for rows.Next() {
		n, err := scanNote(rows, viewer, false)
		if err != nil {
			rows.Close()
			return nil, err
		}
		res.Notes = append(res.Notes, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, n := range res.Notes {
		if n.Tags, err = s.tagsForShort(n.ID); err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (s *Store) tagsForShort(id string) ([]string, error) { return s.tagsFor(id) }

func (s *Store) ListOwn(owner string, q ListQuery) (*ListResult, error) {
	cond := `n.owner=? AND n.deleted_at IS NULL`
	if q.Trash {
		cond = `n.owner=? AND n.deleted_at IS NOT NULL`
	}
	return s.list(cond, []any{owner}, q, owner)
}

func (s *Store) ListShared(viewer string, q ListQuery) (*ListResult, error) {
	cond := `n.deleted_at IS NULL AND n.owner<>? AND EXISTS (SELECT 1 FROM shares sh JOIN users me ON me.email=sh.email WHERE sh.note_id=n.id AND me.sub=?)`
	return s.list(cond, []any{viewer, viewer}, q, viewer)
}

func (s *Store) ListShares(id, owner string) ([]Share, error) {
	if o, _, _, err := s.ownerOf(id); err != nil || o != owner {
		return nil, ErrNotFound
	}
	rows, err := s.db.Query(`SELECT email,created_at FROM shares WHERE note_id=? ORDER BY created_at, email`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Share{}
	for rows.Next() {
		var sh Share
		if err := rows.Scan(&sh.Email, &sh.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sh)
	}
	return out, rows.Err()
}

func validEmail(e string) bool {
	if len(e) > 254 || strings.ContainsAny(e, " \t\r\n<>,;\"") {
		return false
	}
	i := strings.IndexByte(e, '@')
	return i > 0 && i == strings.LastIndexByte(e, '@') && i < len(e)-1 && strings.Contains(e[i+1:], ".")
}

func (s *Store) AddShare(id, owner, ownerEmail, email string, now time.Time) (*Share, error) {
	if o, _, _, err := s.ownerOf(id); err != nil || o != owner {
		return nil, ErrNotFound
	}
	email = normEmail(email)
	if !validEmail(email) {
		return nil, &ValidationError{"email", "must be a valid email address"}
	}
	if email == normEmail(ownerEmail) {
		return nil, &ValidationError{"email", "you cannot share a note with yourself"}
	}
	sh := Share{Email: email, CreatedAt: ts(now)}
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO shares(note_id,email,created_at) VALUES(?,?,?)`, id, email, sh.CreatedAt); err != nil {
		return nil, err
	}
	return &sh, s.db.QueryRow(`SELECT created_at FROM shares WHERE note_id=? AND email=?`, id, email).Scan(&sh.CreatedAt)
}

func (s *Store) RemoveShare(id, owner, email string) error {
	if o, _, _, err := s.ownerOf(id); err != nil || o != owner {
		return ErrNotFound
	}
	res, err := s.db.Exec(`DELETE FROM shares WHERE note_id=? AND email=?`, id, normEmail(email))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
