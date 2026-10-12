package app

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	SessionCookie = "sn_session"
	StateCookie   = "sn_oauth"
	SessionTTL    = 14 * 24 * time.Hour
)

var ErrBadToken = errors.New("invalid token")

var b64 = base64.RawURLEncoding

// sign produces payload.mac where mac = HMAC-SHA256(key, purpose|payload).
func sign(key []byte, purpose string, v any) (string, error) {
	p, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	enc := b64.EncodeToString(p)
	return enc + "." + mac(key, purpose, enc), nil
}

func mac(key []byte, purpose, enc string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(purpose + "|" + enc))
	return b64.EncodeToString(h.Sum(nil))
}

func verify(key []byte, purpose, token string, out any) error {
	i := strings.IndexByte(token, '.')
	if i < 0 {
		return ErrBadToken
	}
	enc, m := token[:i], token[i+1:]
	if subtle.ConstantTimeCompare([]byte(m), []byte(mac(key, purpose, enc))) != 1 {
		return ErrBadToken
	}
	p, err := b64.DecodeString(enc)
	if err != nil {
		return ErrBadToken
	}
	if err := json.Unmarshal(p, out); err != nil {
		return ErrBadToken
	}
	return nil
}

type sessionClaims struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
}

// SignSession returns a session cookie value for the user.
func SignSession(key []byte, sub string, exp time.Time) (string, error) {
	return sign(key, "session", sessionClaims{Sub: sub, Exp: exp.Unix()})
}

// VerifySession returns the user sub if the token is authentic and not expired.
func VerifySession(key []byte, token string, now time.Time) (string, error) {
	var c sessionClaims
	if err := verify(key, "session", token, &c); err != nil {
		return "", err
	}
	if c.Sub == "" || now.Unix() >= c.Exp {
		return "", ErrBadToken
	}
	return c.Sub, nil
}

type oauthState struct {
	State    string `json:"s"`
	Verifier string `json:"v"`
	Exp      int64  `json:"exp"`
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b64.EncodeToString(b)
}

// loadOrCreateKey reads DATA_DIR/keys.json or creates it with a random 32-byte session key.
func loadOrCreateKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, "keys.json")
	type keysFile struct {
		SessionKey string `json:"session_key"`
	}
	if b, err := os.ReadFile(path); err == nil {
		var k keysFile
		if err := json.Unmarshal(b, &k); err != nil {
			return nil, errors.New("keys.json is corrupt")
		}
		key, err := b64.DecodeString(k.SessionKey)
		if err != nil || len(key) != 32 {
			return nil, errors.New("keys.json has an invalid session key")
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	b, _ := json.Marshal(keysFile{SessionKey: b64.EncodeToString(key)})
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return key, nil
}
