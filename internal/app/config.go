package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const Version = "1.0.0"

// Config is the resolved application configuration.
type Config struct {
	Domain           string
	GoogleClientID   string
	GoogleSecret     string
	ACMEEmail        string
	ACMEDirectoryURL string
}

// Settings are the values that do not come from Secrets Manager.
type Settings struct {
	HTTPPort        string
	HTTPSPort       string
	DataDir         string
	SecretName      string
	DevInsecureHTTP bool
	VolumeStateFile string
	Env             map[string]string // environment values for Config (DOMAIN, ...)
}

func SettingsFromEnv() Settings {
	get := func(k, def string) string {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
		return def
	}
	env := map[string]string{}
	for _, k := range []string{"DOMAIN", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "ACME_EMAIL", "ACME_DIRECTORY_URL"} {
		env[k] = strings.TrimSpace(os.Getenv(k))
	}
	return Settings{
		HTTPPort:        get("HTTP_PORT", "80"),
		HTTPSPort:       get("HTTPS_PORT", "443"),
		DataDir:         get("DATA_DIR", "/data"),
		SecretName:      get("CONFIG_SECRET_NAME", "secure-notes/config"),
		DevInsecureHTTP: os.Getenv("DEV_INSECURE_HTTP") == "1",
		VolumeStateFile: get("VOLUME_STATE_FILE", "/run/secure-notes-volume.state"),
		Env:             env,
	}
}

// SecretFetcher reads a secret string by name.
type SecretFetcher interface {
	GetSecretString(ctx context.Context, name string) (string, error)
}

type awsSecrets struct{ client *secretsmanager.Client }

// NewAWSSecrets creates a fetcher using the default credential chain (instance role).
func NewAWSSecrets(ctx context.Context) (SecretFetcher, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithEC2IMDSRegion())
	if err != nil {
		return nil, err
	}
	return &awsSecrets{client: secretsmanager.NewFromConfig(cfg)}, nil
}

func (a *awsSecrets) GetSecretString(ctx context.Context, name string) (string, error) {
	out, err := a.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: &name})
	if err != nil {
		return "", err
	}
	if out.SecretString == nil {
		return "", errors.New("secret has no string value")
	}
	return *out.SecretString, nil
}

type secretJSON struct {
	Domain           string `json:"domain"`
	GoogleClientID   string `json:"google_client_id"`
	GoogleSecret     string `json:"google_client_secret"`
	ACMEEmail        string `json:"acme_email"`
	ACMEDirectoryURL string `json:"acme_directory_url"`
}

// ResolveConfig combines the environment with the secret; the environment wins.
// The fetcher is only used when a required value is missing from the environment.
func ResolveConfig(ctx context.Context, env map[string]string, fetch func(context.Context) (SecretFetcher, error), secretName string) (Config, error) {
	c := Config{
		Domain:           env["DOMAIN"],
		GoogleClientID:   env["GOOGLE_CLIENT_ID"],
		GoogleSecret:     env["GOOGLE_CLIENT_SECRET"],
		ACMEEmail:        env["ACME_EMAIL"],
		ACMEDirectoryURL: env["ACME_DIRECTORY_URL"],
	}
	needSecret := c.Domain == "" || c.GoogleClientID == "" || c.GoogleSecret == ""
	if needSecret {
		f, err := fetch(ctx)
		if err != nil {
			return Config{}, fmt.Errorf("aws config: %w", err)
		}
		raw, err := f.GetSecretString(ctx, secretName)
		if err != nil {
			return Config{}, fmt.Errorf("get secret: %w", err)
		}
		var s secretJSON
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			return Config{}, errors.New("secret is not valid JSON")
		}
		fill := func(dst *string, v string) {
			if *dst == "" {
				*dst = strings.TrimSpace(v)
			}
		}
		fill(&c.Domain, s.Domain)
		fill(&c.GoogleClientID, s.GoogleClientID)
		fill(&c.GoogleSecret, s.GoogleSecret)
		fill(&c.ACMEEmail, s.ACMEEmail)
		fill(&c.ACMEDirectoryURL, s.ACMEDirectoryURL)
	}
	var missing []string
	if c.Domain == "" {
		missing = append(missing, "domain")
	}
	if c.GoogleClientID == "" {
		missing = append(missing, "google_client_id")
	}
	if c.GoogleSecret == "" {
		missing = append(missing, "google_client_secret")
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing configuration: %s", strings.Join(missing, ", "))
	}
	if c.ACMEDirectoryURL == "" {
		c.ACMEDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"
	}
	return c, nil
}

// retryResolve keeps trying with exponential backoff until success or ctx is done.
func retryResolve(ctx context.Context, try func(context.Context) error, initial, max time.Duration, logf func(attempt int, err error)) error {
	delay := initial
	for attempt := 1; ; attempt++ {
		err := try(ctx)
		if err == nil {
			return nil
		}
		logf(attempt, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
		if delay > max {
			delay = max
		}
	}
}
