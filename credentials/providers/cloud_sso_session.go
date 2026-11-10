package providers

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"time"
)

var cloudSSOSessionName = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

type cloudSSOSession struct {
	Name        string `json:"name"`
	SignInURL   string `json:"sign_in_url"`
	AccessToken string `json:"access_token"`
	ExpiresAt   int64  `json:"expires_at"`
}

func readCloudSSOSession(configPath, defaultPath, name string) (session cloudSSOSession, err error) {
	if !cloudSSOSessionName.MatchString(name) {
		return session, fmt.Errorf("invalid CloudSSO session name")
	}
	configPath = canonicalCloudSSOConfigPath(configPath)
	defaultPath = canonicalCloudSSOConfigPath(defaultPath)
	dir := filepath.Join(filepath.Dir(configPath), "sso")
	if configPath != defaultPath {
		dir = filepath.Join(dir, fmt.Sprintf("%x", sha256.Sum256([]byte(configPath))))
	}
	data, err := ioutil.ReadFile(filepath.Join(dir, name+".json"))
	if err != nil {
		return session, fmt.Errorf("unable to read CloudSSO session %q: %w", name, err)
	}
	if json.Unmarshal(data, &session) != nil || session.Name != name || session.SignInURL == "" {
		return session, fmt.Errorf("invalid CloudSSO session %q", name)
	}
	if session.AccessToken == "" || session.ExpiresAt <= time.Now().Unix() {
		return session, fmt.Errorf("CloudSSO session %q access token is empty or expired, please re-login with CLI", name)
	}
	return session, nil
}

func canonicalCloudSSOConfigPath(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	} else {
		// The default config might not exist, while its parent is a symlink.
		dir, file := filepath.Split(path)
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			path = filepath.Join(resolved, file)
		}
	}
	if absolute, err := filepath.Abs(path); err == nil {
		return absolute
	}
	return path
}
