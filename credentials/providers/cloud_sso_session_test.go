package providers

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	httputil "github.com/aliyun/credentials-go/credentials/internal/http"
	"github.com/stretchr/testify/require"
)

func TestCLIProfileSharedCloudSSOSession(t *testing.T) {
	root, err := ioutil.TempDir("", "cloud-sso")
	require.NoError(t, err)
	defer os.RemoveAll(root)
	config := filepath.Join(root, "custom.json")
	require.NoError(t, ioutil.WriteFile(config, []byte(`{"current":"dev","profiles":[{"name":"dev","mode":"CloudSSO","sso_session":"company","cloud_sso_account_id":"account","cloud_sso_access_config":"role","access_token":"legacy"}]}`), 0600))
	config, err = filepath.EvalSymlinks(config)
	require.NoError(t, err)
	namespace := fmt.Sprintf("%x", sha256.Sum256([]byte(config)))
	dir := filepath.Join(filepath.Dir(config), "sso", namespace)
	require.NoError(t, os.MkdirAll(dir, 0700))
	sessionPath := filepath.Join(dir, "company.json")

	cli, err := NewCLIProfileCredentialsProviderBuilder().WithProfileFile(config).Build()
	require.NoError(t, err)
	conf, err := newConfigurationFromPath(config)
	require.NoError(t, err)
	cp, err := cli.getCredentialsProvider(conf, "dev")
	require.NoError(t, err)
	provider := cp.(*CloudSSOCredentialsProvider)

	originHTTPDo := httpDo
	defer func() { httpDo = originHTTPDo }()
	var received []string
	httpDo = func(req *httputil.Request) (*httputil.Response, error) {
		require.Equal(t, "/cloud-credentials", req.Path)
		require.JSONEq(t, `{"AccountId":"account","AccessConfigurationId":"role"}`, string(req.Body))
		received = append(received, req.Headers["Authorization"])
		return &httputil.Response{StatusCode: 200, Body: []byte(`{"CloudCredential":{"AccessKeyId":"ak","AccessKeySecret":"sk","SecurityToken":"sts","Expiration":"2099-01-01T00:00:00Z"}}`)}, nil
	}
	_, err = provider.getCredentials()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to read CloudSSO session")
	for _, token := range []string{"first", "second"} {
		data, err := json.Marshal(cloudSSOSession{"company", "https://example.test/sign-in", token, time.Now().Unix() + 300})
		require.NoError(t, err)
		require.NoError(t, ioutil.WriteFile(sessionPath, data, 0600))
		_, err = provider.getCredentials()
		require.NoError(t, err)
	}
	require.Equal(t, []string{"Bearer first", "Bearer second"}, received)
	require.NoError(t, ioutil.WriteFile(sessionPath, []byte(`{"name":"company","sign_in_url":"https://example.test","access_token":"expired","expires_at":1}`), 0600))
	_, err = provider.getCredentials()
	require.Error(t, err)
	require.Contains(t, err.Error(), "expired")
	_, err = readCloudSSOSession(config, config, "../outside")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid CloudSSO session name")
}
