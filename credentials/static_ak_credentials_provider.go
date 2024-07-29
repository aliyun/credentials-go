package credentials

import "github.com/alibabacloud-go/tea/tea"

// StaticAKCredentialsProvider is a kind of credentials provider
type StaticAKCredentialsProvider struct {
	AccessKeyId     string
	AccessKeySecret string
}

func newAccessKeyCredential(accessKeyId, accessKeySecret string) *StaticAKCredentialsProvider {
	return &StaticAKCredentialsProvider{
		AccessKeyId:     accessKeyId,
		AccessKeySecret: accessKeySecret,
	}
}

func (s *StaticAKCredentialsProvider) GetCredential() (*CredentialModel, error) {
	credential := &CredentialModel{
		AccessKeyId:     tea.String(s.AccessKeyId),
		AccessKeySecret: tea.String(s.AccessKeySecret),
		Type:            tea.String("access_key"),
	}
	return credential, nil
}

// GetAccessKeyId reutrns  AccessKeyCreential's AccessKeyId
func (a *StaticAKCredentialsProvider) GetAccessKeyId() (*string, error) {
	return tea.String(a.AccessKeyId), nil
}

// GetAccessSecret reutrns  AccessKeyCreential's AccessKeySecret
func (a *StaticAKCredentialsProvider) GetAccessKeySecret() (*string, error) {
	return tea.String(a.AccessKeySecret), nil
}

// GetSecurityToken is useless for AccessKeyCreential
func (a *StaticAKCredentialsProvider) GetSecurityToken() (*string, error) {
	return tea.String(""), nil
}

// GetBearerToken is useless for AccessKeyCreential
func (a *StaticAKCredentialsProvider) GetBearerToken() *string {
	return tea.String("")
}

// GetType reutrns  AccessKeyCreential's type
func (a *StaticAKCredentialsProvider) GetType() *string {
	return tea.String("access_key")
}
