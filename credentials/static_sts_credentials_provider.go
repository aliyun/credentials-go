package credentials

import "github.com/alibabacloud-go/tea/tea"

// StsTokenCredential is a kind of credentials provider
type StaticSTSCredentialsProvider struct {
	AccessKeyId     string
	AccessKeySecret string
	SecurityToken   string
}

func NewStaticSTSCredentialsProvider(accessKeyId, accessKeySecret, securityToken string) *StaticSTSCredentialsProvider {
	return &StaticSTSCredentialsProvider{
		AccessKeyId:     accessKeyId,
		AccessKeySecret: accessKeySecret,
		SecurityToken:   securityToken,
	}
}

func (s *StaticSTSCredentialsProvider) GetCredential() (*CredentialModel, error) {
	credential := &CredentialModel{
		AccessKeyId:     tea.String(s.AccessKeyId),
		AccessKeySecret: tea.String(s.AccessKeySecret),
		SecurityToken:   tea.String(s.SecurityToken),
		Type:            tea.String("sts"),
	}
	return credential, nil
}

// GetAccessKeyId reutrns  StsTokenCredential's AccessKeyId
func (s *StaticSTSCredentialsProvider) GetAccessKeyId() (*string, error) {
	return tea.String(s.AccessKeyId), nil
}

// GetAccessSecret reutrns  StsTokenCredential's AccessKeySecret
func (s *StaticSTSCredentialsProvider) GetAccessKeySecret() (*string, error) {
	return tea.String(s.AccessKeySecret), nil
}

// GetSecurityToken reutrns  StsTokenCredential's SecurityToken
func (s *StaticSTSCredentialsProvider) GetSecurityToken() (*string, error) {
	return tea.String(s.SecurityToken), nil
}

// GetBearerToken is useless StsTokenCredential
func (s *StaticSTSCredentialsProvider) GetBearerToken() *string {
	return tea.String("")
}

// GetType reutrns  StsTokenCredential's type
func (s *StaticSTSCredentialsProvider) GetType() *string {
	return tea.String("sts")
}
