package credentials

// StsTokenCredential is a kind of credentials
type StsTokenCredential struct {
	AccessKeyId     string
	AccessKeySecret string
	SecurityToken   string
}

func newStsTokenCredential(accessKeyId, accessKeySecret, securityToken string) *StsTokenCredential {
	return &StsTokenCredential{
		AccessKeyId:     accessKeyId,
		AccessKeySecret: accessKeySecret,
		SecurityToken:   securityToken,
	}
}

// GetAccessKeyId reutrns  StsTokenCredential's AccessKeyId
func (s *StsTokenCredential) GetAccessKeyId() (string, error) {
	return s.AccessKeyId, nil
}

// GetAccessSecret reutrns  StsTokenCredential's AccessKeySecret
func (s *StsTokenCredential) GetAccessKeySecret() (string, error) {
	return s.AccessKeySecret, nil
}

// GetSecurityToken reutrns  StsTokenCredential's SecurityToken
func (s *StsTokenCredential) GetSecurityToken() (string, error) {
	return s.SecurityToken, nil
}

// GetBearerToken is useless StsTokenCredential
func (s *StsTokenCredential) GetBearerToken() string {
	return ""
}

// GetType reutrns  StsTokenCredential's type
func (s *StsTokenCredential) GetType() string {
	return "sts"
}
