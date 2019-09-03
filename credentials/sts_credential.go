package credentials

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

func (s *StsTokenCredential) GetAccessKeyId() (string, error) {
	return s.AccessKeyId, nil
}

func (s *StsTokenCredential) GetAccessSecret() (string, error) {
	return s.AccessKeySecret, nil
}

func (s *StsTokenCredential) GetSecurityToken() (string, error) {
	return s.SecurityToken, nil
}

func (s *StsTokenCredential) GetBearerToken() string {
	return ""
}

func (s *StsTokenCredential) GetType() string {
	return "sts"
}
