package credentials

// AccessKeyCredential is a kind of credential
type AccessKeyCredential struct {
	AccessKeyId     string
	AccessKeySecret string
}

func newAccessKeyCredential(accessKeyId, accessKeySecret string) *AccessKeyCredential {
	return &AccessKeyCredential{
		AccessKeyId:     accessKeyId,
		AccessKeySecret: accessKeySecret,
	}
}

// GetAccessKeyId reutrns  AccessKeyCreential's AccessKeyId
func (a *AccessKeyCredential) GetAccessKeyId() (string, error) {
	return a.AccessKeyId, nil
}

// GetAccessSecret reutrns  AccessKeyCreential's AccessKeySecret
func (a *AccessKeyCredential) GetAccessKeySecret() (string, error) {
	return a.AccessKeySecret, nil
}

// GetSecurityToken is useless for AccessKeyCreential
func (a *AccessKeyCredential) GetSecurityToken() (string, error) {
	return "", nil
}

// GetBearerToken is useless for AccessKeyCreential
func (a *AccessKeyCredential) GetBearerToken() string {
	return ""
}

// GetType reutrns  AccessKeyCreential's type
func (a *AccessKeyCredential) GetType() string {
	return "access_key"
}
