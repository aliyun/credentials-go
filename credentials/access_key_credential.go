package credentials

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

func (a *AccessKeyCredential) GetAccessKeyId() (string, error) {
	return a.AccessKeyId, nil
}

func (a *AccessKeyCredential) GetAccessSecret() (string, error) {
	return a.AccessKeySecret, nil
}

func (a *AccessKeyCredential) GetSecurityToken() (string, error) {
	return "", nil
}

func (a *AccessKeyCredential) GetBearerToken() string {
	return ""
}

func (a *AccessKeyCredential) GetType() string {
	return "access_key"
}
