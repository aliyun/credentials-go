package credentials

// BearerTokenCredential is a kind of credential
type BearerTokenCredential struct {
	BearerToken string
}

// newBearerTokenCredential return a BearerTokenCredential object
func newBearerTokenCredential(token string) *BearerTokenCredential {
	return &BearerTokenCredential{
		BearerToken: token,
	}
}

// GetAccessKeyId is useless for BearerTokenCredential
func (b *BearerTokenCredential) GetAccessKeyId() (string, error) {
	return "", nil
}

// GetAccessSecret is useless for BearerTokenCredential
func (b *BearerTokenCredential) GetAccessKeySecret() (string, error) {
	return "", nil
}

// GetSecurityToken is useless for BearerTokenCredential
func (b *BearerTokenCredential) GetSecurityToken() (string, error) {
	return "", nil
}

// GetBearerToken reutrns  BearerTokenCredential's BearerToken
func (b *BearerTokenCredential) GetBearerToken() string {
	return b.BearerToken
}

// GetType reutrns  BearerTokenCredential's type
func (b *BearerTokenCredential) GetType() string {
	return "bearer"
}
