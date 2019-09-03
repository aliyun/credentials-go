package credentials

type BearerTokenCredential struct {
	BearerToken string
}

// newBearerTokenCredential return a BearerTokenCredential object
func newBearerTokenCredential(token string) *BearerTokenCredential {
	return &BearerTokenCredential{
		BearerToken: token,
	}
}

func (b *BearerTokenCredential) GetAccessKeyId() (string, error) {
	return "", nil
}

func (b *BearerTokenCredential) GetAccessSecret() (string, error) {
	return "", nil
}

func (b *BearerTokenCredential) GetSecurityToken() (string, error) {
	return "", nil
}

func (b *BearerTokenCredential) GetBearerToken() string {
	return b.BearerToken
}

func (b *BearerTokenCredential) GetType() string {
	return "bearer"
}
