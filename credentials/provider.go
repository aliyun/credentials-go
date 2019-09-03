package credentials

//Environmental virables that may be used by the provider
const (
	ENVCredentialFile  = "ALIBABA_CLOUD_CREDENTIALS_FILE"
	ENVEcsMetadata     = "ALIBABA_CLOUD_ECS_METADATA"
	PATHCredentialFile = "~/.alibabacloud/credentials"
)

// When you want to customize the provider, you only need to implement the method of the interface.
type Provider interface {
	Resolve() (*Configuration, error)
}
