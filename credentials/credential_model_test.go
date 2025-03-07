package credentials

import (
	"testing"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
)

func Test_Credential(t *testing.T) {
	cred := &CredentialModel{
		AccessKeyId:     tea.String("AccessKeyId"),
		AccessKeySecret: tea.String("AccessKeySecret"),
		SecurityToken:   tea.String("SecurityToken"),
		BearerToken:     tea.String("BearerToken"),
		Type:            tea.String("Type"),
		ProviderName:    tea.String("ProviderName"),
	}
	assert.Equal(t, "AccessKeyId", *cred.AccessKeyId)
	assert.Equal(t, "AccessKeySecret", *cred.AccessKeySecret)
	assert.Equal(t, "SecurityToken", *cred.SecurityToken)
	assert.Equal(t, "BearerToken", *cred.BearerToken)
	assert.Equal(t, "Type", *cred.Type)
	assert.Equal(t, "ProviderName", *cred.ProviderName)

	assert.Equal(t, "{\n   \"accessKeyId\": \"AccessKeyId\",\n   \"accessKeySecret\": \"AccessKeySecret\",\n   \"securityToken\": \"SecurityToken\",\n   \"bearerToken\": \"BearerToken\",\n   \"type\": \"Type\",\n   \"providerName\": \"ProviderName\"\n}", cred.String())
	assert.Equal(t, "{\n   \"accessKeyId\": \"AccessKeyId\",\n   \"accessKeySecret\": \"AccessKeySecret\",\n   \"securityToken\": \"SecurityToken\",\n   \"bearerToken\": \"BearerToken\",\n   \"type\": \"Type\",\n   \"providerName\": \"ProviderName\"\n}", cred.GoString())

	cred = &CredentialModel{}
	cred.SetAccessKeyId("")
	cred.SetAccessKeySecret("")
	cred.SetSecurityToken("")
	assert.Equal(t, "", *cred.AccessKeyId)
	assert.Equal(t, "", *cred.AccessKeySecret)
	assert.Equal(t, "", *cred.SecurityToken)
	assert.Nil(t, cred.BearerToken)
	assert.Nil(t, cred.Type)
	assert.Nil(t, cred.ProviderName)
}

func Test_Credential2(t *testing.T) {
	cred := &CredentialModel{}
	cred.SetBearerToken("bearertoken")
	assert.Equal(t, "bearertoken", *cred.BearerToken)
	cred.SetType("bearertoken")
	cred.SetProviderName("bearertoken")
	assert.Equal(t, "bearertoken", *cred.Type)
	assert.Equal(t, "bearertoken", *cred.ProviderName)
}
