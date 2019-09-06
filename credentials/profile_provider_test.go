package credentials

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var inistr = `
[default]              
enable = true                    
type = access_key                
access_key_id = foo               
access_key_secret = bar            
				   
[notype]              
access_key_id = foo               
access_key_secret = bar

[noak]
type = access_key                        
access_key_secret = bar   

[emptyak]
type = access_key                
access_key_id =                
access_key_secret = bar 

[noaksecret]
type = access_key  
access_key_id =  bar                       

[emptyaksecret]
type = access_key                
access_key_id =  bar              
access_key_secret =  

[ecs]                         
type = ecs_ram_role                
role_name = EcsRamRoleTest

[noecs]
type = ecs_ram_role                

[emptyecs]                         
type = ecs_ram_role                
role_name = 

[invalidRuntimeEcs]                         
type = ecs_ram_role                
role_name = EcsRamRoleTest
timeout = a

[ram]                                         
type = ram_role_arn                
access_key_id = foo
access_key_secret = bar
role_arn = role_arn
role_session_name = session_name  

[noramak]                                         
type = ram_role_arn                
access_key_secret = bar
role_arn = role_arn
role_session_name = session_name  

[emptyramak]                                         
type = ram_role_arn                
access_key_id = 
access_key_secret = bar
role_arn = role_arn
role_session_name = session_name

[noramsecret]                                         
type = ram_role_arn  
access_key_id = id              
role_arn = role_arn
role_session_name = session_name  

[emptyramsecret]                                         
type = ram_role_arn                
access_key_id = id
access_key_secret =
role_arn = role_arn
role_session_name = session_name

[noramarn]                                         
type = ram_role_arn
access_key_id = id                
access_key_secret = bar
role_session_name = session_name  

[emptyramarn]                                         
type = ram_role_arn                
access_key_id = id
access_key_secret = bar
role_arn =
role_session_name = session_name

[noramsessionname]                                         
type = ram_role_arn   
access_key_id = id             
access_key_secret = bar
role_arn = role_arn

[emptyramsessionname]                                         
type = ram_role_arn                
access_key_id = id
access_key_secret = bar
role_arn = role_arn
role_session_name =

[invalidexpirationram]                                         
type = ram_role_arn                
access_key_id = foo
access_key_secret = bar
role_arn = role_arn
role_session_name = session_name
role_session_expiration = a

[invalidRuntimeram]                         
type = ram_role_arn                
access_key_id = foo
access_key_secret = bar
role_arn = role_arn
role_session_name = session_name
timeout = a

[sts]                                         
type = sts                
access_key_id = foo
access_key_secret = bar
security_token= token

[nostskey]                                         
type = sts                
access_key_secret = bar
security_token= token 

[emptystskey]                                         
type = sts                
access_key_id =
access_key_secret = bar
security_token= token

[nostssecret]                                         
type = sts    
access_key_id = id          
security_token= token 

[emptystssecret]                                         
type = sts                
access_key_id = id
access_key_secret =
security_token= token

[noststoken]                                         
type = sts     
access_key_id = id           
access_key_secret = bar

[emptyststoken]                                         
type = sts                
access_key_id = id
access_key_secret = bar
security_token=

[bearer]                                         
type = bearer                
bearer_token = foo 

[nobearer]                                         
type = bearer                

[emptybearer]                                         
type = bearer                
bearer_token = 

[rsa]                          
type = rsa_key_pair               
public_key_id = publicKeyID       
private_key_file = ./pk.pem
proxy = www.aliyun.com
timeout = 10
connect_timeout = 10
host = www.aliyun.com

[norsaprivate]                          
type = rsa_key_pair               
public_key_id = publicKeyID       

[emptyrsaprivate]                          
type = rsa_key_pair               
public_key_id = publicKeyID       
private_key_file = 

[norsapublic]                          
type = rsa_key_pair  
private_key_file = ./pk.pem             

[emptyrsapublic]                          
type = rsa_key_pair               
public_key_id =       
private_key_file = ./pk.pem

[invalidexpirationrsa]                                         
type = rsa_key_pair               
public_key_id = publicKeyID       
private_key_file = ./pk.pem
session_expiration = a

[invalidTimeoutrsa]                         
type = rsa_key_pair               
public_key_id = publicKeyID       
private_key_file = ./pk.pem
timeout = a

[invalidConnectTimeoutrsa]                         
type = rsa_key_pair               
public_key_id = publicKeyID       
private_key_file = ./pk.pem
connect_timeout = a

[error_type]                          
type = error_type               
public_key_id = publicKeyID       
private_key_file = ./pk_error.pem
`

func TestProfileProvider(t *testing.T) {
	var HOME string
	if runtime.GOOS == "windows" {
		HOME = "USERPROFILE"
	} else {
		HOME = "HOME"
	}
	path, ok := os.LookupEnv(HOME)
	assert.True(t, ok)
	os.Unsetenv(HOME)

	// testcase 1, no HOME or USERPROFILE environment variable set
	p := NewProfileProvider()
	c, err := p.Resolve()
	assert.Nil(t, c)
	assert.EqualError(t, err, "The default credential file path is invalid")

	originFilePath := os.Getenv(ENVCredentialFile)
	os.Setenv(ENVCredentialFile, "")
	defer func() {
		os.Setenv(ENVCredentialFile, originFilePath)
	}()
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.EqualError(t, err, "ALIBABA_CLOUD_CREDENTIALS_FILE cannot be empty")

	// testcase 2, default profile object
	os.Unsetenv(ENVCredentialFile)
	os.Setenv(HOME, path)
	p = NewProfileProvider()
	value, ok := p.(*ProfileProvider)
	assert.True(t, ok)
	assert.Equal(t, value.Profile, "default")

	// testcase 3, credential file does not exist in the default path
	// and section name does not exist
	p = NewProfileProvider("first")
	value, ok = p.(*ProfileProvider)
	assert.True(t, ok)
	assert.Equal(t, value.Profile, "first")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Nil(t, err)

	// testcase 4, credential file path is error
	os.Setenv(ENVCredentialFile, "../../credentials_error")
	p = NewProfileProvider()
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.True(t, strings.Contains(err.Error(), "ERROR: Can not open file"))

	// create profile
	os.Setenv(ENVCredentialFile, "./credentials")

	file, err := os.Create("./credentials")
	assert.Nil(t, err)
	file.WriteString(inistr)
	file.Close()
	defer os.Remove("./credentials")

	// testcase 5, section does not exist
	p = NewProfileProvider("NonExist")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "ERROR: Can not load section section 'NonExist' does not exist", err.Error())

	// testcase 6, credential type does not set
	p = NewProfileProvider("notype")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Missing required type option error when getting key of section 'notype': key 'type' not exists", err.Error())

	// testcase 7, normal AK
	p = NewProfileProvider()
	c, err = p.Resolve()
	assert.Nil(t, err)
	// testcase 8, access_key_id key does not exist
	p = NewProfileProvider("noak")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Missing required access_key_id option in profile for access_key", err.Error())
	// testcase 9, access_key_id value is empty
	p = NewProfileProvider("emptyak")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "access_key_id cannot be empty", err.Error())
	// testcase 10, access_key_secret key does not exist
	p = NewProfileProvider("noaksecret")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Missing required access_key_secret option in profile for access_key", err.Error())
	// testcase 11, access_key_secret value is empty
	p = NewProfileProvider("emptyaksecret")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "access_key_secret cannot be empty", err.Error())

	//testcase 12, normal EcsRamRole
	p = NewProfileProvider("ecs")
	c, err = p.Resolve()
	assert.Nil(t, err)
	//testcase 13, key does not exist
	p = NewProfileProvider("noecs")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Missing required role_name option in profile for ecs_ram_role", err.Error())
	//testcase 14, value is empty
	p = NewProfileProvider("emptyecs")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "role_name cannot be empty", err.Error())
	//testcase 15, timeout is not int
	p = NewProfileProvider("invalidRuntimeEcs")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Please set timeout with an int value", err.Error())

	//testcase 16, normal RamRoleArn
	p = NewProfileProvider("ram")
	c, err = p.Resolve()
	assert.Nil(t, err)
	//testcase 17, access_key_id key does not exist
	p = NewProfileProvider("noramak")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Missing required access_key_id option in profile for ram_role_arn", err.Error())
	//testcase 18, access_key_id value is empty
	p = NewProfileProvider("emptyramak")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "access_key_id cannot be empty", err.Error())
	//testcase 19, access_key_secret key does not exist
	p = NewProfileProvider("noramsecret")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Missing required access_key_secret option in profile for ram_role_arn", err.Error())
	//testcase 20, access_key_secret value is empty
	p = NewProfileProvider("emptyramsecret")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "access_key_secret cannot be empty", err.Error())
	//testcase 21, role_arn key does not exist
	p = NewProfileProvider("noramarn")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Missing required role_arn option in profile for ram_role_arn", err.Error())
	//testcase 22, role_arn value is empty
	p = NewProfileProvider("emptyramarn")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "role_arn cannot be empty", err.Error())
	//testcase 23, role_session_name key does not exist
	p = NewProfileProvider("noramsessionname")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Missing required role_session_name option in profile for ram_role_arn", err.Error())
	//testcase 24, role_session_name value is empty
	p = NewProfileProvider("emptyramsessionname")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "role_session_name cannot be empty", err.Error())
	//testcase 25, role_session_expiration is not int
	p = NewProfileProvider("invalidexpirationram")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "role_session_expiration must be an int", err.Error())
	//testcase 26, timeout is not int
	p = NewProfileProvider("invalidRuntimeram")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Please set timeout with an int value", err.Error())

	//testase 27, normal RsaKeyPair
	file, err = os.Create("./pk.pem")
	assert.Nil(t, err)
	_, err = file.WriteString(privatekey)
	assert.Nil(t, err)
	file.Close()

	p = NewProfileProvider("rsa")
	c, err = p.Resolve()
	assert.Nil(t, err)
	defer os.Remove(`./pk.pem`)
	//testcase 28, private_key_file key does not exist
	p = NewProfileProvider("norsaprivate")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Missing required private_key_file option in profile for rsa_key_pair", err.Error())
	//testcase 29, private_key_file value is empty
	p = NewProfileProvider("emptyrsaprivate")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "private_key_file cannot be empty", err.Error())
	//testcase 30, public_key_id key does not exist
	p = NewProfileProvider("norsapublic")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Missing required public_key_id option in profile for rsa_key_pair", err.Error())
	//testcase 31, public_key_id value is empty
	p = NewProfileProvider("emptyrsapublic")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "public_key_id cannot be empty", err.Error())
	//testcase 32, session_expiration is not int
	p = NewProfileProvider("invalidexpirationrsa")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "session_expiration must be an int", err.Error())
	//testcase 33, timeout is not int
	p = NewProfileProvider("invalidTimeoutrsa")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Please set timeout with an int value", err.Error())
	//testcase 34, connect_timeout is not int
	p = NewProfileProvider("invalidConnectTimeoutrsa")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Please set connect_timeout with an int value", err.Error())

	//testcase 35, normal RamRoleArn
	p = NewProfileProvider("sts")
	c, err = p.Resolve()
	assert.Nil(t, err)
	//testcase 36, access_key_id key does not exist
	p = NewProfileProvider("nostskey")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Missing required access_key_id option in profile for sts", err.Error())
	//testcase 37, access_key_id value is empty
	p = NewProfileProvider("emptystskey")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "access_key_id cannot be empty", err.Error())
	//testcase 38, access_key_secret key does not exist
	p = NewProfileProvider("nostssecret")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Missing required access_key_secret option in profile for sts", err.Error())
	//testcase 39, access_key_secret value is empty
	p = NewProfileProvider("emptystssecret")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "access_key_secret cannot be empty", err.Error())
	//testcase 40, security_token access_key_secretkey does not exist
	p = NewProfileProvider("noststoken")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Missing required security_token option in profile for sts", err.Error())
	//testcase 41, security_token value is empty
	p = NewProfileProvider("emptyststoken")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "security_token cannot be empty", err.Error())

	//testcase 42, normal RamRoleArn
	p = NewProfileProvider("bearer")
	c, err = p.Resolve()
	assert.Nil(t, err)
	//testcase 43, key does not exist
	p = NewProfileProvider("nobearer")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Missing required bearer_token option in profile for bearer", err.Error())
	//testcase 44, value is empty
	p = NewProfileProvider("emptybearer")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "bearer_token cannot be empty", err.Error())

	//testcase 45, credential type is error
	p = NewProfileProvider("error_type")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.Equal(t, "Invalid type option, support: access_key, sts, ecs_ram_role, ram_role_arn, rsa_key_pair", err.Error())
}

func TestHookOS(t *testing.T) {
	goos := "windows"
	goos = hookOS(goos)
	assert.Equal(t, "windows", goos)

	originHookOs := hookOS
	originUserProfile := os.Getenv("USERPROFILE")
	hookOS = func(goos string) string {
		return "windows"
	}
	defer func() {
		hookOS = originHookOs
		os.Setenv("USERPROFILE", originUserProfile)
	}()
	os.Unsetenv("USERPROFILE")
	path := GetHomePath()
	assert.Equal(t, "", path)

	os.Setenv("USERPROFILE", "ok")
	path = GetHomePath()
	assert.Equal(t, "ok", path)
}

func TestHookState(t *testing.T) {
	info, err := hookState(nil, nil)
	assert.Nil(t, info)
	assert.Nil(t, err)

	originHookState := hookState
	hookState = func(info os.FileInfo, err error) (os.FileInfo, error) {
		return nil, nil
	}
	defer func() {
		hookState = originHookState
	}()
	path, err := checkDefaultPath()
	assert.Nil(t, err)
	assert.NotNil(t, path)
}
