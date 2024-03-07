package secretmanage

import (
	"dev.azure.com/vib-lz-devops/B08-DSC-Project-SmartCollection/_git/smartcollection-base-go.git/storage/local"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"log"
	"os"
)

type AccountAuth struct {
	OmsHostAddr        string `json:"oms_host_addr"`
	OmsUserName        string `json:"oms_user_name"`
	OmsUserPassword    string `json:"oms_user_password"`
	EsbHostAddr        string `json:"esb_host_addr"`
	EsbUserName        string `json:"esb_user_name"`
	EsbPassword        string `json:"esb_password"`
	LdapUrlAddress     string `json:"ldap_url_address"`
	ApimHostAddr       string `json:"apim_host_addr"`
	ApimUserName       string `json:"apim_user_name"`
	ApimUserPassword   string `json:"apim_user_password"`
	ApimUserAuth       string `json:"apim_user_auth"`
	EkycHost           string `json:"ekyc_host"`
	EkycAccessKey      string `json:"ekyc_access_key"`
	EkycSecret         string `json:"ekyc_secret"`
	AppProfileSecret   string `json:"app_profile_secret"`
	JwtTokenContentKey string `json:"jwt_token_content_key"`
}
type AccountEmail struct {
	EmailUsername         string `json:"email_username"`
	EmailUserAgentApp     string `json:"email_user_agent_app"`
	EmailPasswordAgentApp string `json:"email_password_agent_app"`
	EmailHost             string `json:"email_host"`
	EmailPort             string `json:"email_port"`
}

func GetAccountAuth() (*AccountAuth, error) {
	accountAuth := AccountAuth{}

	secretName := local.Getenv("AWS_SECRET_AGENTAPP_NAME")
	region := local.Getenv("AWS_REGION")
	log.Print(fmt.Sprintf("secretName : %s", secretName))

	conf := aws.Config{
		Region: aws.String(region),
	}
	svc := secretsmanager.New(awssession.New(&conf))
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"),
	}
	result, err := svc.GetSecretValue(input)
	if err != nil {
		return nil, err
	}
	var secretString, decodedBinarySecret string

	if result.SecretString != nil {
		secretString = *result.SecretString
		json.Unmarshal([]byte(secretString), &accountAuth)
	} else {
		decodedBinarySecretBytes := make([]byte, base64.StdEncoding.DecodedLen(len(result.SecretBinary)))
		len, err := base64.StdEncoding.Decode(decodedBinarySecretBytes, result.SecretBinary)
		if err != nil {
			fmt.Println("Base64 Decode Error:", err)
		}
		decodedBinarySecret = string(decodedBinarySecretBytes[:len])
		json.Unmarshal([]byte(decodedBinarySecret), &accountAuth)
	}
	// SET env
	os.Setenv("APIM_HOST_ADDR", accountAuth.ApimHostAddr)
	os.Setenv("APIM_USER_NAME", accountAuth.ApimUserName)
	os.Setenv("APIM_USER_PASSWORD", accountAuth.ApimUserPassword)
	os.Setenv("APIM_USER_AUTH", accountAuth.ApimUserAuth)
	os.Setenv("OMS_HOST_ADDR", accountAuth.OmsHostAddr)
	os.Setenv("OMS_USER_NAME", accountAuth.OmsUserName)
	os.Setenv("OMS_USER_PASSWORD", accountAuth.OmsUserPassword)
	os.Setenv("ESB_HOST_ADDR", accountAuth.EsbHostAddr)
	os.Setenv("ESB_USER_NAME", accountAuth.EsbUserName)
	os.Setenv("ESB_PASSWORD", accountAuth.EsbPassword)
	os.Setenv("EKYC_HOST", accountAuth.EkycHost)
	os.Setenv("EKYC_ACCESS_KEY", accountAuth.EkycAccessKey)
	os.Setenv("EKYC_SECRET", accountAuth.EkycSecret)
	os.Setenv("LDAP_URL_ADDRESS", accountAuth.LdapUrlAddress)
	os.Setenv("KEY_VAULT_APP_PROFILE_SECRET", accountAuth.AppProfileSecret)
	os.Setenv("KEY_VAULT_JWT_TOKEN_CONTENT_KEY", accountAuth.JwtTokenContentKey)

	//out,_ := json.Marshal(&accountAuth)
	//log.Print(fmt.Sprintf("AuthAccount : %s ", out))
	return &accountAuth, nil
}
func GetAccountEmail() (*AccountEmail, error) {
	accountEmail := AccountEmail{}

	secretName := local.Getenv("AWS_SECRET_ACCOUNT_EMAIL_INFO")
	region := local.Getenv("AWS_REGION")
	log.Print(fmt.Sprintf("secretName : %s", secretName))

	conf := aws.Config{
		Region: aws.String(region),
	}
	svc := secretsmanager.New(awssession.New(&conf))
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"),
	}
	result, err := svc.GetSecretValue(input)
	if err != nil {
		return nil, err
	}
	var secretString, decodedBinarySecret string

	if result.SecretString != nil {
		secretString = *result.SecretString
		json.Unmarshal([]byte(secretString), &accountEmail)
	} else {
		decodedBinarySecretBytes := make([]byte, base64.StdEncoding.DecodedLen(len(result.SecretBinary)))
		len, err := base64.StdEncoding.Decode(decodedBinarySecretBytes, result.SecretBinary)
		if err != nil {
			fmt.Println("Base64 Decode Error:", err)
		}
		decodedBinarySecret = string(decodedBinarySecretBytes[:len])
		json.Unmarshal([]byte(decodedBinarySecret), &accountEmail)
	}
	// SET ENV
	os.Setenv("EMAIL_USER_AGENT_APP", accountEmail.EmailUserAgentApp)
	os.Setenv("EMAIL_USERNAME", accountEmail.EmailUsername)
	os.Setenv("EMAIL_PASSWORD_AGENT_APP", accountEmail.EmailPasswordAgentApp)
	os.Setenv("EMAIL_HOST", accountEmail.EmailHost)
	os.Setenv("EMAIL_PORT", accountEmail.EmailPort)
	//out,_ := json.Marshal(&accountEmail)
	//log.Print(fmt.Sprintf("AuthAccount : %s ", out))
	return &accountEmail, nil
}
