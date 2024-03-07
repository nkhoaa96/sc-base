package s3

import (
	"bytes"
	"dev.azure.com/vib-lz-devops/B08-DSC-Project-SmartCollection/_git/smartcollection-base-go.git/storage/local"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"io"
	"io/ioutil"
	logg "log"
	"net/http"
)

func UploadAvatarToS3(fileName, bucket, acl string, files io.Reader) error {
	awsss, err := createAWSSession()
	if err != nil {
		return err
	}
	data, err := ioutil.ReadAll(files)
	if err != nil {
		return err
	}
	_, err = s3.New(awsss).PutObject(&s3.PutObjectInput{
		Bucket:             aws.String(bucket),
		Key:                aws.String(fileName),
		ACL:                aws.String(acl),
		Body:               bytes.NewReader(data),
		ContentLength:      aws.Int64(int64(len(data))),
		ContentType:        aws.String(http.DetectContentType(data)),
		ContentDisposition: aws.String("attachment"),
	})
	if err != nil {
		return err
	}
	return nil
}

func UploadToS3WithByteFile(fileName, bucket string, files []byte) error {
	awsss, err := createAWSSession()
	logg.Print("\nAddFileToS3:", fileName)
	logg.Print("\nbucket:", bucket)

	if err != nil {
		return err
	}
	//data, err := ioutil.ReadAll(files)
	if err != nil {
		return err
	}
	_, err = s3.New(awsss).PutObject(&s3.PutObjectInput{
		Bucket:               aws.String(bucket),
		Key:                  aws.String(fileName),
		ACL:                  aws.String("private"),
		Body:                 bytes.NewReader(files),
		ContentLength:        aws.Int64(int64(len(files))),
		ContentType:          aws.String(http.DetectContentType(files)),
		ContentDisposition:   aws.String("attachment"),
		ServerSideEncryption: aws.String("AES256"),
	})
	if err != nil {
		return err
	}
	return nil
}

func UploadToS3(fileName, bucket string, files io.Reader) error {
	awsss, err := createAWSSession()
	logg.Print("\nAddFileToS3:", fileName)
	logg.Print("\nbucket:", bucket)

	if err != nil {
		return err
	}
	data, err := ioutil.ReadAll(files)
	if err != nil {
		return err
	}
	_, err = s3.New(awsss).PutObject(&s3.PutObjectInput{
		Bucket:               aws.String(bucket),
		Key:                  aws.String(fileName),
		ACL:                  aws.String("private"),
		Body:                 bytes.NewReader(data),
		ContentLength:        aws.Int64(int64(len(data))),
		ContentType:          aws.String(http.DetectContentType(data)),
		ContentDisposition:   aws.String("attachment"),
		ServerSideEncryption: aws.String("AES256"),
	})
	if err != nil {
		return err
	}
	return nil
}
func createAWSSession() (*awssession.Session, error) {
	if local.Getenv("ENVIRONMENT") != "dev" {
		conf := aws.Config{
			Region: aws.String(local.Getenv("AWS_REGION")),
		}
		return awssession.NewSession(&conf)
	}
	key := local.Getenv("aws_access_key_id")
	secret := local.Getenv("aws_secret_access_key")
	token := local.Getenv("aws_session_token")

	conf := aws.Config{
		Region:      aws.String("ap-southeast-1"),
		Credentials: credentials.NewStaticCredentials(key, secret, token),
	}
	return awssession.NewSession(&conf)
}
