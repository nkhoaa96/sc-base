package dynamodb

import (
	"dev.azure.com/vib-lz-devops/B08-DSC-Project-SmartCollection/_git/smartcollection-base-go.git/storage/local"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
)

func Connection() (*dynamodbiface.DynamoDBAPI, error) {
	region := local.Getenv("AWS_REGION")
	awsSession, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		return nil, err
	}
	var dynaClient dynamodbiface.DynamoDBAPI
	dynaClient = dynamodb.New(awsSession)
	return &dynaClient, nil
}
