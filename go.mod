module dev.azure.com/vib-lz-devops/B08-DSC-Project-SmartCollection/_git/smartcollection-base-go.git

go 1.16

require (
	github.com/aws/aws-lambda-go v1.23.0
	github.com/aws/aws-sdk-go v1.38.28
	github.com/casbin/casbin/v2 v2.28.4
	github.com/go-asn1-ber/asn1-ber v1.5.3
	github.com/go-logfmt/logfmt v0.5.0
	github.com/go-stack/stack v1.8.0
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/golang/protobuf v1.5.2
	github.com/gomodule/redigo v1.8.4
	github.com/google/uuid v1.2.0
	github.com/gorilla/mux v1.8.1
	github.com/joho/godotenv v1.3.0
	github.com/nats-io/nats-server/v2 v2.2.2
	github.com/nats-io/nats.go v1.10.1-0.20210419223411-20527524c393
	github.com/sirupsen/logrus v1.8.1
	github.com/streadway/amqp v1.0.0
	github.com/stretchr/testify v1.8.1
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.14.0
	golang.org/x/text v0.13.0
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/grpc v1.37.0
	google.golang.org/protobuf v1.26.0
	gopkg.in/yaml.v2 v2.3.0 // indirect
	gorm.io/driver/postgres v1.5.4
	gorm.io/gorm v1.25.5
)

replace (
	github.com/apache/thrift => github.com/apache/thrift v0.14.0
	github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.2
	github.com/gorilla/websocket => github.com/gorilla/websocket v1.4.1
	go.etcd.io/etcd => go.etcd.io/etcd v0.5.0-alpha.5.0.20200423152442-f4b650b51dc4
)
