package config

import (
	"log"
	"os"

	"github.com/nats-io/nats.go"
)

// Config is a structure for configuration
type Config struct {
	Service    Service
	NatsServer NatsServer
}

//NatsServer : for nats connection parameters
type NatsServer struct {
	URL      string
	Token    string
	Username string
	Password string
	Subject  string
	Queue    string
}

// Service is a structure for service specific related configuration
type Service struct {
	Port           string
	Environment    string
	Build          string
	RepoURL        string
	RepoPrivateKey string
}

var (
	// Conf is a global variable for configuration
	Conf Config
	// TomlFile is a global variable for toml file path
	TomlFile string

	//NC for nats connection
	NC *nats.Conn
)

const (
	PersistStoragePath string = "./scripts/websiteScan/"
	MailService        string = "false"
)

// ConfigurationWithEnv is a method to initialize configuration with environment variables
func ConfigurationWithEnv() {

	//Service Configuration
	Conf.Service.Environment = os.Getenv("ENVIRONMENT")
	Conf.Service.Build = os.Getenv("BUILD_IMAGE")
	Conf.Service.RepoURL = os.Getenv("REPO_URL_OF_SCRIPT")
	Conf.Service.RepoPrivateKey = os.Getenv("PRIVATE_KEY_OF_REPO")

	Conf.NatsServer.Subject = os.Getenv("SCRIPT_NAME")

	//nats server
	Conf.NatsServer.URL = os.Getenv("NATS_URL")
	Conf.NatsServer.Token = os.Getenv("NATS_TOKEN")
	Conf.NatsServer.Username = os.Getenv("NATS_USERNAME")
	Conf.NatsServer.Password = os.Getenv("NATS_PASSWORD")
	log.Println(Conf)

}
