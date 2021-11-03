package main

import (
	"log"

	"git.xenonstack.com/akirastack/continuous-security-deployments/config"
	"git.xenonstack.com/akirastack/continuous-security-deployments/src/nats"
)

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	config.ConfigurationWithEnv()
	//load scripts
	//	script.DownloadScripts()
	// nats connection
	nats.InitConnection()
	nats.Subscribe()
}
