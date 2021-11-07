package nats

import (
	"log"
	"os"
	"sync"

	"github.com/nats-io/nats.go"

	"git.xenonstack.com/akirastack/continuous-security-deployments/config"
)

//printMsg : To print when a msg is recieved
func printMsg(m *nats.Msg, i int) {
	log.Printf("[#%d] Received on [%s] Pid[%d]: '%s'", i, m.Subject, os.Getpid(), string(m.Data))
}

//Subscribe : This function is used to initiate subscriber
func Subscribe() {
	var wg sync.WaitGroup
	nc := config.NC
	i := 0
	subject := config.Conf.NatsServer.Subject
	// subject := config.Conf.NatsServer.Subject + ".*"
	log.Println(subject)
	wg.Add(1)
	log.Println("Subscribe starting")
	// Subscribe
	if _, err := nc.Subscribe(subject, func(msg *nats.Msg) {
		i++
		printMsg(msg, i)
		go request(msg)
		// wg.Done()
	}); err != nil {
		log.Fatal(err)
	}

	// Wait for a message to come in
	wg.Wait()
}

func request(msg *nats.Msg) {
	// if strings.Contains(msg.Subject, "tlsVersions") {
	// 	sub := strings.TrimPrefix(msg.Subject, "tlsVersions.")
	// 	if sub == "tlsVersions" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		log.Println(data)
	// 		tlsVersions(data.URL, data.UUID, data.Method, data.Status)
	// 	}
	// } else if strings.Contains(msg.Subject, "beast") {
	// 	sub := strings.TrimPrefix(msg.Subject, "beast.")
	// 	if sub == "beast" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		beast(data.URL, data.UUID, data.Method, data.Status)
	// 	}
	// } else if strings.Contains(msg.Subject, "breach") {
	// 	sub := strings.TrimPrefix(msg.Subject, "breach.")
	// 	if sub == "breach" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		breach(data.URL, data.UUID, data.Method, data.Status)
	// 	}
	// } else if strings.Contains(msg.Subject, "crime") {
	// 	sub := strings.TrimPrefix(msg.Subject, "crime.")
	// 	if sub == "crime" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		crime(data.URL, data.UUID, data.Method, data.Status)
	// 	}
	// } else if strings.Contains(msg.Subject, "freak") {
	// 	sub := strings.TrimPrefix(msg.Subject, "freak.")
	// 	if sub == "freak" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		freak(data.URL, data.UUID, data.Method, data.Status)
	// 	}
	// } else if strings.Contains(msg.Subject, "heartbleed") {
	// 	sub := strings.TrimPrefix(msg.Subject, "heartbleed.")
	// 	if sub == "heartbleed" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		heartbleed(data.URL, data.UUID, data.Method, data.Status)
	// 	}
	// } else if strings.Contains(msg.Subject, "logjam") {
	// 	sub := strings.TrimPrefix(msg.Subject, "logjam.")
	// 	if sub == "logjam" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		logjam(data.URL, data.UUID, data.Method, data.Status)
	// 	}
	// } else if strings.Contains(msg.Subject, "poodle") {
	// 	sub := strings.TrimPrefix(msg.Subject, "poodle.")
	// 	if sub == "poodle" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		poodle(data.URL, data.UUID, data.Method, data.Status)
	// 	}
	// } else if strings.Contains(msg.Subject, "signaturealgo") {
	// 	sub := strings.TrimPrefix(msg.Subject, "signaturealgo.")
	// 	if sub == "certificateValid" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		certificateValid(data.URL, data.UUID, data.Method, data.Status)
	// 	} else if sub == "httpMethodsUsed" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		httpMethodsUsed(data.URL, data.UUID, data.Method)
	// 	}
	// } else if strings.Contains(msg.Subject, "hsts") {
	// 	sub := strings.TrimPrefix(msg.Subject, "hsts.")
	// 	if sub == "hsts" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		hsts(data.URL, data.UUID, data.Method, data.Status)
	// 	} else if sub == "potentially" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		potentially(data.URL, data.UUID, data.Method)
	// 	}
	// } else if strings.Contains(msg.Subject, "serverInformationHeaderExposed") {
	// 	sub := strings.TrimPrefix(msg.Subject, "serverInformationHeaderExposed.")
	// 	if sub == "serverInformationHeaderExposed" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		serverInformationHeaderExposed(data.URL, data.UUID, data.Method)
	// 	} else if sub == "redirectToHTTPS" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		redirectToHTTPS(data.URL, data.UUID, data.Method)
	// 	} else if sub == "expiryTime" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		expiryTime(data.URL, data.UUID, data.Method)
	// 	}
	// } else if strings.Contains(msg.Subject, "missingSecurityHeaders") {
	// 	sub := strings.TrimPrefix(msg.Subject, "missingSecurityHeaders.")
	// 	if sub == "missingSecurityHeaders" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		missingSecurityHeaders(data.URL, data.UUID, data.Method)
	// 	} else if sub == "dMARCPolicy" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		dMARCPolicy(data.URL, data.UUID, data.Method)
	// 	} else if sub == "dNSSECEnabled" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		dNSSECEnabled(data.URL, data.UUID, data.Method)
	// 	} else if sub == "dMARCPercentage" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		dMARCPercentage(data.URL, data.UUID, data.Method)
	// 	} else if sub == "dMARCReject" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		dMARCReject(data.URL, data.UUID, data.Method)
	// 	} else if sub == "openPorts" {
	// 		data := convertDatatoJSON(msg.Data)
	// 		openPorts(data.URL, data.UUID, data.Method)
	// 	}
	// }
	// return
	switch msg.Subject {
	case "tlsVersions":
		data := convertDatatoJSON(msg.Data)
		log.Println(data)
		tlsVersions(data.URL, data.UUID, data.Method, data.Status)
	case "hsts":
		data := convertDatatoJSON(msg.Data)
		hsts(data.URL, data.UUID, data.Method, data.Status)
	case "serverInformationHeaderExposed":
		data := convertDatatoJSON(msg.Data)
		serverInformationHeaderExposed(data.URL, data.UUID, data.Method)
	case "missingSecurityHeaders":
		data := convertDatatoJSON(msg.Data)
		missingSecurityHeaders(data.URL, data.UUID, data.Method)
	case "freak":
		data := convertDatatoJSON(msg.Data)
		freak(data.URL, data.UUID, data.Method, data.Status)
	case "crime":
		data := convertDatatoJSON(msg.Data)
		crime(data.URL, data.UUID, data.Method, data.Status)
	case "breach":
		data := convertDatatoJSON(msg.Data)
		breach(data.URL, data.UUID, data.Method, data.Status)
	case "beast":
		data := convertDatatoJSON(msg.Data)
		beast(data.URL, data.UUID, data.Method, data.Status)
	case "logjam":
		data := convertDatatoJSON(msg.Data)
		logjam(data.URL, data.UUID, data.Method, data.Status)
	case "heartbleed":
		data := convertDatatoJSON(msg.Data)
		heartbleed(data.URL, data.UUID, data.Method, data.Status)
	case "poodle":
		data := convertDatatoJSON(msg.Data)
		poodle(data.URL, data.UUID, data.Method, data.Status)
	case "signatureAlgo":
		data := convertDatatoJSON(msg.Data)
		signatureAlgo(data.URL, data.UUID, data.Method, data.Status)
	case "chainTrust":
		data := convertDatatoJSON(msg.Data)
		chainTrust(data.URL, data.UUID, data.Method, data.Status)
	case "redirectToHTTPS":
		data := convertDatatoJSON(msg.Data)
		redirectToHTTPS(data.URL, data.UUID, data.Method)
	case "potentially":
		data := convertDatatoJSON(msg.Data)
		potentially(data.URL, data.UUID, data.Method)
	case "httpMethodsUsed":
		data := convertDatatoJSON(msg.Data)
		httpMethodsUsed(data.URL, data.UUID, data.Method)
	case "certificateValid":
		data := convertDatatoJSON(msg.Data)
		certificateValid(data.URL, data.UUID, data.Method, data.Status)
	case "expiryTime":
		data := convertDatatoJSON(msg.Data)
		expiryTime(data.URL, data.UUID, data.Method)
	case "openPorts":
		data := convertDatatoJSON(msg.Data)
		openPorts(data.URL, data.UUID, data.Method)
	case "dNSSECEnabled":
		data := convertDatatoJSON(msg.Data)
		dNSSECEnabled(data.URL, data.UUID, data.Method)
	case "dMARCPolicy":
		data := convertDatatoJSON(msg.Data)
		dMARCPolicy(data.URL, data.UUID, data.Method)
	case "dMARCPercentage":
		data := convertDatatoJSON(msg.Data)
		dMARCPercentage(data.URL, data.UUID, data.Method)
	case "dMARCReject":
		data := convertDatatoJSON(msg.Data)
		dMARCReject(data.URL, data.UUID, data.Method)
	case "expectCt":
		data := convertDatatoJSON(msg.Data)
		expectCt(data.URL, data.UUID, data.Method, data.Status)
	case "contentSecurityPolicy":
		data := convertDatatoJSON(msg.Data)
		contentSecurityPolicy(data.URL, data.UUID, data.Method, data.Status)
	case "xss":
		data := convertDatatoJSON(msg.Data)
		xss(data.URL, data.UUID, data.Method, data.Status)
	case "xContentTypeOption":
		data := convertDatatoJSON(msg.Data)
		xContentTypeOption(data.URL, data.UUID, data.Method, data.Status)
	case "referrerPolicy":
		data := convertDatatoJSON(msg.Data)
		referrerPolicy(data.URL, data.UUID, data.Method, data.Status)
	case "xFrameOption":
		data := convertDatatoJSON(msg.Data)
		xFrameOption(data.URL, data.UUID, data.Method, data.Status)
	case "nodeScan":
		data := convertDatatoJSON(msg.Data)
		nodeScan(data.URL, data.UUID, data.Branch, data.Method)
	case "X":
		data := convertDatatoJSON(msg.Data)
		log.Println(data)
	}

}
