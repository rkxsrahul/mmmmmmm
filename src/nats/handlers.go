package nats

import (
	"encoding/json"
	"log"
	"regexp"
	"strings"

	"git.xenonstack.com/akirastack/continuous-security-deployments/config"
)

const (
	true               string = "true"
	false              string = "false"
	ansi               string = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"
	commonErrorMessage string = "SSL certificate not found"
)

var re = regexp.MustCompile(ansi)

//tlsVersions is used to check Insecure SSL/TLS Versions Available of the url
func tlsVersions(url, uuid, method, status string) {
	log.Println(uuid, " tlsVersions")
	header := "Insecure SSL/TLS Versions Available"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	data = strings.ReplaceAll(data, " ", "")

	if strings.Contains(strings.ToLower(data), "notvulnerable") {
		mapd["secure"] = true
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["heading"] = "No Insecure SSL/TLS versions detected"
		mapd["description"] = "TLS version is valid"
	} else if data != "" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "HIGH"
		mapd["heading"] = "Insecure SSL/TLS versions detected"
		mapd["description"] = "The existence of TLS prior to the version on the internet acts as a security risk. The server should disable support for these old protocols."
	} else {
		mapd["secure"] = true
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["heading"] = "No Insecure SSL/TLS versions detected"
		mapd["description"] = "TLS version is valid"

	}

	if status != "" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "HIGH"
		mapd["heading"] = "Insecure SSL/TLS versions detected"
		mapd["description"] = "SSL certificate not found"
	}

	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

//expectCt is used to check Expect-CT of the url
func expectCt(url, uuid, method, status string) {
	log.Println(uuid, " Expect-CT")
	header := "Expect-CT"
	//fetch the data
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	mapd["message"] = data + "testing"
	data = strings.Join(strings.Fields(strings.TrimSpace(data)), " ")
	data = re.ReplaceAllString(data, "")
	if data == "NotImplemented" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "LOW"
		mapd["heading"] = "Expect-CT"
		mapd["description"] = "HTTP Expect-CT header is not implemented"
	} else {
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["secure"] = true
		mapd["heading"] = "Expect-CT"
		mapd["description"] = "HTTP Expect-CT header is not implemented properly"
	}
	if status != "" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "HIGH"
		mapd["heading"] = "Expect-CT"
		mapd["description"] = "HTTP Expect-CT header is not implemented"
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}
	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

//contentSecurityPolicy is used to check the Content Security Policy of the url
func contentSecurityPolicy(url, uuid, method, status string) {
	log.Println(uuid, " contentSecurityPolicy")
	header := "Content Security Policy"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	mapd["message"] = data + "testing"
	data = strings.Join(strings.Fields(strings.TrimSpace(data)), " ")
	data = re.ReplaceAllString(data, "")
	if data == "NotImplemented" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "HIGH"
		mapd["heading"] = "Content Security Policy"
		mapd["description"] = "Content Security Policy (CSP) header is not implemented"
	} else if data == "NotProperlyImplemented" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "Medium"
		mapd["heading"] = "Content Security Policy"
		mapd["description"] = "Content Security Policy (CSP) is unsafey  implemented."
	} else if data == "CSP-present" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["heading"] = "Content Security Policy"
		mapd["description"] = "Content Security Policy (CSP) is  implemented safely."
	} else {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["heading"] = "Content Security Policy"
		mapd["description"] = "Content Security Policy (CSP) is  implemented safely."
	}
	if status != "" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "HIGH"
		mapd["heading"] = "Content Security Policy"
		mapd["description"] = "Content Security Policy (CSP) header is not implemented"
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

//xss is used to check the XSS of the url
func xss(url, uuid, method, status string) {
	log.Println(uuid, " hsts")
	header := "XSS"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	mapd["message"] = data + "testing"
	data = strings.Join(strings.Fields(strings.TrimSpace(data)), " ")
	data = re.ReplaceAllString(data, "")
	header = "XSS-Protection"
	if data == "NotImplemented" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "Medium"
		mapd["heading"] = header
		mapd["description"] = "X-XSS-Protection header not implemented"
	} else {
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["secure"] = true
		mapd["heading"] = header
		mapd["description"] = "X-XSS-Protection header is  implemented"
	}
	if status != "" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "Medium"
		mapd["heading"] = header
		mapd["description"] = "X-XSS-Protection header not implemented"
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

//xContentTypeOption is used to check X-Content-type Options of the url
func xContentTypeOption(url, uuid, method, status string) {
	log.Println(uuid, " hsts")
	header := "X-Content-type Options"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	mapd["message"] = data + "testing"
	data = strings.Join(strings.Fields(strings.TrimSpace(data)), " ")
	data = re.ReplaceAllString(data, "")
	header = "X-Content-Type-Options"
	if data == "NotImplemented" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "LOW"
		mapd["heading"] = header
		mapd["description"] = "X-Content-Type-Options header not implemented"
	} else {
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["secure"] = true
		mapd["heading"] = header
		mapd["description"] = "X-Content-Type-Options header is implemented"
	}
	if status != "" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "LOW"
		mapd["heading"] = header
		mapd["description"] = "X-Content-Type-Options header not implemented"
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

//xFrameOption is used to check the xframe option of the url
func xFrameOption(url, uuid, method, status string) {
	log.Println(uuid, " hsts")
	header := "X-Frame Options"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	mapd["message"] = data + "testing"
	data = strings.Join(strings.Fields(strings.TrimSpace(data)), " ")
	data = re.ReplaceAllString(data, "")
	header = "X-Frame-Options"
	if data == "NotImplemented" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "HIGH"
		mapd["heading"] = header
		mapd["description"] = "X-Frame-Options (XFO) header not implemented"
	} else {
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["secure"] = true
		mapd["heading"] = header
		mapd["description"] = "X-Frame-Options (XFO) header is implemented"
	}
	if status != "" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "HIGH"
		mapd["heading"] = header
		mapd["description"] = "X-Frame-Options (XFO) header not implemented"
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

//referrerPolicy is used to check the Referrer Policy of the url
func referrerPolicy(url, uuid, method, status string) {
	log.Println(uuid, " hsts")
	header := "Referrer Policy"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	mapd["message"] = data + "testing"
	data = strings.Join(strings.Fields(strings.TrimSpace(data)), " ")
	data = re.ReplaceAllString(data, "")
	if data == "NotImplemented" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "Low"
		mapd["heading"] = header
		mapd["description"] = "Referrer-Policy HTTP header is not implemented"
	} else {
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["secure"] = true
		mapd["heading"] = header
		mapd["description"] = "Referrer-Policy HTTP header is implemented"
	}
	if status != "" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "Low"
		mapd["heading"] = header
		mapd["description"] = "Referrer-Policy HTTP header is not implemented"
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}
func hsts(url, uuid, method, status string) {
	log.Println(uuid, " hsts")
	header := "Strict Transport Security Enabled"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	data = strings.Join(strings.Fields(strings.TrimSpace(data)), " ")
	data = re.ReplaceAllString(data, "")
	if data == "not" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "HIGH"
		mapd["heading"] = "Strict Transport Security Not Enabled"
		mapd["description"] = "Without HSTS not enforced, creates an opportunity for a man-in-the-middle attack"
	} else {
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["secure"] = true
		mapd["heading"] = "Strict Transport Security is Enabled"
		mapd["description"] = "HSTS is Enforced in this website"
	}
	if status != "" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "HIGH"
		mapd["heading"] = "Strict Transport Security Not Enabled"
		mapd["description"] = "Without HSTS not enforced, creates an opportunity for a man-in-the-middle attack"
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

//serverInformationHeaderExposed 	Server Information Header exposed
func serverInformationHeaderExposed(url, uuid, method string) {
	log.Println(uuid, " serverInformationHeaderExposed")
	header := "Server information header exposed"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	data = strings.Join(strings.Fields(strings.TrimSpace(data)), " ")
	if data != "" {
		if data != "secured" {
			mapd["secure"] = false
			mapd["header"] = header
			mapd["impact"] = "MEDIUM"
			mapd["heading"] = "Server version Header"
			mapd["description"] = "This Disclosed version " + data + " can be used by attackers to gain insightful knowledge about the possible weaknesses and increases the ability of attackers to exploit certain vulnerabilities."
		} else {
			mapd["secure"] = true
			mapd["impact"] = "PASS"
			mapd["heading"] = "Server version Header"
			mapd["description"] = "Server Information is not Exposed"
			mapd["header"] = header
		}
	} else {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "MEDIUM"
		mapd["heading"] = "Server version Header"
		mapd["description"] = "This Disclosed version " + data + " can be used by attackers to gain insightful knowledge about the possible weaknesses and increases the ability of attackers to exploit certain vulnerabilities."
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func missingSecurityHeaders(url, uuid, method string) {
	log.Println(uuid, " missingSecurityHeaders")
	header := "Missing Security Headers"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	if data != "" {
		data = strings.Join(strings.Fields(strings.TrimSpace(data)), " ")
		if data != "" {
			dataArr := strings.Split(data, "\n")
			for i := 0; i < len(dataArr); i++ {
				dataArr[i] = re.ReplaceAllString(dataArr[i], "")
				dataArr[i] = strings.Join(strings.Fields(strings.TrimSpace(dataArr[i])), " ")
			}
			mapd["secure"] = false
			mapd["header"] = header
			mapd["impact"] = "MEDIUM"
			mapd["heading"] = "Missing Security Headers"
			mapd["description"] = "Missing Security Headers Detected: " + strings.ReplaceAll(strings.Join(dataArr, ", "), " ", ", ")
		} else {
			mapd["secure"] = true
			mapd["header"] = header
			mapd["impact"] = "PASS"
			mapd["heading"] = "Missing Security Headers"
			mapd["description"] = "No Missing Security Headers Detected."
		}
	} else {
		mapd["secure"] = true
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["heading"] = "Missing Security Headers"
		mapd["description"] = " No Missing Security Headers Detected."
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func freak(url, uuid, method, status string) {
	log.Println(uuid, " freak")
	header := "Not Vulnerable to FREAK "
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug("FREAK"), header)
	if strings.Contains(data, "notvulnerable") {
		data = strings.Join(strings.Fields(strings.TrimSpace(data)), " ")
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["heading"] = "Not Vulnerable to Freak  CVE-2015-0204"
		mapd["description"] = "The target is not PRONE to FREAK attack."
	} else {
		mapd["secure"] = true
		mapd["header"] = header
		mapd["impact"] = "MEDIUM"
		mapd["heading"] = "Vulnerable to Freak  CVE-2015-0204"
		mapd["description"] = "The target is PRONE to FREAK attack"
	}
	if status != "" {
		mapd["secure"] = true
		mapd["header"] = header
		mapd["impact"] = "MEDIUM"
		mapd["heading"] = "Vulnerable to Freak  CVE-2015-0204"
		mapd["description"] = commonErrorMessage
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func crime(url, uuid, method, status string) {
	log.Println(uuid, " crime")
	header := "Not Vulnerable to CRIME "
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug("CRIME"), header)
	if strings.Contains(data, "notvulnerable") {
		data = strings.Join(strings.Fields(strings.TrimSpace(data)), " ")
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["heading"] = "Not Vulnerable to CRIME (CVE-2012-4929)"
		mapd["description"] = "The target is not PRONE to CRIME attack."

	} else {
		mapd["secure"] = true
		mapd["header"] = header
		mapd["impact"] = "LOW"
		mapd["heading"] = "Vulnerable to CRIME (CVE-2012-4929)"
		mapd["description"] = "The target is PRONE to CRIME attack"
	}
	if status != "" {
		mapd["secure"] = true
		mapd["header"] = header
		mapd["impact"] = "LOW"
		mapd["heading"] = "Vulnerable to CRIME (CVE-2012-4929)"
		mapd["description"] = commonErrorMessage
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func breach(url, uuid, method, status string) {
	log.Println(uuid, " breach")
	header := "Not Vulnerable to BREACH "
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug("BREACH"), header)
	if strings.Contains(data, "noHTTPcompression(OK)") {
		data = strings.Join(strings.Fields(strings.TrimSpace(data)), " ")
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["heading"] = "Not Vulnerable to BREACH (CVE-2013-3587)"
		mapd["description"] = "The target is not PRONE to BREACH attack."
	} else {
		mapd["secure"] = true
		mapd["header"] = header
		mapd["impact"] = "MEDIUM"
		mapd["heading"] = "Vulnerable to BREACH (CVE-2013-3587)"
		mapd["description"] = "The target is PRONE to BREACH attack"
	}
	if status != "" {
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "MEDIUM"
		mapd["heading"] = "Vulnerable to BREACH (CVE-2013-3587)"
		mapd["description"] = commonErrorMessage
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func beast(url, uuid, method, status string) {
	log.Println(uuid, " beast")
	header := "Not Vulnerable to BEAST "
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug("BEAST"), header)
	if strings.Contains(data, "notvulnerable") {
		data = strings.Join(strings.Fields(strings.TrimSpace(data)), " ")
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["heading"] = "Not Vulnerable to BEAST (CVE-2011-3389)"
		mapd["description"] = "The target is not PRONE to BEAST attack."
	} else {

		mapd["secure"] = true
		mapd["header"] = "Vulnerable to BEAST"
		mapd["impact"] = "MEDIUM"
		mapd["heading"] = "Vulnerable to BEAST (CVE-2011-3389)"
		mapd["description"] = "The target is PRONE to BEAST attack"

	}
	if status != "" {
		mapd["secure"] = false
		mapd["header"] = "Vulnerable to BEAST"
		mapd["impact"] = "MEDIUM"
		mapd["heading"] = "Vulnerable to BEAST (CVE-2011-3389)"
		mapd["description"] = commonErrorMessage
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func logjam(url, uuid, method, status string) {
	log.Println(uuid, " logjam")
	header := "Not Vulnerable to LOGJAM "
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug("LOGJAM"), header)
	if strings.Contains(data, "notvulnerable") {
		data = strings.Join(strings.Fields(strings.TrimSpace(data)), " ")
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["heading"] = "Not Vulnerable to LOGJAM (CVE-2015-4000)"
		mapd["description"] = "The target is not PRONE to LOGJAM attack."
	} else {
		mapd["secure"] = true
		mapd["header"] = header
		mapd["impact"] = "MEDIUM"
		mapd["heading"] = "Vulnerable to LOGJAM (CVE-2015-4000)"
		mapd["description"] = "The target is PRONE to LOGJAM attack"
	}

	if status != "" {
		mapd["secure"] = true
		mapd["header"] = header
		mapd["impact"] = "MEDIUM"
		mapd["heading"] = "Vulnerable to LOGJAM (CVE-2015-4000)"
		mapd["description"] = commonErrorMessage
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func heartbleed(url, uuid, method, stauts string) {
	log.Println(uuid, " heartbleed")
	header := "Not Vulnerable to HEARTBLEED "
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug("HEARTBLEED"), header)
	if strings.Contains(data, "notvulnerable") {
		data = strings.Join(strings.Fields(strings.TrimSpace(data)), " ")
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["heading"] = "Not Vulnerable to HEARTBLEED (CVE-2014-0160)"
		mapd["description"] = "The target is not PRONE to HEARTBLEED attack."
	} else {
		mapd["secure"] = true
		mapd["header"] = header
		mapd["impact"] = "HIGH"
		mapd["heading"] = "Vulnerable to HEARTBLEED (CVE-2014-0160)"
		mapd["description"] = "The target is PRONE to HEARTBLEED attack"

	}
	if stauts != "" {
		mapd["secure"] = true
		mapd["header"] = header
		mapd["impact"] = "HIGH"
		mapd["heading"] = "Vulnerable to HEARTBLEED (CVE-2014-0160)"
		mapd["description"] = commonErrorMessage
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func poodle(url, uuid, method, status string) {
	log.Println(uuid, " poodle")
	header := "Not Vulnerable to POODLE"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug("POODLE"), header)
	if strings.Contains(data, "notvulnerable") {
		data = strings.Join(strings.Fields(strings.TrimSpace(data)), " ")
		mapd["secure"] = false
		mapd["header"] = header
		mapd["impact"] = "PASS"
		mapd["heading"] = "Not Vulnerable to POODLE (CVE-2014-3566)"
		mapd["description"] = "The target is not PRONE to POODLE attack."
	} else {
		mapd["secure"] = true
		mapd["header"] = header
		mapd["impact"] = "LOW"
		mapd["heading"] = "Vulnerable to POODLE (CVE-2014-3566)"
		mapd["description"] = "The target is PRONE to POODLE attack"
	}

	if status != "" {
		mapd["secure"] = true
		mapd["header"] = header
		mapd["impact"] = "LOW"
		mapd["heading"] = "Vulnerable to POODLE (CVE-2014-3566)"
		mapd["description"] = commonErrorMessage
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func signatureAlgo(url, uuid, method, status string) {
	log.Println(uuid, " signatureAlgo")
	header := "Signature Algorithm Used"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	data = strings.Join(strings.Fields(strings.TrimSpace(data)), " ")
	data = re.ReplaceAllString(data, "")
	mapd["header"] = header
	mapd["secure"] = true
	mapd["description"] = "Signature Algorithm used for this website is " + data
	mapd["impact"] = "INFORMATIONAL"
	mapd["heading"] = header

	if status != "" {
		mapd["description"] = commonErrorMessage
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func chainTrust(url, uuid, method, status string) {
	log.Println(uuid, " chainTrust")
	header := "Chain of Trust Established"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	if data != "" {
		mapd["header"] = "Chain of Trust Not Established"
		mapd["secure"] = false
		mapd["impact"] = "HIGH"
		mapd["heading"] = "Chain of Trust Not Established"
		mapd["description"] = "Chain of trust enables the receiver to verify that the sender and all intermediate certificates are trust-worthy. Therefore, the chain of trust should be enabled for this website. "
	} else {
		mapd["header"] = "Chain of Trust is valid"
		mapd["secure"] = false
		mapd["impact"] = "PASS"
		mapd["heading"] = header
		mapd["description"] = " Chain of trust enables the receiver to verify that the sender and all intermediate certificates are trust-worthy."
	}
	if status != "" {
		mapd["header"] = "Chain of Trust Not Established"
		mapd["secure"] = false
		mapd["impact"] = "HIGH"
		mapd["heading"] = "Chain of Trust Not Established"
		mapd["description"] = commonErrorMessage
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func redirectToHTTPS(url, uuid, method string) {
	log.Println(uuid, " redirectToHTTPS")
	header := "Redirect to HTTPS"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	if data != "" {
		mapd["header"] = header
		mapd["secure"] = true
		mapd["impact"] = "PASS"
		mapd["heading"] = "Redirect to HTTPS"
		mapd["description"] = "All HTTP requests are redirected to HTTPS"
	} else {
		mapd["header"] = header
		mapd["secure"] = false
		mapd["impact"] = "HIGH"
		mapd["heading"] = "Redirect to HTTPS"
		mapd["description"] = "The target is not redirected to HTTPS i.e Site data can be viewed in plain text, Site is unsecure."
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)

}

func potentially(url, uuid, method string) {
	log.Println(uuid, " potentially")
	header := "Potentially risky methods found"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	if data != "" {
		mapd["header"] = header
		mapd["secure"] = true
		mapd["impact"] = "LOW"
		mapd["heading"] = "Risky HTTP method detected."
		mapd["description"] = "The detected method " + data + " can potentially pose a security risk for a web Application."
	} else {
		mapd["header"] = header
		mapd["secure"] = true
		mapd["impact"] = "PASS"
		mapd["heading"] = "No Risky HTTP Method detected"
		mapd["description"] = "The website is not using any risky methods."
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func httpMethodsUsed(url, uuid, method string) {
	log.Println(uuid, " httpMethodsUsed")
	header := "HTTP Methods Used"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	mapd["header"] = header
	mapd["secure"] = true
	mapd["impact"] = "INFORMATIONAL"
	mapd["heading"] = header
	mapd["description"] = "The HTTP methods used are: " + data
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func certificateValid(url, uuid, method, status string) {
	log.Println(uuid, " certificateValid")
	header := "Certificate Validity"
	// run bash command
	scriptOut, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	if strings.Contains(scriptOut, "expires") {
		mapd["header"] = header
		mapd["description"] = "SSL is used to keep sensitive information sent across the Internet. So, a valid SSL certificate is necessary to prevent from attacks."
		mapd["heading"] = "Certificate is Expired"
		mapd["secure"] = true
		mapd["impact"] = "INFORMATIONAL"
	} else if strings.Contains(scriptOut, "expired") {
		mapd["header"] = header
		mapd["description"] = "SSL is used to keep sensitive information sent across the Internet. So, a valid SSL certificate is necessary to prevent from attacks."
		mapd["heading"] = "Certificate is Expired"
		mapd["secure"] = true
		mapd["impact"] = "INFORMATIONAL"
	} else if scriptOut != "" {
		scriptOut = strings.Join(strings.Fields(strings.TrimSpace(scriptOut)), " ")
		scriptOut = re.ReplaceAllString(scriptOut, "")
		mapd["header"] = header
		mapd["description"] = "SSL is used to keep sensitive information sent across the Internet. So, a valid SSL certificate is necessary to prevent from attacks."
		mapd["heading"] = "The certificate will expire in " + scriptOut + " days."
		mapd["secure"] = true
		mapd["impact"] = "INFORMATIONAL"
	} else {
		mapd["heading"] = header
		mapd["header"] = header
		mapd["description"] = "SSL is used to keep sensitive information sent across the Internet. So, a valid SSL certificate is necessary to prevent from attacks."
		mapd["impact"] = "INFORMATIONAL"
		mapd["secure"] = true
	}

	if status != "" {
		mapd["impact"] = "INFORMATIONAL"
		mapd["secure"] = false
		mapd["heading"] = header
		mapd["header"] = header
		mapd["description"] = commonErrorMessage
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func expiryTime(url, uuid, method string) {
	log.Println(uuid, " expiryTime")
	header := "Domain Expiry"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	mapd["header"] = header
	if strings.Contains(data, "domain is expired") {
		mapd["heading"] = " Domain Validity"
		mapd["secure"] = false
		mapd["impact"] = "INFORMATIONAL"
		mapd["description"] = "Your Domain is Expired"
	} else {
		mapd["heading"] = "Domain Validity"
		mapd["secure"] = false
		mapd["impact"] = "INFORMATIONAL"
		mapd["description"] = data + " for your domain to Expire"
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func openPorts(url, uuid, method string) {
	log.Println(uuid, " openPorts")
	header := "Found Open Ports"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	if data != "" {
		data = strings.TrimSpace(data)
		if data == "" {
			mapd["secure"] = true
			mapd["header"] = "No Open Ports Found"
			mapd["description"] = "No un-necessary open ports found"
			mapd["heading"] = "No Open Ports Found"
			mapd["impact"] = "PASS"
		} else {
			mapd["secure"] = false
			mapd["header"] = header
			mapd["heading"] = "Open Ports Detected"
			mapd["impact"] = "HIGH"
			mapd["description"] = "Open ports detected may reveal information about the system or network architecture. Therefore. ensure that servers have the minimum number of exposed services."

		}
	} else {
		mapd["secure"] = true
		mapd["header"] = "No Open Ports Found"
		mapd["description"] = "No un-necessary open ports found"
		mapd["heading"] = "No Open Ports Found"
		mapd["impact"] = "PASS"
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func dNSSECEnabled(url, uuid, method string) {
	log.Println(uuid, " dNSSECEnabled")
	header := "DNSSEC Enabled"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	if data != "" {
		if strings.Contains(data, "unsigned") && data != "" {
			mapd["secure"] = "false"
			mapd["header"] = "DNSSEC Not Enabled"
			mapd["heading"] = "DNSSEC Not Enabled"
			mapd["impact"] = "LOW"
			mapd["description"] = "DNSSEC is to authenticate DNS responses with the major goal of preventing spoofing. Therefore, DNSSEC should be configured"
		} else {
			mapd["secure"] = "true"
			mapd["header"] = header
			mapd["heading"] = "DNSSEC Enabled"
			mapd["impact"] = "PASS"
			mapd["description"] = "DNSSEC is enabled for this website."
		}
	} else {
		mapd["secure"] = "true"
		mapd["header"] = header
		mapd["heading"] = "DNSSEC Enabled"
		mapd["impact"] = "PASS"
		mapd["description"] = "DNSSEC is enabled for this website."
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func dMARCPolicy(url, uuid, method string) {
	log.Println(uuid, " dMARCPolicy")
	header := "DMARC policy exist"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)

	log.Println("---------------->>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
	log.Println(data)
	log.Println("---------------->>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")

	if data != "" {
		mapd["secure"] = "true"
		mapd["header"] = "DMARC policy exists"
		mapd["heading"] = "DMARC policy exists"
		mapd["impact"] = "PASS"
		mapd["description"] = "DMARC protects against spam emails being sent from a domain"
	} else {
		mapd["secure"] = "false"
		mapd["header"] = "DMARC policy exists"
		mapd["heading"] = "DMARC policy does not exists"
		mapd["impact"] = "HIGH"
		mapd["description"] = "DMARC protects against spam emails being sent from a domain"

	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func dMARCPercentage(url, uuid, method string) {
	log.Println(uuid, " dMARCPercentage")
	header := "DMARC policy percentage"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	if strings.Contains(data, "less") {
		mapd["secure"] = "false"
		mapd["header"] = header
		mapd["heading"] = "DMARC policy percentage is less than 100%"
		mapd["impact"] = "MEDIUM"
		mapd["description"] = "DMARC Policy less than 100% may allow fraudulent emails to be delivered"
	} else {
		mapd["secure"] = "true"
		mapd["header"] = header
		mapd["heading"] = "DMARC policy percentage is 100%"
		mapd["impact"] = "PASS"
		mapd["description"] = "DMARC Policy less than 100% may allow fraudulent emails to be delivered."
	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}

func dMARCReject(url, uuid, method string) {
	log.Println(uuid, " dMARCReject")
	header := "DMARC policy Reject"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	if strings.Contains(data, "p=reject") {
		mapd["secure"] = "true"
		mapd["header"] = header
		mapd["heading"] = "DMARC policy is p=reject"
		mapd["impact"] = "PASS"
		mapd["description"] = "Reject policy of DMARC provides the most effective protection against spam emails being sent from a domain."
	} else {
		mapd["secure"] = "false"
		mapd["header"] = header
		mapd["heading"] = "DMARC policy is not p=reject"
		mapd["impact"] = "MEDIUM"
		mapd["description"] = "Reject policy of DMARC provides the most effective protection against spam emails being sent from a domain."

	}
	reqBody := RequestData{
		Data:   mapd,
		UUID:   uuid,
		Method: method,
		Header: header,
	}

	body, _ := json.Marshal(reqBody)
	Publish(body, uuid)
}
