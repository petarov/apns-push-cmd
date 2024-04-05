package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"regexp"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/net/http2"
)

// APPNAME App Name
const APPNAME = "apns-push-cmd"

// VERSION Version
const VERSION = "1.2"

var (
	// ApnsSandboxHost Development push notifications
	ApnsSandboxHost = "api.sandbox.push.apple.com"
	// ApnsProductionHost Production push notifications
	ApnsProductionHost = "api.push.apple.com"
	// AAA Certificate Services Root (2028)
	RootGeoTrustGlobal = `-----BEGIN CERTIFICATE-----
MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEb
MBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRow
GAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmlj
YXRlIFNlcnZpY2VzMB4XDTA0MDEwMTAwMDAwMFoXDTI4MTIzMTIzNTk1OVowezEL
MAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
BwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMM
GEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAL5AnfRu4ep2hxxNRUSOvkbIgwadwSr+GB+O5AL686tdUIoWMQua
BtDFcCLNSS1UY8y2bmhGC1Pqy0wkwLxyTurxFa70VJoSCsN6sjNg4tqJVfMiWPPe
3M/vg4aijJRPn2jymJBGhCfHdr/jzDUsi14HZGWCwEiwqJH5YZ92IFCokcdmtet4
YgNW8IoaE+oxox6gmf049vYnMlhvB/VruPsUK6+3qszWY19zjNoFmag4qMsXeDZR
rOme9Hg6jc8P2ULimAyrL58OAd7vn5lJ8S3frHRNG5i1R8XlKdH5kBjHYpy+g8cm
ez6KJcfA3Z3mNWgQIJ2P2N7Sw4ScDV7oL8kCAwEAAaOBwDCBvTAdBgNVHQ4EFgQU
oBEKIz6W8Qfs4q8p74Klf9AwpLQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF
MAMBAf8wewYDVR0fBHQwcjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20v
QUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNqA0oDKGMGh0dHA6Ly9jcmwuY29t
b2RvLm5ldC9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDANBgkqhkiG9w0BAQUF
AAOCAQEACFb8AvCb6P+k+tZ7xkSAzk/ExfYAWMymtrwUSWgEdujm7l3sAg9g1o1Q
GE8mTgHj5rCl7r+8dFRBv/38ErjHT1r0iWAFf2C3BUrz9vHCv8S5dIa2LX1rzNLz
Rt0vxuBqw8M0Ayx9lt1awg6nCpnBBYurDC/zXDrPbDdVCYfeU0BsWO/8tqtlbgT2
G9w84FoVxp7Z8VlIMCFlA2zs6SFz7JsDoeA3raAVGI/6ugLOpyypEBMs1OUIJqsi
l2D4kF501KKaU73yqWjgom7C12yxow+ev+to51byrvLjKzg6CYG1a4XXvi3tPxq3
smPi9WIsgtRqAEFQ8TmDn5XpNpaYbg==
-----END CERTIFICATE-----
	`
	// Apple Public Server RSA CA 12 - G1
	RootAppleISTCA2G1 = `-----BEGIN CERTIFICATE-----
MIIEkDCCA3igAwIBAgIQCuSPIwEwZEGSWeHCmumNGDANBgkqhkiG9w0BAQsFADB7
MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
VQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UE
AwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTE5MDYxOTAwMDAwMFoXDTI4
MTIwNjIzNTk1OVowZDErMCkGA1UEAxMiQXBwbGUgUHVibGljIFNlcnZlciBSU0Eg
Q0EgMTIgLSBHMTETMBEGA1UEChMKQXBwbGUgSW5jLjETMBEGA1UECBMKQ2FsaWZv
cm5pYTELMAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQC9vhI3XrifeRWYC+x6U5sPCaYAPncBLBBsyQdt7ztiyROEG6fEKZG1tToZMES3
jtgqV+7RcBV9xX2jVeU+EwAnHkIpwoDWcte0gLfALL3hkVcwXJoJaojVF8mMHlJt
QYTr3FYkZ6FqALt/LFUxeis3/Zgtug7EoqBsZeF5g79lSZtZqcNLm+3NuvZUdAHB
GIzD++wVlOhy9IxahD/Z7eIkpuJTedYVpLmnX/fHq92gYoNHezlNN8vdILlsPV4k
IdrwTKso7II25Kha0/l3hx2xEBtUIQLMGxKF+fD9AjcYhSMqhTM5/2tyud4QJxIy
409Dj4OhNooHAxurBDHwV8ZlAgMBAAGjggElMIIBITAfBgNVHSMEGDAWgBSgEQoj
PpbxB+zirynvgqV/0DCktDAdBgNVHQ4EFgQUHlwXkQVXAvx3XONwQ+xr/d3S2Gkw
DgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAh
BgNVHSAEGjAYMAwGCiqGSIb3Y2QFCwQwCAYGZ4EMAQICMBIGA1UdEwEB/wQIMAYB
Af8CAQAwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20v
QUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEEKDAmMCQGCCsG
AQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZIhvcNAQELBQAD
ggEBAGa7XPTd+1lgnT/dDf2agLAIIXpbTn6XtEGMq9jovXbK076zHlQSWapd6Zd/
p/uWydwuTbd+cobkUTFZhKGMkY0e8gXgI2s09kQ0EfotFUOdQ7qf1U+UM7JIEZmD
gsTn9vBLNwbtwH9t6cvYxH//VhWyL07pPkfTFBVqvAprGZ9MgraZD2S9qYu9usfS
vuH4lr4b3NuZ7mh3zOs4aD3Omgx30DU8DV82LikGN4/MF+uDOGgHtPv0ozlvPrFc
8bsE+lTnjP199w5X+kPtpzrkjYPNrGxTg4nhugo6y+GPOCl00S+T/794oTq/HFlj
6IoOvOR7UaKo39qnYwA6Fs0F0to=
-----END CERTIFICATE-----`
)

var (
	// KeystorePath The path to a APNs PKCS#12 certificate container (.p12, .pfx)
	KeystorePath string
	// KeystorePassword The password to open the certificate file container
	KeystorePassword string
	// ClientCertPath The path to APNs client ceritificate file (.pem, .der)
	ClientCertPath string
	// ClientKeyPath The path to APNs client cerificate key (.pem, .der)
	ClientKeyPath string
	// AuthTokenPath The path to the authentication token signing key (.p8)
	AuthTokenPath string
	// KeyID The 10-character string with the Key ID
	KeyID string
	// TeamID The 10-character Team ID from your developer account
	TeamID string
	// IsExplicitTrust Explicitly trust Geo Trust CA and Apple IST CA 2 root certificates
	IsExplicitTrust bool
	// DeviceToken Hexadecimal or Base64 encoded push token for the device
	DeviceToken string
	// PushTopic The topic the device subscribes to
	PushTopic string
	// The value of the apns-push-type. Default to 'alert'
	PushType string
	// MdmPushMagic The magic string that has to be included in the push notification message.
	MdmPushMagic string
	// IsSandbox Sends push notification to APNs sandbox at api.sandbox.push.apple.com
	IsSandbox bool
	// PushAlertMessage Alert text to display for app push notifications
	PushAlertMessage string
	// PushAlertJSON raw JSON for app notification
	PushAlertJSON string
	// PushAlertFileName filename to read for JSON (will overwrite PushAlertJSON)
	PushAlertFileName string
	// IsPort2197 Use port 2197 (instead of port 443) when communicating with APNs
	IsPort2197 bool
)

// Required Mandatory parameters
var Required = []string{"token", "topic"}

func init() {
	flag.StringVar(&KeystorePath, "cert-p12", "", "The path to a APNs PKCS#12 certificate container (.p12, .pfx)")
	flag.StringVar(&KeystorePassword, "cert-pass", "", "The password to open the certificate file container")
	flag.StringVar(&ClientCertPath, "cert-file", "", "The path to APNs client ceritificate file, if -cert-p12 has not been specified (.pem, .der)")
	flag.StringVar(&ClientKeyPath, "cert-key", "", "The path to APNs client cerificate key (.pem, .der)")
	flag.StringVar(&AuthTokenPath, "auth-token", "", "The path to the authentication token signing key (.p8)")
	flag.StringVar(&KeyID, "key-id", "", "The 10-character string with the Key ID")
	flag.StringVar(&TeamID, "team-id", "", "The 10-character Team ID from your developer account")
	flag.BoolVar(&IsExplicitTrust, "x-trust", false, "Explicitly trust Apple root certificates (Usually you should not need to do this)")
	flag.StringVar(&DeviceToken, "token", "", "Required. Hexadecimal or Base64 encoded push token for the device")
	flag.StringVar(&PushTopic, "topic", "", "Required. The topic the device subscribes to")
	flag.StringVar(&PushType, "type", "", "The value of the apns-push-type. Possible vaules are: 'alert', 'background', 'location', 'voip', 'complication', 'fileprovider', 'mdm', 'liveactivity'.  Default is 'alert'")
	flag.StringVar(&MdmPushMagic, "mdm-magic", "", "The magic string that has to be included in the push notification message")
	flag.StringVar(&PushAlertMessage, "alert-text", "Hello from app-push-cmd!", "Alert text to display for app push notifications")
	flag.StringVar(&PushAlertJSON, "alert-json", "", "If this is set, this raw JSON will be sent instead of alert-text")
	flag.StringVar(&PushAlertFileName, "alert-filename", "", "If this is set the content of this file will be sent instead of alert-text/alert-json")
	flag.BoolVar(&IsSandbox, "sandbox", false, "Sends push notification to APNs sandbox at api.sandbox.push.apple.com")
	flag.BoolVar(&IsPort2197, "port2197", false, "Use port 2197 (instead of port 443) when communicating with APNs")
}

func getCertPool() (caCertPool *x509.CertPool, err error) {
	caCertPool = x509.NewCertPool()

	// for i := 0; i < len(CaCertFiles); i++ {
	// caCert, err := ioutil.ReadFile(fmt.Sprintf("certs/%s", CaCertFiles[i]))
	// if err != nil {
	// 	return nil, err
	// }
	ok := caCertPool.AppendCertsFromPEM([]byte(RootGeoTrustGlobal))
	if !ok {
		return nil, fmt.Errorf("Error loading RootGeoTrustGlobal")
	}
	ok = caCertPool.AppendCertsFromPEM([]byte(RootAppleISTCA2G1))
	if !ok {
		return nil, fmt.Errorf("Error loading RootAppleISTCA2G1")
	}
	// }

	return caCertPool, nil
}

func getClientCert() (_ *tls.Certificate, err error) {
	if len(KeystorePath) > 0 {
		keystoreBytes, err := ioutil.ReadFile(KeystorePath)
		if err != nil {
			log.Printf("Error reading keystore (%s)!", KeystorePath)
			return nil, err
		}

		blocks, err := pkcs12.ToPEM(keystoreBytes, KeystorePassword)
		if err != nil {
			log.Printf("Error keystore (%s) ToPEM!", KeystorePath)
			return nil, err
		}

		var pemData []byte
		for _, b := range blocks {
			pemData = append(pemData, pem.EncodeToMemory(b)...)
		}

		cert, err := tls.X509KeyPair(pemData, pemData)
		if err != nil {
			log.Printf("Error creating X509KeyPair from keystore blocks!")
			return nil, err
		}
		return &cert, nil
	}

	cert, err := tls.LoadX509KeyPair(*&ClientCertPath, *&ClientKeyPath)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

func getClientBearerToken() (auth string, err error) {
	tokenBytes, err := ioutil.ReadFile(AuthTokenPath)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(tokenBytes)
	if block == nil {
		return "", errors.New("Auth token does not seem to be a valid .p8 key file")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	jwtToken := &jwt.Token{
		Header: map[string]interface{}{
			"alg": "ES256",
			"kid": KeyID,
		},
		Claims: jwt.MapClaims{
			"iss": TeamID,
			"iat": time.Now().Unix(),
		},
		Method: jwt.SigningMethodES256,
	}

	bearer, err := jwtToken.SignedString(key)
	if err != nil {
		return "", err
	}

	return bearer, nil
}

func getClient(cert *tls.Certificate) (client *http.Client, err error) {
	var tlsConfig *tls.Config

	if IsExplicitTrust {
		caCertPool, err := getCertPool()
		if err != nil {
			log.Printf("Error loading/adding root CAs!")
			return nil, err
		}
		if cert != nil {
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{*cert},
				RootCAs:      caCertPool,
			}
		} else {
			tlsConfig = &tls.Config{RootCAs: caCertPool}
		}
	} else if cert != nil {
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{*cert}}
	} else {
		tlsConfig = &tls.Config{}
	}

	client = &http.Client{Timeout: 20 * time.Second}
	client.Transport = &http2.Transport{TLSClientConfig: tlsConfig}

	return client, nil
}

func normalizeDeviceToken(tokenParam string) (result string, err error) {
	rxHex := regexp.MustCompile("^[0-9a-fA-F]+$")
	if rxHex.MatchString(tokenParam) {
		return tokenParam, nil
	}

	dec, err := base64.StdEncoding.DecodeString(tokenParam)
	if err != nil {
		return tokenParam, nil
	}
	return hex.EncodeToString(dec), nil
}

func main() {
	fmt.Printf("%s v%s - Apple Push Notification service Command Line Push\n", APPNAME, VERSION)
	flag.Parse()

	passed := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		passed[f.Name] = true
	})
	for _, r := range Required {
		if !passed[r] {
			flag.PrintDefaults()
			log.Fatalf("Missing required argument: %s", r)
		}
	}

	bearerToken := func() string {
		if len(AuthTokenPath) > 0 {
			bt, err := getClientBearerToken()
			if err != nil {
				log.Fatalf("Error load/init auth token: %s", err)
			}
			return bt
		}
		return ""
	}()

	client := func() *http.Client {
		client, err := getClient(
			func() *tls.Certificate {
				if len(AuthTokenPath) == 0 {
					cert, err := getClientCert()
					if err != nil {
						log.Fatalf("Error load/init client cert: %s", err)
					}
					return cert
				}
				return nil
			}(),
		)
		if err != nil {
			log.Fatalf("Error creating HTTP client: %s", err)
		}
		return client
	}()

	var url string
	if IsSandbox {
		url = fmt.Sprintf("https://%s", ApnsSandboxHost)
	} else {
		url = fmt.Sprintf("https://%s", ApnsProductionHost)
	}

	if IsPort2197 {
		url = url + ":2197"
	}

	url = url + "/3/device/"

	token, err := normalizeDeviceToken(DeviceToken)
	if err != nil {
		log.Fatalf("Error decoding hex device token: %s", err)
	}
	url = url + token

	req := func() *http.Request {
		var body []byte
		if len(MdmPushMagic) > 0 {
			body = []byte(fmt.Sprintf(`{"aps": {}, "mdm": "%s"}`, MdmPushMagic))
		} else {
			if PushAlertFileName != "" {
				body, err = ioutil.ReadFile(PushAlertFileName)
				if err != nil {
					log.Fatalf("Error reading file: %s", err)
				}
			} else if PushAlertJSON != "" {
				body = []byte(PushAlertJSON)
			} else {
				body = []byte(fmt.Sprintf(`{"aps": {"alert" : "%s", "sound": "default"}}`, PushAlertMessage))
			}
		}

		var v interface{}
		err = json.Unmarshal(body, &v)
		if err != nil {
			log.Fatalf("Error parsing JSON alert payload: %s", err)
		}

		req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
		if err != nil {
			log.Fatalf("Error creating POST request: %s", err)
		}

		if len(MdmPushMagic) > 0 {
			req.Header.Set("apns-push-type", "mdm")
		} else {
			req.Header.Set("apns-push-type", "alert")
		}

		if len(PushType) > 0 {
			req.Header.Set("apns-push-type", PushType)
		}

		if len(bearerToken) > 0 {
			req.Header.Set("authorization", fmt.Sprintf("bearer %s", bearerToken))
		}
		req.Header.Set("apns-expiration", "0")
		//req.Header.Set("apns-priority", "10")
		req.Header.Set("apns-topic", PushTopic)

		return req
	}()

	log.Println(fmt.Sprintf("Sending... POST %s", url))

	reqOut, err := httputil.DumpRequest(req, false)
	if err != nil {
		for k, v := range req.Header {
			fmt.Print(k)
			fmt.Print(": ")
			fmt.Println(v)
		}
	} else {
		fmt.Println(string(reqOut))
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error in HTTP request: %s", err)
	}
	defer resp.Body.Close()

	respOut, err := httputil.DumpResponse(resp, true)
	if err != nil {
		for k, v := range resp.Header {
			fmt.Print(k)
			fmt.Print(": ")
			fmt.Println(v)
		}
	} else {
		fmt.Println(string(respOut))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading HTTP response body: %s", err)
	}
	fmt.Printf("Response: %s (%d) %s\n", resp.Proto, resp.StatusCode, string(body))
}
