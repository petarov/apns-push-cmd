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
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/net/http2"
)

// APPNAME App Name
const APPNAME = "apns-push-cmd"

// VERSION Version
const VERSION = "1.5"

var (
	// ApnsSandboxHost Development push notifications
	ApnsSandboxHost = "api.sandbox.push.apple.com"
	// ApnsProductionHost Production push notifications
	ApnsProductionHost = "api.push.apple.com"
	// SHA-2 Root  USERTrust RSA Certification Authority
	USERTrustRSACA = `-----BEGIN CERTIFICATE-----
MIIF3jCCA8agAwIBAgIQAf1tMPyjylGoG7xkDjUDLTANBgkqhkiG9w0BAQwFADCB
iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl
cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV
BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAw
MjAxMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEzARBgNV
BAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVU
aGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2Vy
dGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQCAEmUXNg7D2wiz0KxXDXbtzSfTTK1Qg2HiqiBNCS1kCdzOiZ/MPans9s/B
3PHTsdZ7NygRK0faOca8Ohm0X6a9fZ2jY0K2dvKpOyuR+OJv0OwWIJAJPuLodMkY
tJHUYmTbf6MG8YgYapAiPLz+E/CHFHv25B+O1ORRxhFnRghRy4YUVD+8M/5+bJz/
Fp0YvVGONaanZshyZ9shZrHUm3gDwFA66Mzw3LyeTP6vBZY1H1dat//O+T23LLb2
VN3I5xI6Ta5MirdcmrS3ID3KfyI0rn47aGYBROcBTkZTmzNg95S+UzeQc0PzMsNT
79uq/nROacdrjGCT3sTHDN/hMq7MkztReJVni+49Vv4M0GkPGw/zJSZrM233bkf6
c0Plfg6lZrEpfDKEY1WJxA3Bk1QwGROs0303p+tdOmw1XNtB1xLaqUkL39iAigmT
Yo61Zs8liM2EuLE/pDkP2QKe6xJMlXzzawWpXhaDzLhn4ugTncxbgtNMs+1b/97l
c6wjOy0AvzVVdAlJ2ElYGn+SNuZRkg7zJn0cTRe8yexDJtC/QV9AqURE9JnnV4ee
UB9XVKg+/XRjL7FQZQnmWEIuQxpMtPAlR1n6BB6T1CZGSlCBst6+eLf8ZxXhyVeE
Hg9j1uliutZfVS7qXMYoCAQlObgOK6nyTJccBz8NUvXt7y+CDwIDAQABo0IwQDAd
BgNVHQ4EFgQUU3m/WqorSs9UgOHYm8Cd8rIDZsswDgYDVR0PAQH/BAQDAgEGMA8G
A1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAFzUfA3P9wF9QZllDHPF
Up/L+M+ZBn8b2kMVn54CVVeWFPFSPCeHlCjtHzoBN6J2/FNQwISbxmtOuowhT6KO
VWKR82kV2LyI48SqC/3vqOlLVSoGIG1VeCkZ7l8wXEskEVX/JJpuXior7gtNn3/3
ATiUFJVDBwn7YKnuHKsSjKCaXqeYalltiz8I+8jRRa8YFWSQEg9zKC7F4iRO/Fjs
8PRF/iKz6y+O0tlFYQXBl2+odnKPi4w2r78NBc5xjeambx9spnFixdjQg3IM8WcR
iQycE0xyNN+81XHfqnHd4blsjDwSXWXavVcStkNr/+XeTWYRUc+ZruwXtuhxkYze
Sf7dNXGiFSeUHM9h4ya7b6NnJSFd5t0dCy5oGzuCr+yDZ4XUmFF0sbmZgIn/f3gZ
XHlKYC6SQK5MNyosycdiyA5d9zZbyuAlJQG03RoHnHcAP9Dc1ew91Pq7P8yF1m9/
qS3fuQL39ZeatTXaw2ewh0qpKJ4jjv9cJ2vhsE/zB+4ALtRZh8tSQZXq9EfX7mRB
VXyNWQKV3WKdwrnuWih0hKWbt5DHDAff9Yk2dDLWKMGwsAvgnEzDHNb842m1R0aB
L6KCq9NjRHDEjf8tM7qtj3u1cIiuPhnPQCjY/MiQu12ZIvVS5ljFH4gxQ+6IHdfG
jjxDah2nGN59PRbxYvnKkKj9
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
	// The value of the apns-priority. Default is 10
	PushPriority int
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
	flag.StringVar(&PushType, "type", "", "The value of the apns-push-type header. Possible vaules are: 'alert', 'background', 'location', 'voip', 'complication', 'fileprovider', 'mdm', 'liveactivity'.  Default is 'alert'")
	flag.IntVar(&PushPriority, "priority", 10, "The value of the apns-priority header. Possible vaules are: 10, 5, 1. Default is 10")
	flag.StringVar(&MdmPushMagic, "mdm-magic", "", "The magic string that has to be included in the push notification message")
	flag.StringVar(&PushAlertMessage, "alert-text", "Hello from app-push-cmd!", "Alert text to display for app push notifications")
	flag.StringVar(&PushAlertJSON, "alert-json", "", "If this is set, this raw JSON will be sent instead of alert-text")
	flag.StringVar(&PushAlertFileName, "alert-filename", "", "If this is set the content of this file will be sent instead of alert-text/alert-json")
	flag.BoolVar(&IsSandbox, "sandbox", false, "Sends push notification to APNs sandbox at api.sandbox.push.apple.com")
	flag.BoolVar(&IsPort2197, "port2197", false, "Use port 2197 (instead of port 443) when communicating with APNs")
}

func getCertPool() (caCertPool *x509.CertPool, err error) {
	caCertPool = x509.NewCertPool()

	ok := caCertPool.AppendCertsFromPEM([]byte(USERTrustRSACA))
	if !ok {
		return nil, fmt.Errorf("error loading RootGeoTrustGlobal")
	}

	return caCertPool, nil
}

func getClientCert() (_ *tls.Certificate, err error) {
	if len(KeystorePath) > 0 {
		keystoreBytes, err := os.ReadFile(KeystorePath)
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

	cert, err := tls.LoadX509KeyPair(ClientCertPath, ClientKeyPath)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

func getClientBearerToken() (auth string, err error) {
	tokenBytes, err := os.ReadFile(AuthTokenPath)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(tokenBytes)
	if block == nil {
		return "", errors.New("auth token does not seem to be a valid .p8 key file")
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
				Certificates:       []tls.Certificate{*cert},
				RootCAs:            caCertPool,
				InsecureSkipVerify: false,
				MinVersion:         tls.VersionTLS12,
			}
		} else {
			tlsConfig = &tls.Config{
				RootCAs:            caCertPool,
				InsecureSkipVerify: false,
				MinVersion:         tls.VersionTLS12,
			}
		}
	} else if cert != nil {
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS12,
		}
	} else {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
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

	// Validate KeyID
	if KeyID != "" {
		if len(KeyID) != 10 {
			log.Fatalf("Error: -key-id must be 10 characters long.")
		}
		matched, _ := regexp.MatchString("^[a-zA-Z0-9]+$", KeyID)
		if !matched {
			log.Fatalf("Error: -key-id must be alphanumeric.")
		}
	}

	// Validate TeamID
	if TeamID != "" {
		if len(TeamID) != 10 {
			log.Fatalf("Error: -team-id must be 10 characters long.")
		}
		matched, _ := regexp.MatchString("^[a-zA-Z0-9]+$", TeamID)
		if !matched {
			log.Fatalf("Error: -team-id must be alphanumeric.")
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
				body, err = os.ReadFile(PushAlertFileName)
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
		req.Header.Set("apns-priority", strconv.Itoa(PushPriority))
		req.Header.Set("apns-topic", PushTopic)

		return req
	}()

	log.Printf("Sending... POST %s\n", url)

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading HTTP response body: %s", err)
	}
	fmt.Printf("Response: %s (%d) %s\n", resp.Proto, resp.StatusCode, string(body))
}
