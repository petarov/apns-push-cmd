package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/net/http2"
)

// APP_NAME Name
const APP_NAME = "apns-push-cmd"

// VERSION Version
const VERSION = "1.0"

var (
	redColor           = color.New(color.FgRed)
	cyan               = color.New(color.FgCyan).SprintFunc()
	red                = color.New(color.FgRed).SprintFunc()
	ApnsProductionHost = "api.push.apple.com"
	ApnsSandboxHost    = "api.sandbox.push.apple.com"
	CaCertFiles        = [1]string{"AppleISTCA2G1.cer"}
	RootGeoTrustGlobal = `-----BEGIN CERTIFICATE-----
MIIDVDCCAjygAwIBAgIDAjRWMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMDIwNTIxMDQwMDAwWhcNMjIwNTIxMDQwMDAwWjBCMQswCQYDVQQG
EwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UEAxMSR2VvVHJ1c3Qg
R2xvYmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2swYYzD9
9BcjGlZ+W988bDjkcbd4kdS8odhM+KhDtgPpTSEHCIjaWC9mOSm9BXiLnTjoBbdq
fnGk5sRgprDvgOSJKA+eJdbtg/OtppHHmMlCGDUUna2YRpIuT8rxh0PBFpVXLVDv
iS2Aelet8u5fa9IAjbkU+BQVNdnARqN7csiRv8lVK83Qlz6cJmTM386DGXHKTubU
1XupGc1V3sjs0l44U+VcT4wt/lAjNvxm5suOpDkZALeVAjmRCw7+OC7RHQWa9k0+
bw8HHa8sHo9gOeL6NlMTOdReJivbPagUvTLrGAMoUgRx5aszPeE4uwc2hGKceeoW
MPRfwCvocWvk+QIDAQABo1MwUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTA
ephojYn7qwVkDBF9qn1luMrMTjAfBgNVHSMEGDAWgBTAephojYn7qwVkDBF9qn1l
uMrMTjANBgkqhkiG9w0BAQUFAAOCAQEANeMpauUvXVSOKVCUn5kaFOSPeCpilKIn
Z57QzxpeR+nBsqTP3UEaBU6bS+5Kb1VSsyShNwrrZHYqLizz/Tt1kL/6cdjHPTfS
tQWVYrmm3ok9Nns4d0iXrKYgjy6myQzCsplFAMfOEVEiIuCl6rYVSAlk6l5PdPcF
PseKUgzbFbS9bZvlxrFUaKnjaZC2mqUPuLk/IH2uSrW4nOQdtqvmlKXBx4Ot2/Un
hw4EbNX/3aBd7YdStysVAq45pmp06drE57xNNB6pXE0zX5IJL4hmXXeXxx12E6nV
5fEWCRE11azbJHFwLJhWC9kXtNHjUStedejV0NxPNO3CBWaAocvmMw==
-----END CERTIFICATE-----`
	RootAppleISTCA2G1 = `-----BEGIN CERTIFICATE-----
MIIEQDCCAyigAwIBAgIDAjp0MA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMTQwNjE2MTU0MjAyWhcNMjIwNTIwMTU0MjAyWjBiMRwwGgYDVQQD
ExNBcHBsZSBJU1QgQ0EgMiAtIEcxMSAwHgYDVQQLExdDZXJ0aWZpY2F0aW9uIEF1
dGhvcml0eTETMBEGA1UEChMKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQk6EdR0MgFrILa+vD1bTox5jN896/
6E3p4zaAB/xFG2p8RYauVtOkCX9hDWtdflJrfbTIOcT0Zzr3g84Zb4YvfkV+Rxxn
UsqVBV3iNlGFwNRngDVvFd0+/R3S/Y80UNjsdiq+49Pa5P3I6ygClhGXF2Ec6cRZ
O0LcMtEJHdqm0UOG/16yvIzPZtsBiwKulEjzOI/96jKoCOyGl1GUJD5JSZZT6Hmh
QIHpBbuTlVH84/18EUv3ngizFUkVB/nRN6CbSzL2tcTcatH8Cu324MUpoKiLcf4N
krz+VHAYCm3H7Qz7yS0Gw4yF/MuGXNY2jhKLCX/7GRo41fCUMHoPpozzAgMBAAGj
ggEdMIIBGTAfBgNVHSMEGDAWgBTAephojYn7qwVkDBF9qn1luMrMTjAdBgNVHQ4E
FgQU2HqURHyQcJAWnt0XnAFEA4bWKikwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNV
HQ8BAf8EBAMCAQYwNQYDVR0fBC4wLDAqoCigJoYkaHR0cDovL2cuc3ltY2IuY29t
L2NybHMvZ3RnbG9iYWwuY3JsMC4GCCsGAQUFBwEBBCIwIDAeBggrBgEFBQcwAYYS
aHR0cDovL2cuc3ltY2QuY29tMEwGA1UdIARFMEMwQQYKYIZIAYb4RQEHNjAzMDEG
CCsGAQUFBwIBFiVodHRwOi8vd3d3Lmdlb3RydXN0LmNvbS9yZXNvdXJjZXMvY3Bz
MA0GCSqGSIb3DQEBCwUAA4IBAQAWR3NvhaJi4ecqdruJlUIml7xKrKxwUzo/MYM9
PByrmuKxXRx2GqA8DHJXvtOeUODImdZY1wLqzg0pVHzN9cLGkClVo28UqAtCDTqY
bQZ4nvBqox0CCqIopI3CgUY+bWfa3j/+hQ5CKhLetbf7uBunlux3n+zUU5V6/wf0
8goUwFFSsdaOUAsamVy8C8m97e34XsFW201+I6QRoSzUGwWa5BtS9nw4mQVLunKN
QolgBGYq9P1o12v3mUEo1mwkq+YlUy7Igpnioo8jvjCDsSeL+mh/AUnoxphrEC6Y
XorXykuxx8lYmtA225aV7LaB5PLNbxt5h0wQPInkTfpU3Kqm
-----END CERTIFICATE-----`
)

var (
	// IsMdm ConfigPath config.yml file path
	IsMdm bool
	// KeystorePath The path to a APNs PKCS#12 certificate container
	KeystorePath string
	// KeystorePassword The password to open the certificate file container
	KeystorePassword string
	// ClientCertPath The path to APNs client ceritificate file
	ClientCertPath string
	// ClientKeyPath The path to APNs client cerificate key
	ClientKeyPath string
	// IsExplicitTrust Explicitly trust Geo Trust CA and Apple IST CA 2 root certificates.
	IsExplicitTrust bool
)

func init() {
	flag.BoolVar(&IsMdm, "mdm", false, "Is this an mdm")
	flag.StringVar(&KeystorePath, "cert-p12", "", "The path to a APNs PKCS#12 certificate container")
	flag.StringVar(&KeystorePassword, "cert-pass", "", "The password to open the certificate file container")
	flag.StringVar(&ClientCertPath, "cert-file", "", "The path to APNs client ceritificate file (If -cert-p12 has not been specified)")
	flag.StringVar(&ClientKeyPath, "cert-key", "", "The path to APNs client cerificate key")
	flag.BoolVar(&IsExplicitTrust, "x-trust", false, "Explicitly trust Geo Trust CA and Apple IST CA 2 root certificates (Usually you should not need to do this)")
}

func verifyPath(path string, what string, mustExist bool) {
	if len(path) < 1 {
		redColor.Println(what + " path not specified")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if mustExist {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			redColor.Println(what + " path not found")
			flag.PrintDefaults()
			os.Exit(1)
		}
	}
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

func main() {
	fmt.Printf("%s v%s - Apple Push Notification service Command Line Tool\n", APP_NAME, VERSION)

	flag.Parse()

	cert, err := getClientCert()
	if err != nil {
		log.Fatalf("Error loading/adding client cert: %s", err)
	}

	var tlsConfig *tls.Config

	if IsExplicitTrust {
		caCertPool, err := getCertPool()
		if err != nil {
			log.Fatalf("Error loading/adding root CAs: %s", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{*cert},
			RootCAs:      caCertPool,
		}
	} else {
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{*cert},
		}
	}

	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	client.Transport = &http2.Transport{
		TLSClientConfig: tlsConfig,
	}

	resp, err := client.Get(fmt.Sprintf("https://%s/3/device/123", ApnsProductionHost))
	if err != nil {
		log.Fatalf("Error in HTTP request: %s", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading HTTP response body: %s", err)
	}

	fmt.Printf(
		"Got response %d: %s %s\n",
		resp.StatusCode, resp.Proto, string(body))
}
