APNs Command Line Push
===================================================

[![CI Build](https://github.com/petarov/apns-push-cmd/actions/workflows/build.yml/badge.svg)](https://github.com/petarov/apns-push-cmd/actions/workflows/build.yml)
[![Dependabot Updates](https://github.com/petarov/apns-push-cmd/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/petarov/apns-push-cmd/actions/workflows/dependabot/dependabot-updates)
[![goreport](https://goreportcard.com/badge/github.com/petarov/apns-push-cmd)](https://goreportcard.com/report/github.com/petarov/apns-push-cmd)

<img align="right" src="apnsicon.png"> Send your push notifications to Apple Push Notification service from the command line using HTTP/2.

Authentication Mechanism         | Supported
---------------------------------|------------------------
 Provider Authentication Tokens  | yes :white_check_mark:
 APNs provider certificate       | yes :white_check_mark:

# Installation

[Download binaries](https://github.com/petarov/apns-push-cmd/releases/tag/latest) for Linux, macOS and Windows.

# Usage

Send a push notification to your app using certificate-based authentication:

    apnscmd_linux_amd64 -cert-file app-cert.pem -cert-key app-private.pem \
        -token c7b68e4eb7d604876bf5836133479ffa49449c669f7e6b79318ae59032e83c24 \
        -topic com.my.app

Send an MDM push notification using certificate-based authentication with a PKCS#12 keystore and Base64 encoded device token:

    apnscmd_linux_amd64 -cert-p12 apns.p12 -cert-pass <my password> \
        -token 'v2RwEsm69Go4aY4vSFY2pRLped2BMqETO3gDGBx7XmxKwSaKtZik7Q==' \
        -topic com.apple.mgmt.External.462ad9c3-7ca1-437b-8c6f-5575941a4ea7 \
        -mdm-magic 1AA91790-BA78-4DBF-9102-FBA06E6110C4

Send a push notification to your app using token-based authentication:

    apnscmd_linux_amd64 -auth-token AuthKey_BBC42Y2321.p8 -key-id BBC42Y2321 -team-id YXB7430FC8 \
        -token c7b68e4eb7d604876bf5836133479ffa49449c669f7e6b79318ae59032e83c24 \
        -topic com.my.app

Send a custom push notification to your app using token-based authentication with the JSON message specified in the command line:

    apnscmd_linux_amd64 -auth-token AuthKey_BBC42Y2321.p8 -key-id BBC42Y2321 -team-id YXB7430FC8 \
        -token c7b68e4eb7d604876bf5836133479ffa49449c669f7e6b79318ae59032e83c24 \
        -topic com.my.app -alert-json '{"aps": {"alert" : "test", "sound": "default"}, "custom":"custom value"}'


Send a custom push notification to your app using token-based authentication with the JSON message read from a file:

    apnscmd_linux_amd64 -auth-token AuthKey_BBC42Y2321.p8 -key-id BBC42Y2321 -team-id YXB7430FC8 \
        -token c7b68e4eb7d604876bf5836133479ffa49449c669f7e6b79318ae59032e83c24 \
        -topic com.my.app -alert-filename custom.json


Show all available arguments:

    apnscmd_linux_amd64 -h

The `-auth-token` argument always takes prescedence overt the `-cert-*` arguments.

## Extract keys from PKCS#12

If you're using a PKCS#12 keystore, then it must be [DER](https://en.wikipedia.org/wiki/X.690#DER_encoding) encoded. [BER](https://en.wikipedia.org/wiki/X.690#BER_encoding) encoded keystores are not supported. You'll need to manually break down a BER encoded keystore into certificate and private key files.

To extract private key file from a PKCS#12 container use:

    openssl pkcs12 -info -in apns-production.p12 -nodes -nocerts -out apns-private.pem

To extrcat certificate file from a PKCS#12 container use:

    openssl pkcs12 -info -in apns-production.p12 -nokeys -out apns-cert.pem

# Development

  - [Sending Notification Requests to APNs](https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/sending_notification_requests_to_apns/)
  - [Communicating with APNs](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/CommunicatingwithAPNs.html)

# License

[MIT](LICENSE)

README icon by [Freepik](http://www.freepik.com/) from [Flaticon](https://www.flaticon.com/).
