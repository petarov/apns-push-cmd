APNs Command Line Tool
===================================================

Transmit your remote notifications to Apple Push Notification service from the command line.

TODO

# Installation

TODO

# Usage

Show help:

    go run main.go -h

Send a push notification to your app using certificate-based authentication with public/private keys:

    go run main.go -cert-file app-cert.pem  -cert-key app-private.pem \
        -token 'c7b68e4eb7d604876bf5836133479ffa49449c669f7e6b79318ae59032e83c24' \
        -topic 'com.my.app'

Send an mdm push notification using certificate-based authentication with a PKCS#12 keystore.

    go run main.go -cert-p12 apns.p12 -cert-pass <my password> \
        -token 'v2RwEsm69Go4aY4vSFY2pRLped2BMqETO3gDGBx7XmxKwSaKtZik7Q==' \
        -mdm-magic '1AA91790-BA78-4DBF-9102-FBA06E6110C4' \
        -topic 'com.apple.mgmt.External.462ad9c3-7ca1-437b-8c6f-5575941a4ea7' 

## Extract keys from PKCS#12

To extract private key file from a PKCS#12 container use:

    openssl pkcs12 -info -in apns-production.p12 -nodes -nocerts -out apns-private.pem

To extrcat certificate file from a PKCS#12 container use:

    openssl pkcs12 -info -in apns-production.p12 -nokeys -out apns-cert.pem

# License

[MIT](LICENSE)