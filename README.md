APNs Command Line Tool
===================================================

Transmit your remote notifications to Apple Push Notification service from the command line.

# Installation

TODO

# Usage

TODO

## Extract keys from PKCS#12

To extract private key file from a PKCS#12 container use:

    openssl pkcs12 -info -in apns-production.p12 -nodes -nocerts -out apns-private.pem

To extrcat certificate file from a PKCS#12 container use:

    openssl pkcs12 -info -in apns-production.p12 -nokeys -out apns-cert.pem

# License

[MIT](LICENSE)