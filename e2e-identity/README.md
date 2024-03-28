# Wire end to end identity example
Ed25519 - SHA256
```mermaid
sequenceDiagram
    autonumber
    wire-client->>+acme-server: 🔒 GET /acme/wire/directory
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 HEAD /acme/wire/new-nonce
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/new-account
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: 🔒 POST /acme/wire/new-order
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/OkCx2A56RIDYnkstTOf3hqCS79tgK8rQ
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/dDUIkFKarbmJrEzSJnoCrUB1eigdIYzU
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/a5e43f34510177a6/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/OkCx2A56RIDYnkstTOf3hqCS79tgK8rQ/4V01b2VCO9daeNnjWf1WWtGnVJE6fkph
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /realms/master/protocol/openid-connect/auth
    IdP->>-wire-client: 200
    wire-client->>+IdP:  POST /realms/master/protocol/openid-connect/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/dDUIkFKarbmJrEzSJnoCrUB1eigdIYzU/TnuonitDxBhrXO2NJpLuzg0ajOHQ9bBs
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/kkLyGo465YchWw6SdaO2Hnpk46CmxYPQ
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/kkLyGo465YchWw6SdaO2Hnpk46CmxYPQ/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/bZwcNOGlfXsZHmyf1xgh46pTMoau6iEd
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32779/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:32779/acme/wire/new-nonce",
  "newAccount": "https://stepca:32779/acme/wire/new-account",
  "newOrder": "https://stepca:32779/acme/wire/new-order",
  "revokeCert": "https://stepca:32779/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32779/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32779/acme/wire/directory>;rel="index"
replay-nonce: NE93VUxWdmE4OEVDeXVYR25PY25yMmZuVW5vOW45ZDU
```
```text
NE93VUxWdmE4OEVDeXVYR25PY25yMmZuVW5vOW45ZDU
```
#### 5. create a new account
```http request
POST https://stepca:32779/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkYwc25KWkxwM0RQOWl6bll5LW0yVi1MMkg1SlNIVC1YVmtRTXVQcUEzSjQifSwibm9uY2UiOiJORTkzVlV4V2RtRTRPRVZEZVhWWVIyNVBZMjV5TW1adVZXNXZPVzQ1WkRVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzkvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "77SKVLz7WTWgkZtjGy65P2nSGKBDlXbrySdc5IfeM1HNN15oPLYa8Ir9WbE3EnZZJMYlEdkZXTFiO21AKJDLDw"
}
```
```json
{
  "payload": {
    "contact": [
      "anonymous@anonymous.invalid"
    ],
    "onlyReturnExisting": false,
    "termsOfServiceAgreed": true
  },
  "protected": {
    "alg": "EdDSA",
    "jwk": {
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "F0snJZLp3DP9iznYy-m2V-L2H5JSHT-XVkQMuPqA3J4"
    },
    "nonce": "NE93VUxWdmE4OEVDeXVYR25PY25yMmZuVW5vOW45ZDU",
    "typ": "JWT",
    "url": "https://stepca:32779/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32779/acme/wire/directory>;rel="index"
location: https://stepca:32779/acme/wire/account/p8KF0TpgS5s74cW93blIwmB2B6kCSD5p
replay-nonce: Y1RSU0t2UDROS3NBSXpVRVZvVGhJbWE5YjFDdnJzWGI
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32779/acme/wire/account/p8KF0TpgS5s74cW93blIwmB2B6kCSD5p/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32779/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzc5L2FjbWUvd2lyZS9hY2NvdW50L3A4S0YwVHBnUzVzNzRjVzkzYmxJd21CMkI2a0NTRDVwIiwidHlwIjoiSldUIiwibm9uY2UiOiJZMVJTVTB0MlVEUk9TM05CU1hwVlJWWnZWR2hKYldFNVlqRkRkbkp6V0dJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzkvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtZGV2aWNlIiwidmFsdWUiOiJ7XCJjbGllbnQtaWRcIjpcIndpcmVhcHA6Ly9RMGJnOVBXQ1RaZXRXMVlmU0FLQ3h3IWE1ZTQzZjM0NTEwMTc3YTZAd2lyZS5jb21cIixcImhhbmRsZVwiOlwid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb21cIixcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCJ9In0seyJ0eXBlIjoid2lyZWFwcC11c2VyIiwidmFsdWUiOiJ7XCJoYW5kbGVcIjpcIndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tXCIsXCJuYW1lXCI6XCJBbGljZSBTbWl0aFwiLFwiZG9tYWluXCI6XCJ3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyNC0wMy0yOFQwODo1NzowMS45Nzc0MTJaIiwibm90QWZ0ZXIiOiIyMDM0LTAzLTI2VDA4OjU3OjAxLjk3NzQxMloifQ",
  "signature": "Zzee9t04_GbH_tkkpgf6zJm1BNARzXv2zdwAR1bVLwEkBs2wVpLo6sXcDgl9VZHA8WdLcvaQRjlM6mCRUAb1Dw"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-device",
        "value": "{\"client-id\":\"wireapp://Q0bg9PWCTZetW1YfSAKCxw!a5e43f34510177a6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      },
      {
        "type": "wireapp-user",
        "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      }
    ],
    "notAfter": "2034-03-26T08:57:01.977412Z",
    "notBefore": "2024-03-28T08:57:01.977412Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32779/acme/wire/account/p8KF0TpgS5s74cW93blIwmB2B6kCSD5p",
    "nonce": "Y1RSU0t2UDROS3NBSXpVRVZvVGhJbWE5YjFDdnJzWGI",
    "typ": "JWT",
    "url": "https://stepca:32779/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32779/acme/wire/directory>;rel="index"
location: https://stepca:32779/acme/wire/order/kkLyGo465YchWw6SdaO2Hnpk46CmxYPQ
replay-nonce: azFmV3JseFFwNGI5TG1uQVppSE4zak5yeEI1Yjd0VXc
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32779/acme/wire/order/kkLyGo465YchWw6SdaO2Hnpk46CmxYPQ/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://Q0bg9PWCTZetW1YfSAKCxw!a5e43f34510177a6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32779/acme/wire/authz/OkCx2A56RIDYnkstTOf3hqCS79tgK8rQ",
    "https://stepca:32779/acme/wire/authz/dDUIkFKarbmJrEzSJnoCrUB1eigdIYzU"
  ],
  "expires": "2024-03-29T08:57:01Z",
  "notBefore": "2024-03-28T08:57:01.977412Z",
  "notAfter": "2034-03-26T08:57:01.977412Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32779/acme/wire/authz/OkCx2A56RIDYnkstTOf3hqCS79tgK8rQ
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzc5L2FjbWUvd2lyZS9hY2NvdW50L3A4S0YwVHBnUzVzNzRjVzkzYmxJd21CMkI2a0NTRDVwIiwidHlwIjoiSldUIiwibm9uY2UiOiJhekZtVjNKc2VGRndOR0k1VEcxdVFWcHBTRTR6YWs1eWVFSTFZamQwVlhjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzkvYWNtZS93aXJlL2F1dGh6L09rQ3gyQTU2UklEWW5rc3RUT2YzaHFDUzc5dGdLOHJRIn0",
  "payload": "",
  "signature": "dKf4zL6EuH-U9cXcxUh4KPUSnPjBODWfuKpWAy_Nba6qR_-F8xzBmwgaeBDM_nWWEYTZBAOq_S-w15xRrrsACA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32779/acme/wire/account/p8KF0TpgS5s74cW93blIwmB2B6kCSD5p",
    "nonce": "azFmV3JseFFwNGI5TG1uQVppSE4zak5yeEI1Yjd0VXc",
    "typ": "JWT",
    "url": "https://stepca:32779/acme/wire/authz/OkCx2A56RIDYnkstTOf3hqCS79tgK8rQ"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32779/acme/wire/directory>;rel="index"
location: https://stepca:32779/acme/wire/authz/OkCx2A56RIDYnkstTOf3hqCS79tgK8rQ
replay-nonce: aU91bmU0bjJNYmZNU3NkUlJPaVhxMEJsVGo1ckxySWM
```
```json
{
  "status": "pending",
  "expires": "2024-03-29T08:57:01Z",
  "challenges": [
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32779/acme/wire/challenge/OkCx2A56RIDYnkstTOf3hqCS79tgK8rQ/4V01b2VCO9daeNnjWf1WWtGnVJE6fkph",
      "status": "pending",
      "token": "oLPZNGZ0KTBcn6DwRtkKb0hXzA9fC5iB",
      "target": "http://wire.com:24143/clients/a5e43f34510177a6/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-device",
    "value": "{\"client-id\":\"wireapp://Q0bg9PWCTZetW1YfSAKCxw!a5e43f34510177a6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
  }
}
```
```http request
POST https://stepca:32779/acme/wire/authz/dDUIkFKarbmJrEzSJnoCrUB1eigdIYzU
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzc5L2FjbWUvd2lyZS9hY2NvdW50L3A4S0YwVHBnUzVzNzRjVzkzYmxJd21CMkI2a0NTRDVwIiwidHlwIjoiSldUIiwibm9uY2UiOiJhVTkxYm1VMGJqSk5ZbVpOVTNOa1VsSlBhVmh4TUVKc1ZHbzFja3h5U1dNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzkvYWNtZS93aXJlL2F1dGh6L2REVUlrRkthcmJtSnJFelNKbm9DclVCMWVpZ2RJWXpVIn0",
  "payload": "",
  "signature": "yIEwH5B_9mIfrj3Vj_f17UiGj94db7Rhx1cVQiTCfhYvqNIK_RHs5LDpBAU2bdcne7As1gQHmBMk90HM0EQNAw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32779/acme/wire/account/p8KF0TpgS5s74cW93blIwmB2B6kCSD5p",
    "nonce": "aU91bmU0bjJNYmZNU3NkUlJPaVhxMEJsVGo1ckxySWM",
    "typ": "JWT",
    "url": "https://stepca:32779/acme/wire/authz/dDUIkFKarbmJrEzSJnoCrUB1eigdIYzU"
  }
}
```
#### 11. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32779/acme/wire/directory>;rel="index"
location: https://stepca:32779/acme/wire/authz/dDUIkFKarbmJrEzSJnoCrUB1eigdIYzU
replay-nonce: M1BCdEVTQ1BHeTlQZEVvbjBIM0hseE9JOEttZ0NObko
```
```json
{
  "status": "pending",
  "expires": "2024-03-29T08:57:01Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32779/acme/wire/challenge/dDUIkFKarbmJrEzSJnoCrUB1eigdIYzU/TnuonitDxBhrXO2NJpLuzg0ajOHQ9bBs",
      "status": "pending",
      "token": "W1FTR9ha78oje4mtuJKoa3nvaM25zbE8",
      "target": "http://keycloak:18398/realms/master"
    }
  ],
  "identifier": {
    "type": "wireapp-user",
    "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 12. fetch a nonce from wire-server
```http request
GET http://wire.com:24143/clients/token/nonce
```
#### 13. get wire-server nonce
```http request
200

```
```text
TGh4aHU1RFBvalkwVnlxTFhMYmlDMHdEeFl5cVFCdnY
```
#### 14. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiRjBzbkpaTHAzRFA5aXpuWXktbTJWLUwySDVKU0hULVhWa1FNdVBxQTNKNCJ9fQ.eyJpYXQiOjE3MTE2MTI2MjEsImV4cCI6MTcxMTYxOTgyMSwibmJmIjoxNzExNjEyNjIxLCJzdWIiOiJ3aXJlYXBwOi8vUTBiZzlQV0NUWmV0VzFZZlNBS0N4dyFhNWU0M2YzNDUxMDE3N2E2QHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzkvYWNtZS93aXJlL2NoYWxsZW5nZS9Pa0N4MkE1NlJJRFlua3N0VE9mM2hxQ1M3OXRnSzhyUS80VjAxYjJWQ085ZGFlTm5qV2YxV1d0R25WSkU2ZmtwaCIsImp0aSI6IjUxYjE4NDQ0LTE5YTQtNDA1My04ODMyLTQ1NjgyYzAxNjZjZCIsIm5vbmNlIjoiVEdoNGFIVTFSRkJ2YWxrd1ZubHhURmhNWW1sRE1IZEVlRmw1Y1ZGQ2RuWSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQxNDMvY2xpZW50cy9hNWU0M2YzNDUxMDE3N2E2L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJvTFBaTkdaMEtUQmNuNkR3UnRrS2IwaFh6QTlmQzVpQiIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUiLCJuYW1lIjoiQWxpY2UgU21pdGgifQ.dYDmJ8dfe93HTmpHJ8MtzuBuUe6-PNSdhUgoi8IJG_5zEnoyV8dadwWKuEGfsQmXRA0k4unMJKulTUe7_TryDA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiRjBzbkpaTHAzRFA5aXpuWXktbTJWLUwy
SDVKU0hULVhWa1FNdVBxQTNKNCJ9fQ.eyJpYXQiOjE3MTE2MTI2MjEsImV4cCI6M
TcxMTYxOTgyMSwibmJmIjoxNzExNjEyNjIxLCJzdWIiOiJ3aXJlYXBwOi8vUTBiZ
zlQV0NUWmV0VzFZZlNBS0N4dyFhNWU0M2YzNDUxMDE3N2E2QHdpcmUuY29tIiwiY
XVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzkvYWNtZS93aXJlL2NoYWxsZW5nZS9Pa
0N4MkE1NlJJRFlua3N0VE9mM2hxQ1M3OXRnSzhyUS80VjAxYjJWQ085ZGFlTm5qV
2YxV1d0R25WSkU2ZmtwaCIsImp0aSI6IjUxYjE4NDQ0LTE5YTQtNDA1My04ODMyL
TQ1NjgyYzAxNjZjZCIsIm5vbmNlIjoiVEdoNGFIVTFSRkJ2YWxrd1ZubHhURmhNW
W1sRE1IZEVlRmw1Y1ZGQ2RuWSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd
2lyZS5jb206MjQxNDMvY2xpZW50cy9hNWU0M2YzNDUxMDE3N2E2L2FjY2Vzcy10b
2tlbiIsImNoYWwiOiJvTFBaTkdaMEtUQmNuNkR3UnRrS2IwaFh6QTlmQzVpQiIsI
mhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhb
SI6IndpcmUiLCJuYW1lIjoiQWxpY2UgU21pdGgifQ.dYDmJ8dfe93HTmpHJ8Mtzu
BuUe6-PNSdhUgoi8IJG_5zEnoyV8dadwWKuEGfsQmXRA0k4unMJKulTUe7_TryDA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "F0snJZLp3DP9iznYy-m2V-L2H5JSHT-XVkQMuPqA3J4"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "aud": "https://stepca:32779/acme/wire/challenge/OkCx2A56RIDYnkstTOf3hqCS79tgK8rQ/4V01b2VCO9daeNnjWf1WWtGnVJE6fkph",
  "chal": "oLPZNGZ0KTBcn6DwRtkKb0hXzA9fC5iB",
  "exp": 1711619821,
  "handle": "wireapp://%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:24143/clients/a5e43f34510177a6/access-token",
  "iat": 1711612621,
  "jti": "51b18444-19a4-4053-8832-45682c0166cd",
  "name": "Alice Smith",
  "nbf": 1711612621,
  "nonce": "TGh4aHU1RFBvalkwVnlxTFhMYmlDMHdEeFl5cVFCdnY",
  "sub": "wireapp://Q0bg9PWCTZetW1YfSAKCxw!a5e43f34510177a6@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEID+2/+cgsYEfLTNix6T7y3gzsOm+n5PPDuX11eX7F0JQ
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAF0snJZLp3DP9iznYy+m2V+L2H5JSHT+XVkQMuPqA3J4=
-----END PUBLIC KEY-----
```

</details>


#### 15. trade client DPoP token for an access token
```http request
POST http://wire.com:24143/clients/a5e43f34510177a6/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pUmpCemJrcGFUSEF6UkZBNWFYcHVXWGt0YlRKV0xVd3lTRFZLVTBoVUxWaFdhMUZOZFZCeFFUTktOQ0o5ZlEuZXlKcFlYUWlPakUzTVRFMk1USTJNakVzSW1WNGNDSTZNVGN4TVRZeE9UZ3lNU3dpYm1KbUlqb3hOekV4TmpFeU5qSXhMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZVVEJpWnpsUVYwTlVXbVYwVnpGWlpsTkJTME40ZHlGaE5XVTBNMll6TkRVeE1ERTNOMkUyUUhkcGNtVXVZMjl0SWl3aVlYVmtJam9pYUhSMGNITTZMeTl6ZEdWd1kyRTZNekkzTnprdllXTnRaUzkzYVhKbEwyTm9ZV3hzWlc1blpTOVBhME40TWtFMU5sSkpSRmx1YTNOMFZFOW1NMmh4UTFNM09YUm5Temh5VVM4MFZqQXhZakpXUTA4NVpHRmxUbTVxVjJZeFYxZDBSMjVXU2tVMlptdHdhQ0lzSW1wMGFTSTZJalV4WWpFNE5EUTBMVEU1WVRRdE5EQTFNeTA0T0RNeUxUUTFOamd5WXpBeE5qWmpaQ0lzSW01dmJtTmxJam9pVkVkb05HRklWVEZTUmtKMllXeHJkMVp1YkhoVVJtaE5XVzFzUkUxSVpFVmxSbXcxWTFaR1EyUnVXU0lzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpReE5ETXZZMnhwWlc1MGN5OWhOV1UwTTJZek5EVXhNREUzTjJFMkwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUp2VEZCYVRrZGFNRXRVUW1OdU5rUjNVblJyUzJJd2FGaDZRVGxtUXpWcFFpSXNJbWhoYm1Sc1pTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2lkR1ZoYlNJNkluZHBjbVVpTENKdVlXMWxJam9pUVd4cFkyVWdVMjFwZEdnaWZRLmRZRG1KOGRmZTkzSFRtcEhKOE10enVCdVVlNi1QTlNkaFVnb2k4SUpHXzV6RW5veVY4ZGFkd1dLdUVHZnNRbVhSQTBrNHVuTUpLdWxUVWU3X1RyeURB
```
#### 16. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Ik1sVVRiSURVV1I3WjFxbV9kWjBjb05sQVZCRjVZcHdKSHNpRTNHT21hdmcifX0.eyJpYXQiOjE3MTE2MTI2MjEsImV4cCI6MTcxMTYxNjU4MSwibmJmIjoxNzExNjEyNjIxLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQxNDMvY2xpZW50cy9hNWU0M2YzNDUxMDE3N2E2L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9RMGJnOVBXQ1RaZXRXMVlmU0FLQ3h3IWE1ZTQzZjM0NTEwMTc3YTZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjc3OS9hY21lL3dpcmUvY2hhbGxlbmdlL09rQ3gyQTU2UklEWW5rc3RUT2YzaHFDUzc5dGdLOHJRLzRWMDFiMlZDTzlkYWVObmpXZjFXV3RHblZKRTZma3BoIiwianRpIjoiNmUxNWExZTUtODBlOS00Mjc5LThkMmItYjllZTY2NDk4ZjNmIiwibm9uY2UiOiJUR2g0YUhVMVJGQnZhbGt3Vm5seFRGaE1ZbWxETUhkRWVGbDVjVkZDZG5ZIiwiY2hhbCI6Im9MUFpOR1owS1RCY242RHdSdGtLYjBoWHpBOWZDNWlCIiwiY25mIjp7ImtpZCI6IjlvWXZJU1dKRjFpVHIzNmo1c3J5YjIxbXlUcW9iOUh4eU5uN1pYNGlEUGMifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lSakJ6YmtwYVRIQXpSRkE1YVhwdVdYa3RiVEpXTFV3eVNEVktVMGhVTFZoV2ExRk5kVkJ4UVROS05DSjlmUS5leUpwWVhRaU9qRTNNVEUyTVRJMk1qRXNJbVY0Y0NJNk1UY3hNVFl4T1RneU1Td2libUptSWpveE56RXhOakV5TmpJeExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dlVUQmlaemxRVjBOVVdtVjBWekZaWmxOQlMwTjRkeUZoTldVME0yWXpORFV4TURFM04yRTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STNOemt2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5UGEwTjRNa0UxTmxKSlJGbHVhM04wVkU5bU0yaHhRMU0zT1hSblN6aHlVUzgwVmpBeFlqSldRMDg1WkdGbFRtNXFWMll4VjFkMFIyNVdTa1UyWm10d2FDSXNJbXAwYVNJNklqVXhZakU0TkRRMExURTVZVFF0TkRBMU15MDRPRE15TFRRMU5qZ3lZekF4TmpaalpDSXNJbTV2Ym1ObElqb2lWRWRvTkdGSVZURlNSa0oyWVd4cmQxWnViSGhVUm1oTldXMXNSRTFJWkVWbFJtdzFZMVpHUTJSdVdTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalF4TkRNdlkyeHBaVzUwY3k5aE5XVTBNMll6TkRVeE1ERTNOMkUyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSnZURkJhVGtkYU1FdFVRbU51TmtSM1VuUnJTMkl3YUZoNlFUbG1RelZwUWlJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlMQ0p1WVcxbElqb2lRV3hwWTJVZ1UyMXBkR2dpZlEuZFlEbUo4ZGZlOTNIVG1wSEo4TXR6dUJ1VWU2LVBOU2RoVWdvaThJSkdfNXpFbm95VjhkYWR3V0t1RUdmc1FtWFJBMGs0dW5NSkt1bFRVZTdfVHJ5REEiLCJjbGllbnRfaWQiOiJ3aXJlYXBwOi8vUTBiZzlQV0NUWmV0VzFZZlNBS0N4dyFhNWU0M2YzNDUxMDE3N2E2QHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.m-j0t0Lv5J4ygf1A3d5hPTRYpSykaZO8TrVHa9YwceYIT5t51n-8pyMqtycBd1g_J5qrReT1W3FWnhA8cdheDw",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Ik1sVVRiSURVV1I3WjFxbV9kWjBjb05sQVZCRjVZcHdKSHNpRTNHT21hdmcifX0.eyJpYXQiOjE3MTE2MTI2MjEsImV4cCI6MTcxMTYxNjU4MSwibmJmIjoxNzExNjEyNjIxLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQxNDMvY2xpZW50cy9hNWU0M2YzNDUxMDE3N2E2L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9RMGJnOVBXQ1RaZXRXMVlmU0FLQ3h3IWE1ZTQzZjM0NTEwMTc3YTZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjc3OS9hY21lL3dpcmUvY2hhbGxlbmdlL09rQ3gyQTU2UklEWW5rc3RUT2YzaHFDUzc5dGdLOHJRLzRWMDFiMlZDTzlkYWVObmpXZjFXV3RHblZKRTZma3BoIiwianRpIjoiNmUxNWExZTUtODBlOS00Mjc5LThkMmItYjllZTY2NDk4ZjNmIiwibm9uY2UiOiJUR2g0YUhVMVJGQnZhbGt3Vm5seFRGaE1ZbWxETUhkRWVGbDVjVkZDZG5ZIiwiY2hhbCI6Im9MUFpOR1owS1RCY242RHdSdGtLYjBoWHpBOWZDNWlCIiwiY25mIjp7ImtpZCI6IjlvWXZJU1dKRjFpVHIzNmo1c3J5YjIxbXlUcW9iOUh4eU5uN1pYNGlEUGMifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lSakJ6YmtwYVRIQXpSRkE1YVhwdVdYa3RiVEpXTFV3eVNEVktVMGhVTFZoV2ExRk5kVkJ4UVROS05DSjlmUS5leUpwWVhRaU9qRTNNVEUyTVRJMk1qRXNJbVY0Y0NJNk1UY3hNVFl4T1RneU1Td2libUptSWpveE56RXhOakV5TmpJeExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dlVUQmlaemxRVjBOVVdtVjBWekZaWmxOQlMwTjRkeUZoTldVME0yWXpORFV4TURFM04yRTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STNOemt2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5UGEwTjRNa0UxTmxKSlJGbHVhM04wVkU5bU0yaHhRMU0zT1hSblN6aHlVUzgwVmpBeFlqSldRMDg1WkdGbFRtNXFWMll4VjFkMFIyNVdTa1UyWm10d2FDSXNJbXAwYVNJNklqVXhZakU0TkRRMExURTVZVFF0TkRBMU15MDRPRE15TFRRMU5qZ3lZekF4TmpaalpDSXNJbTV2Ym1ObElqb2lWRWRvTkdGSVZURlNSa0oyWVd4cmQxWnViSGhVUm1oTldXMXNSRTFJWkVWbFJtdzFZMVpHUTJSdVdTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalF4TkRNdlkyeHBaVzUwY3k5aE5XVTBNMll6TkRVeE1ERTNOMkUyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSnZURkJhVGtkYU1FdFVRbU51TmtSM1VuUnJTMkl3YUZoNlFUbG1RelZwUWlJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlMQ0p1WVcxbElqb2lRV3hwWTJVZ1UyMXBkR2dpZlEuZFlEbUo4ZGZlOTNIVG1wSEo4TXR6dUJ1VWU2LVBOU2RoVWdvaThJSkdfNXpFbm95VjhkYWR3V0t1RUdmc1FtWFJBMGs0dW5NSkt1bFRVZTdfVHJ5REEiLCJjbGllbnRfaWQiOiJ3aXJlYXBwOi8vUTBiZzlQV0NUWmV0VzFZZlNBS0N4dyFhNWU0M2YzNDUxMDE3N2E2QHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.m-j0t0Lv5J4ygf1A3d5hPTRYpSykaZO8TrVHa9YwceYIT5t51n-8pyMqtycBd1g_J5qrReT1W3FWnhA8cdheDw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6Ik1sVVRiSURVV1I3WjFxbV9kWjBjb05sQVZC
RjVZcHdKSHNpRTNHT21hdmcifX0.eyJpYXQiOjE3MTE2MTI2MjEsImV4cCI6MTcx
MTYxNjU4MSwibmJmIjoxNzExNjEyNjIxLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjQxNDMvY2xpZW50cy9hNWU0M2YzNDUxMDE3N2E2L2FjY2Vzcy10b2tlbiIsInN1
YiI6IndpcmVhcHA6Ly9RMGJnOVBXQ1RaZXRXMVlmU0FLQ3h3IWE1ZTQzZjM0NTEw
MTc3YTZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjc3OS9hY21l
L3dpcmUvY2hhbGxlbmdlL09rQ3gyQTU2UklEWW5rc3RUT2YzaHFDUzc5dGdLOHJR
LzRWMDFiMlZDTzlkYWVObmpXZjFXV3RHblZKRTZma3BoIiwianRpIjoiNmUxNWEx
ZTUtODBlOS00Mjc5LThkMmItYjllZTY2NDk4ZjNmIiwibm9uY2UiOiJUR2g0YUhV
MVJGQnZhbGt3Vm5seFRGaE1ZbWxETUhkRWVGbDVjVkZDZG5ZIiwiY2hhbCI6Im9M
UFpOR1owS1RCY242RHdSdGtLYjBoWHpBOWZDNWlCIiwiY25mIjp7ImtpZCI6Ijlv
WXZJU1dKRjFpVHIzNmo1c3J5YjIxbXlUcW9iOUh4eU5uN1pYNGlEUGMifSwicHJv
b2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3
aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENK
NElqb2lSakJ6YmtwYVRIQXpSRkE1YVhwdVdYa3RiVEpXTFV3eVNEVktVMGhVTFZo
V2ExRk5kVkJ4UVROS05DSjlmUS5leUpwWVhRaU9qRTNNVEUyTVRJMk1qRXNJbVY0
Y0NJNk1UY3hNVFl4T1RneU1Td2libUptSWpveE56RXhOakV5TmpJeExDSnpkV0lp
T2lKM2FYSmxZWEJ3T2k4dlVUQmlaemxRVjBOVVdtVjBWekZaWmxOQlMwTjRkeUZo
TldVME0yWXpORFV4TURFM04yRTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIw
Y0hNNkx5OXpkR1Z3WTJFNk16STNOemt2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVu
WlM5UGEwTjRNa0UxTmxKSlJGbHVhM04wVkU5bU0yaHhRMU0zT1hSblN6aHlVUzgw
VmpBeFlqSldRMDg1WkdGbFRtNXFWMll4VjFkMFIyNVdTa1UyWm10d2FDSXNJbXAw
YVNJNklqVXhZakU0TkRRMExURTVZVFF0TkRBMU15MDRPRE15TFRRMU5qZ3lZekF4
TmpaalpDSXNJbTV2Ym1ObElqb2lWRWRvTkdGSVZURlNSa0oyWVd4cmQxWnViSGhV
Um1oTldXMXNSRTFJWkVWbFJtdzFZMVpHUTJSdVdTSXNJbWgwYlNJNklsQlBVMVFp
TENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalF4TkRNdlkyeHBaVzUw
Y3k5aE5XVTBNMll6TkRVeE1ERTNOMkUyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5v
WVd3aU9pSnZURkJhVGtkYU1FdFVRbU51TmtSM1VuUnJTMkl3YUZoNlFUbG1RelZw
UWlJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEps
UUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlMQ0p1WVcxbElqb2lRV3hw
WTJVZ1UyMXBkR2dpZlEuZFlEbUo4ZGZlOTNIVG1wSEo4TXR6dUJ1VWU2LVBOU2Ro
VWdvaThJSkdfNXpFbm95VjhkYWR3V0t1RUdmc1FtWFJBMGs0dW5NSkt1bFRVZTdf
VHJ5REEiLCJjbGllbnRfaWQiOiJ3aXJlYXBwOi8vUTBiZzlQV0NUWmV0VzFZZlNB
S0N4dyFhNWU0M2YzNDUxMDE3N2E2QHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUs
InNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.m-j0t0Lv5J4ygf1A3d5hPTRYpSyka
ZO8TrVHa9YwceYIT5t51n-8pyMqtycBd1g_J5qrReT1W3FWnhA8cdheDw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "MlUTbIDUWR7Z1qm_dZ0coNlAVBF5YpwJHsiE3GOmavg"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "https://stepca:32779/acme/wire/challenge/OkCx2A56RIDYnkstTOf3hqCS79tgK8rQ/4V01b2VCO9daeNnjWf1WWtGnVJE6fkph",
  "chal": "oLPZNGZ0KTBcn6DwRtkKb0hXzA9fC5iB",
  "client_id": "wireapp://Q0bg9PWCTZetW1YfSAKCxw!a5e43f34510177a6@wire.com",
  "cnf": {
    "kid": "9oYvISWJF1iTr36j5sryb21myTqob9HxyNn7ZX4iDPc"
  },
  "exp": 1711616581,
  "iat": 1711612621,
  "iss": "http://wire.com:24143/clients/a5e43f34510177a6/access-token",
  "jti": "6e15a1e5-80e9-4279-8d2b-b9ee66498f3f",
  "nbf": 1711612621,
  "nonce": "TGh4aHU1RFBvalkwVnlxTFhMYmlDMHdEeFl5cVFCdnY",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiRjBzbkpaTHAzRFA5aXpuWXktbTJWLUwySDVKU0hULVhWa1FNdVBxQTNKNCJ9fQ.eyJpYXQiOjE3MTE2MTI2MjEsImV4cCI6MTcxMTYxOTgyMSwibmJmIjoxNzExNjEyNjIxLCJzdWIiOiJ3aXJlYXBwOi8vUTBiZzlQV0NUWmV0VzFZZlNBS0N4dyFhNWU0M2YzNDUxMDE3N2E2QHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzkvYWNtZS93aXJlL2NoYWxsZW5nZS9Pa0N4MkE1NlJJRFlua3N0VE9mM2hxQ1M3OXRnSzhyUS80VjAxYjJWQ085ZGFlTm5qV2YxV1d0R25WSkU2ZmtwaCIsImp0aSI6IjUxYjE4NDQ0LTE5YTQtNDA1My04ODMyLTQ1NjgyYzAxNjZjZCIsIm5vbmNlIjoiVEdoNGFIVTFSRkJ2YWxrd1ZubHhURmhNWW1sRE1IZEVlRmw1Y1ZGQ2RuWSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQxNDMvY2xpZW50cy9hNWU0M2YzNDUxMDE3N2E2L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJvTFBaTkdaMEtUQmNuNkR3UnRrS2IwaFh6QTlmQzVpQiIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUiLCJuYW1lIjoiQWxpY2UgU21pdGgifQ.dYDmJ8dfe93HTmpHJ8MtzuBuUe6-PNSdhUgoi8IJG_5zEnoyV8dadwWKuEGfsQmXRA0k4unMJKulTUe7_TryDA",
  "scope": "wire_client_id",
  "sub": "wireapp://Q0bg9PWCTZetW1YfSAKCxw!a5e43f34510177a6@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINpbtQQH6B9MqhagNUSi+ymbAiWkmu5zMogh2UkeZaQc
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAMlUTbIDUWR7Z1qm/dZ0coNlAVBF5YpwJHsiE3GOmavg=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 17. validate Dpop challenge (clientId)
```http request
POST https://stepca:32779/acme/wire/challenge/OkCx2A56RIDYnkstTOf3hqCS79tgK8rQ/4V01b2VCO9daeNnjWf1WWtGnVJE6fkph
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzc5L2FjbWUvd2lyZS9hY2NvdW50L3A4S0YwVHBnUzVzNzRjVzkzYmxJd21CMkI2a0NTRDVwIiwidHlwIjoiSldUIiwibm9uY2UiOiJNMUJDZEVWVFExQkhlVGxRWkVWdmJqQklNMGhzZUU5Sk9FdHRaME5PYmtvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzkvYWNtZS93aXJlL2NoYWxsZW5nZS9Pa0N4MkE1NlJJRFlua3N0VE9mM2hxQ1M3OXRnSzhyUS80VjAxYjJWQ085ZGFlTm5qV2YxV1d0R25WSkU2ZmtwaCJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklrMXNWVlJpU1VSVlYxSTNXakZ4YlY5a1dqQmpiMDVzUVZaQ1JqVlpjSGRLU0hOcFJUTkhUMjFoZG1jaWZYMC5leUpwWVhRaU9qRTNNVEUyTVRJMk1qRXNJbVY0Y0NJNk1UY3hNVFl4TmpVNE1Td2libUptSWpveE56RXhOakV5TmpJeExDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpReE5ETXZZMnhwWlc1MGN5OWhOV1UwTTJZek5EVXhNREUzTjJFMkwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbmRwY21WaGNIQTZMeTlSTUdKbk9WQlhRMVJhWlhSWE1WbG1VMEZMUTNoM0lXRTFaVFF6WmpNME5URXdNVGMzWVRaQWQybHlaUzVqYjIwaUxDSmhkV1FpT2lKb2RIUndjem92TDNOMFpYQmpZVG96TWpjM09TOWhZMjFsTDNkcGNtVXZZMmhoYkd4bGJtZGxMMDlyUTNneVFUVTJVa2xFV1c1cmMzUlVUMll6YUhGRFV6YzVkR2RMT0hKUkx6UldNREZpTWxaRFR6bGtZV1ZPYm1wWFpqRlhWM1JIYmxaS1JUWm1hM0JvSWl3aWFuUnBJam9pTm1VeE5XRXhaVFV0T0RCbE9TMDBNamM1TFRoa01tSXRZamxsWlRZMk5EazRaak5tSWl3aWJtOXVZMlVpT2lKVVIyZzBZVWhWTVZKR1FuWmhiR3QzVm01c2VGUkdhRTFaYld4RVRVaGtSV1ZHYkRWalZrWkRaRzVaSWl3aVkyaGhiQ0k2SW05TVVGcE9SMW93UzFSQ1kyNDJSSGRTZEd0TFlqQm9XSHBCT1daRE5XbENJaXdpWTI1bUlqcDdJbXRwWkNJNklqbHZXWFpKVTFkS1JqRnBWSEl6Tm1vMWMzSjVZakl4YlhsVWNXOWlPVWg0ZVU1dU4xcFlOR2xFVUdNaWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsU2FrSjZZbXR3WVZSSVFYcFNSa0UxWVZod2RWZFlhM1JpVkVwWFRGVjNlVk5FVmt0Vk1HaFZURlpvVjJFeFJrNWtWa0o0VVZST1MwNURTamxtVVM1bGVVcHdXVmhSYVU5cVJUTk5WRVV5VFZSSk1rMXFSWE5KYlZZMFkwTkpOazFVWTNoTlZGbDRUMVJuZVUxVGQybGliVXB0U1dwdmVFNTZSWGhPYWtWNVRtcEplRXhEU25wa1YwbHBUMmxLTTJGWVNteFpXRUozVDJrNGRsVlVRbWxhZW14UlZqQk9WVmR0VmpCV2VrWmFXbXhPUWxNd1RqUmtlVVpvVGxkVk1FMHlXWHBPUkZWNFRVUkZNMDR5UlRKUlNHUndZMjFWZFZreU9YUkphWGRwV1ZoV2EwbHFiMmxoU0ZJd1kwaE5Oa3g1T1hwa1IxWjNXVEpGTmsxNlNUTk9lbXQyV1ZkT2RGcFRPVE5oV0Vwc1RESk9iMWxYZUhOYVZ6VnVXbE01VUdFd1RqUk5hMFV4VG14S1NsSkdiSFZoTTA0d1ZrVTViVTB5YUhoUk1VMHpUMWhTYmxONmFIbFZVemd3Vm1wQmVGbHFTbGRSTURnMVdrZEdiRlJ0TlhGV01sbDRWakZrTUZJeU5WZFRhMVV5V20xMGQyRkRTWE5KYlhBd1lWTkpOa2xxVlhoWmFrVTBUa1JSTUV4VVJUVlpWRkYwVGtSQk1VMTVNRFJQUkUxNVRGUlJNVTVxWjNsWmVrRjRUbXBhYWxwRFNYTkpiVFYyWW0xT2JFbHFiMmxXUldSdlRrZEdTVlpVUmxOU2Ewb3lXVmQ0Y21ReFduVmlTR2hWVW0xb1RsZFhNWE5TUlRGSldrVldiRkp0ZHpGWk1WcEhVVEpTZFZkVFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOYWxGNFRrUk5kbGt5ZUhCYVZ6VXdZM2s1YUU1WFZUQk5NbGw2VGtSVmVFMUVSVE5PTWtVeVRESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTblpVUmtKaFZHdGtZVTFGZEZWUmJVNTFUbXRTTTFWdVVuSlRNa2wzWVVab05sRlViRzFSZWxad1VXbEpjMGx0YUdoaWJWSnpXbE5KTmtsdVpIQmpiVlpvWTBoQk5reDVPR3hPUkVKb1lrZHNhbHBXT1ROaFdFcHNVVWhrY0dOdFZYVlpNamwwU1dsM2FXUkhWbWhpVTBrMlNXNWtjR050VldsTVEwcDFXVmN4YkVscWIybFJWM2h3V1RKVloxVXlNWEJrUjJkcFpsRXVaRmxFYlVvNFpHWmxPVE5JVkcxd1NFbzRUWFI2ZFVKMVZXVTJMVkJPVTJSb1ZXZHZhVGhKU2tkZk5YcEZibTk1Vmpoa1lXUjNWMHQxUlVkbWMxRnRXRkpCTUdzMGRXNU5Ta3QxYkZSVlpUZGZWSEo1UkVFaUxDSmpiR2xsYm5SZmFXUWlPaUozYVhKbFlYQndPaTh2VVRCaVp6bFFWME5VV21WMFZ6RlpabE5CUzBONGR5RmhOV1UwTTJZek5EVXhNREUzTjJFMlFIZHBjbVV1WTI5dElpd2lZWEJwWDNabGNuTnBiMjRpT2pVc0luTmpiM0JsSWpvaWQybHlaVjlqYkdsbGJuUmZhV1FpZlEubS1qMHQwTHY1SjR5Z2YxQTNkNWhQVFJZcFN5a2FaTzhUclZIYTlZd2NlWUlUNXQ1MW4tOHB5TXF0eWNCZDFnX0o1cXJSZVQxVzNGV25oQThjZGhlRHcifQ",
  "signature": "EJGVcCnzVsEPY96GjozEdHMpi-_SkKHbniJipX1tB-ZBOTisYEd3dIVu8LZ_q9U-5Ts2SQukSjQcMJWLFIonAg"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Ik1sVVRiSURVV1I3WjFxbV9kWjBjb05sQVZCRjVZcHdKSHNpRTNHT21hdmcifX0.eyJpYXQiOjE3MTE2MTI2MjEsImV4cCI6MTcxMTYxNjU4MSwibmJmIjoxNzExNjEyNjIxLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQxNDMvY2xpZW50cy9hNWU0M2YzNDUxMDE3N2E2L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9RMGJnOVBXQ1RaZXRXMVlmU0FLQ3h3IWE1ZTQzZjM0NTEwMTc3YTZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjc3OS9hY21lL3dpcmUvY2hhbGxlbmdlL09rQ3gyQTU2UklEWW5rc3RUT2YzaHFDUzc5dGdLOHJRLzRWMDFiMlZDTzlkYWVObmpXZjFXV3RHblZKRTZma3BoIiwianRpIjoiNmUxNWExZTUtODBlOS00Mjc5LThkMmItYjllZTY2NDk4ZjNmIiwibm9uY2UiOiJUR2g0YUhVMVJGQnZhbGt3Vm5seFRGaE1ZbWxETUhkRWVGbDVjVkZDZG5ZIiwiY2hhbCI6Im9MUFpOR1owS1RCY242RHdSdGtLYjBoWHpBOWZDNWlCIiwiY25mIjp7ImtpZCI6IjlvWXZJU1dKRjFpVHIzNmo1c3J5YjIxbXlUcW9iOUh4eU5uN1pYNGlEUGMifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lSakJ6YmtwYVRIQXpSRkE1YVhwdVdYa3RiVEpXTFV3eVNEVktVMGhVTFZoV2ExRk5kVkJ4UVROS05DSjlmUS5leUpwWVhRaU9qRTNNVEUyTVRJMk1qRXNJbVY0Y0NJNk1UY3hNVFl4T1RneU1Td2libUptSWpveE56RXhOakV5TmpJeExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dlVUQmlaemxRVjBOVVdtVjBWekZaWmxOQlMwTjRkeUZoTldVME0yWXpORFV4TURFM04yRTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STNOemt2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5UGEwTjRNa0UxTmxKSlJGbHVhM04wVkU5bU0yaHhRMU0zT1hSblN6aHlVUzgwVmpBeFlqSldRMDg1WkdGbFRtNXFWMll4VjFkMFIyNVdTa1UyWm10d2FDSXNJbXAwYVNJNklqVXhZakU0TkRRMExURTVZVFF0TkRBMU15MDRPRE15TFRRMU5qZ3lZekF4TmpaalpDSXNJbTV2Ym1ObElqb2lWRWRvTkdGSVZURlNSa0oyWVd4cmQxWnViSGhVUm1oTldXMXNSRTFJWkVWbFJtdzFZMVpHUTJSdVdTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalF4TkRNdlkyeHBaVzUwY3k5aE5XVTBNMll6TkRVeE1ERTNOMkUyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSnZURkJhVGtkYU1FdFVRbU51TmtSM1VuUnJTMkl3YUZoNlFUbG1RelZwUWlJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlMQ0p1WVcxbElqb2lRV3hwWTJVZ1UyMXBkR2dpZlEuZFlEbUo4ZGZlOTNIVG1wSEo4TXR6dUJ1VWU2LVBOU2RoVWdvaThJSkdfNXpFbm95VjhkYWR3V0t1RUdmc1FtWFJBMGs0dW5NSkt1bFRVZTdfVHJ5REEiLCJjbGllbnRfaWQiOiJ3aXJlYXBwOi8vUTBiZzlQV0NUWmV0VzFZZlNBS0N4dyFhNWU0M2YzNDUxMDE3N2E2QHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.m-j0t0Lv5J4ygf1A3d5hPTRYpSykaZO8TrVHa9YwceYIT5t51n-8pyMqtycBd1g_J5qrReT1W3FWnhA8cdheDw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32779/acme/wire/account/p8KF0TpgS5s74cW93blIwmB2B6kCSD5p",
    "nonce": "M1BCdEVTQ1BHeTlQZEVvbjBIM0hseE9JOEttZ0NObko",
    "typ": "JWT",
    "url": "https://stepca:32779/acme/wire/challenge/OkCx2A56RIDYnkstTOf3hqCS79tgK8rQ/4V01b2VCO9daeNnjWf1WWtGnVJE6fkph"
  }
}
```
#### 18. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32779/acme/wire/directory>;rel="index"
link: <https://stepca:32779/acme/wire/authz/OkCx2A56RIDYnkstTOf3hqCS79tgK8rQ>;rel="up"
location: https://stepca:32779/acme/wire/challenge/OkCx2A56RIDYnkstTOf3hqCS79tgK8rQ/4V01b2VCO9daeNnjWf1WWtGnVJE6fkph
replay-nonce: MzduR1hEV0NOanMwcmFxSXdhclBEUXZIM1JqM2ZvNlo
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32779/acme/wire/challenge/OkCx2A56RIDYnkstTOf3hqCS79tgK8rQ/4V01b2VCO9daeNnjWf1WWtGnVJE6fkph",
  "status": "valid",
  "token": "oLPZNGZ0KTBcn6DwRtkKb0hXzA9fC5iB",
  "target": "http://wire.com:24143/clients/a5e43f34510177a6/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 19. OAUTH authorization request

```text
code_verifier=TH9Jv-I9MaltmztOx5g7Yj_B7VWNbvyqXUHMAFfq_fI&code_challenge=rxwovMTi4xm_oogAAYcJSw649LoxmAB-Rti_OGUTZ-o
```
#### 20. OAUTH authorization request (auth code endpoint)
```http request
GET http://keycloak:18398/realms/master/protocol/openid-connect/auth?response_type=code&client_id=wireapp&state=pfAEIgvCcxmR5z0IjSvAYA&code_challenge=rxwovMTi4xm_oogAAYcJSw649LoxmAB-Rti_OGUTZ-o&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A24143%2Fcallback&scope=openid+profile&claims=%7B%22id_token%22%3A%7B%22acme_aud%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22https%3A%2F%2Fstepca%3A32779%2Facme%2Fwire%2Fchallenge%2FdDUIkFKarbmJrEzSJnoCrUB1eigdIYzU%2FTnuonitDxBhrXO2NJpLuzg0ajOHQ9bBs%22%7D%2C%22keyauth%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22W1FTR9ha78oje4mtuJKoa3nvaM25zbE8.9oYvISWJF1iTr36j5sryb21myTqob9HxyNn7ZX4iDPc%22%7D%7D%7D&nonce=Dj-jFTNKPEgDtSihTASyTQ
```

#### 21. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://keycloak:18398/realms/master/protocol/openid-connect/token
accept: application/json
content-type: application/x-www-form-urlencoded
```
```text
grant_type=authorization_code&code=95fca970-6574-4d10-ae33-de0f2c90530b.88f81446-79eb-4275-a9e9-2253f346f533.032f6858-e9ca-4d24-be0d-b9c95f5c20fb&code_verifier=TH9Jv-I9MaltmztOx5g7Yj_B7VWNbvyqXUHMAFfq_fI&client_id=wireapp&redirect_uri=http%3A%2F%2Fwire.com%3A24143%2Fcallback
```
#### 22. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJnTm45bURoT3h0LVRVTlNxajdRcURtYVd3QjlKdmNWcnhQRG96a2o3cU53In0.eyJleHAiOjE3MTE2MTYyODIsImlhdCI6MTcxMTYxNjIyMiwiYXV0aF90aW1lIjoxNzExNjE2MjIyLCJqdGkiOiI3ZTljZTdlYS1mNTVlLTRlOWYtYmZmMy04OGI1ODczM2FmMDIiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTgzOTgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiIxMWUwZTkyOC03MTAyLTQ1YjItYTk2Ni04YTdkYjEyMzNiZjciLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJEai1qRlROS1BFZ0R0U2loVEFTeVRRIiwic2Vzc2lvbl9zdGF0ZSI6Ijg4ZjgxNDQ2LTc5ZWItNDI3NS1hOWU5LTIyNTNmMzQ2ZjUzMyIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjI0MTQzIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiODhmODE0NDYtNzllYi00Mjc1LWE5ZTktMjI1M2YzNDZmNTMzIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.rnjDQnxKwehPd5F3KdZ7jbQhjZ1tLTNgCc_fufhiwHJHGcYbnYPxqkrYRsaUlXWvu6cbM1PiEuduXxCqt4hP6LEGZ2yHlKBLU5vSd4g7l5Hx1931uFOyjYRa9F_IJhl3uNLh0KjmBRIVH4vL6k-LkGmbUinO6BICAn2JlL-W2Q6WBdQVXk9F6qKPOqp-2j_Ep3CKIXshz6FHmUrIS4OG_xFqJrb07bzoJhOM3d_6WYaXu975yet2yG-8HS_F5mVoZtwJJzEwwCf-xJVgUhTZUm-RFnBa26iTfZOpmRpa42pSOYH8gbw279_-DUJbXYtNhlmmWfiSJRDwR7Cm7rx6sQ",
  "expires_in": 60,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJnTm45bURoT3h0LVRVTlNxajdRcURtYVd3QjlKdmNWcnhQRG96a2o3cU53In0.eyJleHAiOjE3MTE2MTYyODIsImlhdCI6MTcxMTYxNjIyMiwiYXV0aF90aW1lIjoxNzExNjE2MjIyLCJqdGkiOiI2ZmM4OTgwZi0xZjc2LTRhZTQtYWYxMi1iZTlhZDc4YzA4YWQiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTgzOTgvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiIxMWUwZTkyOC03MTAyLTQ1YjItYTk2Ni04YTdkYjEyMzNiZjciLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6IkRqLWpGVE5LUEVnRHRTaWhUQVN5VFEiLCJzZXNzaW9uX3N0YXRlIjoiODhmODE0NDYtNzllYi00Mjc1LWE5ZTktMjI1M2YzNDZmNTMzIiwiYXRfaGFzaCI6Ik5vbnRKTnNveGpKZ0g5WGlzM3NReUEiLCJhY3IiOiIxIiwic2lkIjoiODhmODE0NDYtNzllYi00Mjc1LWE5ZTktMjI1M2YzNDZmNTMzIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJhY21lX2F1ZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzc5L2FjbWUvd2lyZS9jaGFsbGVuZ2UvZERVSWtGS2FyYm1KckV6U0pub0NyVUIxZWlnZElZelUvVG51b25pdER4QmhyWE8yTkpwTHV6ZzBhak9IUTliQnMiLCJrZXlhdXRoIjoiVzFGVFI5aGE3OG9qZTRtdHVKS29hM252YU0yNXpiRTguOW9ZdklTV0pGMWlUcjM2ajVzcnliMjFteVRxb2I5SHh5Tm43Wlg0aURQYyIsImdpdmVuX25hbWUiOiJBbGljZSIsImZhbWlseV9uYW1lIjoiU21pdGgiLCJlbWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20ifQ.p_ENaIhBSmMuZHkeOWu_VeL_XM3ip-n44zOINtskTmiGrhleXQOX3gm0M-KV1qHePbv1q9gnFyV74uY0-4SzsVO0kH47qAnodYAyMpEcpWkea0l3uowbrxiwO4eMaVPc4okuEIkW6aOu8kY0HwdjiUzIH_uO4g4NYHx3WIQrqoy3GkmQI6xR5gZAoLrn2-Phm5jLJXxJFKjM2hQn_2QgAFLVOa59MtZ7hGdHkwqaKtu7Baz2trvwcgY921r46qZkq3qTvZdKec8k9-NaaF47guwR15FioNixayXv1v2YSA7WCw34xCAdT8pRqnkW-NefRpQaUDujhtvFtsILnONHaQ",
  "not-before-policy": 0,
  "refresh_expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3NjNiYjgxYS1hZjRkLTQ1YWYtYTlkNC1kMWRkZWUzZGRlZjMifQ.eyJleHAiOjE3MTE2MTgwMjIsImlhdCI6MTcxMTYxNjIyMiwianRpIjoiYWJkN2Y0OTQtODFlZC00MDcyLWFhNWItMWRkOGUxY2M5NWJjIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE4Mzk4L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTgzOTgvcmVhbG1zL21hc3RlciIsInN1YiI6IjExZTBlOTI4LTcxMDItNDViMi1hOTY2LThhN2RiMTIzM2JmNyIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJEai1qRlROS1BFZ0R0U2loVEFTeVRRIiwic2Vzc2lvbl9zdGF0ZSI6Ijg4ZjgxNDQ2LTc5ZWItNDI3NS1hOWU5LTIyNTNmMzQ2ZjUzMyIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiI4OGY4MTQ0Ni03OWViLTQyNzUtYTllOS0yMjUzZjM0NmY1MzMifQ.9ZJDH2JeR2EvYOM-MVM8ph_sX43QbF_kt-wnG3OpJzo",
  "scope": "openid profile email",
  "session_state": "88f81446-79eb-4275-a9e9-2253f346f533",
  "token_type": "Bearer"
}
```

<details>
<summary><b>OAuth Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJnTm45bURoT3h0LVRVTlNxajdRcURtYVd3QjlKdmNWcnhQRG96a2o3cU53In0.eyJleHAiOjE3MTE2MTYyODIsImlhdCI6MTcxMTYxNjIyMiwiYXV0aF90aW1lIjoxNzExNjE2MjIyLCJqdGkiOiI3ZTljZTdlYS1mNTVlLTRlOWYtYmZmMy04OGI1ODczM2FmMDIiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTgzOTgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiIxMWUwZTkyOC03MTAyLTQ1YjItYTk2Ni04YTdkYjEyMzNiZjciLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJEai1qRlROS1BFZ0R0U2loVEFTeVRRIiwic2Vzc2lvbl9zdGF0ZSI6Ijg4ZjgxNDQ2LTc5ZWItNDI3NS1hOWU5LTIyNTNmMzQ2ZjUzMyIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjI0MTQzIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiODhmODE0NDYtNzllYi00Mjc1LWE5ZTktMjI1M2YzNDZmNTMzIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.rnjDQnxKwehPd5F3KdZ7jbQhjZ1tLTNgCc_fufhiwHJHGcYbnYPxqkrYRsaUlXWvu6cbM1PiEuduXxCqt4hP6LEGZ2yHlKBLU5vSd4g7l5Hx1931uFOyjYRa9F_IJhl3uNLh0KjmBRIVH4vL6k-LkGmbUinO6BICAn2JlL-W2Q6WBdQVXk9F6qKPOqp-2j_Ep3CKIXshz6FHmUrIS4OG_xFqJrb07bzoJhOM3d_6WYaXu975yet2yG-8HS_F5mVoZtwJJzEwwCf-xJVgUhTZUm-RFnBa26iTfZOpmRpa42pSOYH8gbw279_-DUJbXYtNhlmmWfiSJRDwR7Cm7rx6sQ)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJnTm45bURoT3h0
LVRVTlNxajdRcURtYVd3QjlKdmNWcnhQRG96a2o3cU53In0.eyJleHAiOjE3MTE2
MTYyODIsImlhdCI6MTcxMTYxNjIyMiwiYXV0aF90aW1lIjoxNzExNjE2MjIyLCJq
dGkiOiI3ZTljZTdlYS1mNTVlLTRlOWYtYmZmMy04OGI1ODczM2FmMDIiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MTgzOTgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFj
Y291bnQiLCJzdWIiOiIxMWUwZTkyOC03MTAyLTQ1YjItYTk2Ni04YTdkYjEyMzNi
ZjciLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJEai1q
RlROS1BFZ0R0U2loVEFTeVRRIiwic2Vzc2lvbl9zdGF0ZSI6Ijg4ZjgxNDQ2LTc5
ZWItNDI3NS1hOWU5LTIyNTNmMzQ2ZjUzMyIsImFjciI6IjEiLCJhbGxvd2VkLW9y
aWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjI0MTQzIl0sInJlYWxtX2FjY2VzcyI6
eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNz
IiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2Nv
dW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQt
bGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxl
IGVtYWlsIiwic2lkIjoiODhmODE0NDYtNzllYi00Mjc1LWE5ZTktMjI1M2YzNDZm
NTMzIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIs
InByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJnaXZl
bl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJh
bGljZXNtaXRoQHdpcmUuY29tIn0.rnjDQnxKwehPd5F3KdZ7jbQhjZ1tLTNgCc_f
ufhiwHJHGcYbnYPxqkrYRsaUlXWvu6cbM1PiEuduXxCqt4hP6LEGZ2yHlKBLU5vS
d4g7l5Hx1931uFOyjYRa9F_IJhl3uNLh0KjmBRIVH4vL6k-LkGmbUinO6BICAn2J
lL-W2Q6WBdQVXk9F6qKPOqp-2j_Ep3CKIXshz6FHmUrIS4OG_xFqJrb07bzoJhOM
3d_6WYaXu975yet2yG-8HS_F5mVoZtwJJzEwwCf-xJVgUhTZUm-RFnBa26iTfZOp
mRpa42pSOYH8gbw279_-DUJbXYtNhlmmWfiSJRDwR7Cm7rx6sQ
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "gNn9mDhOxt-TUNSqj7QqDmaWwB9JvcVrxPDozkj7qNw",
  "typ": "JWT"
}
```

```json
{
  "acr": "1",
  "allowed-origins": [
    "http://wire.com:24143"
  ],
  "aud": "account",
  "auth_time": 1711616222,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1711616282,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1711616222,
  "iss": "http://keycloak:18398/realms/master",
  "jti": "7e9ce7ea-f55e-4e9f-bff3-88b58733af02",
  "name": "Alice Smith",
  "nonce": "Dj-jFTNKPEgDtSihTASyTQ",
  "preferred_username": "alice_wire@wire.com",
  "realm_access": {
    "roles": [
      "default-roles-master",
      "offline_access",
      "uma_authorization"
    ]
  },
  "resource_access": {
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    }
  },
  "scope": "openid profile email",
  "session_state": "88f81446-79eb-4275-a9e9-2253f346f533",
  "sid": "88f81446-79eb-4275-a9e9-2253f346f533",
  "sub": "11e0e928-7102-45b2-a966-8a7db1233bf7",
  "typ": "Bearer"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2ZDYztANDTgcHchdUvsV
eRcsUCfBrXBUWfpjPlLkzRg86qv/i15Y081KxM5nrTCKazuhZ0IFLWz/bXd9drJH
a0jLIrXTcIT8XC2HN1yWgVznDT19RJaGAANxVXKvCxNyJHCuLtNMz3N1uiBhCJ/M
Z/japIDCOdjS2nD/PtYAe6fRqnYNhkm9i4TRxX60F/iWKpHlyfIH6Tv7+N/2Xqjt
cSV9wPzVNPYNM6dRxlAygDwbBhMxHNXEawHYpRPzw1PBAemduufumekxIIpM36Pi
mIa0V7lepurS01HmxqETLWlWuMIE+4zJ9xRXHAV8C33YDtoIz0z7nS+sQaLYjV3x
gQIDAQAB
-----END PUBLIC KEY-----
```

</details>



<details>
<summary><b>OAuth Refresh token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3NjNiYjgxYS1hZjRkLTQ1YWYtYTlkNC1kMWRkZWUzZGRlZjMifQ.eyJleHAiOjE3MTE2MTgwMjIsImlhdCI6MTcxMTYxNjIyMiwianRpIjoiYWJkN2Y0OTQtODFlZC00MDcyLWFhNWItMWRkOGUxY2M5NWJjIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE4Mzk4L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTgzOTgvcmVhbG1zL21hc3RlciIsInN1YiI6IjExZTBlOTI4LTcxMDItNDViMi1hOTY2LThhN2RiMTIzM2JmNyIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJEai1qRlROS1BFZ0R0U2loVEFTeVRRIiwic2Vzc2lvbl9zdGF0ZSI6Ijg4ZjgxNDQ2LTc5ZWItNDI3NS1hOWU5LTIyNTNmMzQ2ZjUzMyIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiI4OGY4MTQ0Ni03OWViLTQyNzUtYTllOS0yMjUzZjM0NmY1MzMifQ.9ZJDH2JeR2EvYOM-MVM8ph_sX43QbF_kt-wnG3OpJzo)

Raw:
```text
eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3NjNiYjgxYS1h
ZjRkLTQ1YWYtYTlkNC1kMWRkZWUzZGRlZjMifQ.eyJleHAiOjE3MTE2MTgwMjIsI
mlhdCI6MTcxMTYxNjIyMiwianRpIjoiYWJkN2Y0OTQtODFlZC00MDcyLWFhNWItM
WRkOGUxY2M5NWJjIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE4Mzk4L3JlYWxtc
y9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTgzOTgvcmVhbG1zL21hc
3RlciIsInN1YiI6IjExZTBlOTI4LTcxMDItNDViMi1hOTY2LThhN2RiMTIzM2JmN
yIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJEai1qR
lROS1BFZ0R0U2loVEFTeVRRIiwic2Vzc2lvbl9zdGF0ZSI6Ijg4ZjgxNDQ2LTc5Z
WItNDI3NS1hOWU5LTIyNTNmMzQ2ZjUzMyIsInNjb3BlIjoib3BlbmlkIHByb2Zpb
GUgZW1haWwiLCJzaWQiOiI4OGY4MTQ0Ni03OWViLTQyNzUtYTllOS0yMjUzZjM0N
mY1MzMifQ.9ZJDH2JeR2EvYOM-MVM8ph_sX43QbF_kt-wnG3OpJzo
```

Decoded:

```json
{
  "alg": "HS256",
  "kid": "763bb81a-af4d-45af-a9d4-d1ddee3ddef3",
  "typ": "JWT"
}
```

```json
{
  "aud": "http://keycloak:18398/realms/master",
  "azp": "wireapp",
  "exp": 1711618022,
  "iat": 1711616222,
  "iss": "http://keycloak:18398/realms/master",
  "jti": "abd7f494-81ed-4072-aa5b-1dd8e1cc95bc",
  "nonce": "Dj-jFTNKPEgDtSihTASyTQ",
  "scope": "openid profile email",
  "session_state": "88f81446-79eb-4275-a9e9-2253f346f533",
  "sid": "88f81446-79eb-4275-a9e9-2253f346f533",
  "sub": "11e0e928-7102-45b2-a966-8a7db1233bf7",
  "typ": "Refresh"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2ZDYztANDTgcHchdUvsV
eRcsUCfBrXBUWfpjPlLkzRg86qv/i15Y081KxM5nrTCKazuhZ0IFLWz/bXd9drJH
a0jLIrXTcIT8XC2HN1yWgVznDT19RJaGAANxVXKvCxNyJHCuLtNMz3N1uiBhCJ/M
Z/japIDCOdjS2nD/PtYAe6fRqnYNhkm9i4TRxX60F/iWKpHlyfIH6Tv7+N/2Xqjt
cSV9wPzVNPYNM6dRxlAygDwbBhMxHNXEawHYpRPzw1PBAemduufumekxIIpM36Pi
mIa0V7lepurS01HmxqETLWlWuMIE+4zJ9xRXHAV8C33YDtoIz0z7nS+sQaLYjV3x
gQIDAQAB
-----END PUBLIC KEY-----
```

</details>


#### 23. validate oidc challenge (userId + displayName)

<details>
<summary><b>OIDC Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJnTm45bURoT3h0LVRVTlNxajdRcURtYVd3QjlKdmNWcnhQRG96a2o3cU53In0.eyJleHAiOjE3MTE2MTYyODIsImlhdCI6MTcxMTYxNjIyMiwiYXV0aF90aW1lIjoxNzExNjE2MjIyLCJqdGkiOiI2ZmM4OTgwZi0xZjc2LTRhZTQtYWYxMi1iZTlhZDc4YzA4YWQiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTgzOTgvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiIxMWUwZTkyOC03MTAyLTQ1YjItYTk2Ni04YTdkYjEyMzNiZjciLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6IkRqLWpGVE5LUEVnRHRTaWhUQVN5VFEiLCJzZXNzaW9uX3N0YXRlIjoiODhmODE0NDYtNzllYi00Mjc1LWE5ZTktMjI1M2YzNDZmNTMzIiwiYXRfaGFzaCI6Ik5vbnRKTnNveGpKZ0g5WGlzM3NReUEiLCJhY3IiOiIxIiwic2lkIjoiODhmODE0NDYtNzllYi00Mjc1LWE5ZTktMjI1M2YzNDZmNTMzIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJhY21lX2F1ZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzc5L2FjbWUvd2lyZS9jaGFsbGVuZ2UvZERVSWtGS2FyYm1KckV6U0pub0NyVUIxZWlnZElZelUvVG51b25pdER4QmhyWE8yTkpwTHV6ZzBhak9IUTliQnMiLCJrZXlhdXRoIjoiVzFGVFI5aGE3OG9qZTRtdHVKS29hM252YU0yNXpiRTguOW9ZdklTV0pGMWlUcjM2ajVzcnliMjFteVRxb2I5SHh5Tm43Wlg0aURQYyIsImdpdmVuX25hbWUiOiJBbGljZSIsImZhbWlseV9uYW1lIjoiU21pdGgiLCJlbWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20ifQ.p_ENaIhBSmMuZHkeOWu_VeL_XM3ip-n44zOINtskTmiGrhleXQOX3gm0M-KV1qHePbv1q9gnFyV74uY0-4SzsVO0kH47qAnodYAyMpEcpWkea0l3uowbrxiwO4eMaVPc4okuEIkW6aOu8kY0HwdjiUzIH_uO4g4NYHx3WIQrqoy3GkmQI6xR5gZAoLrn2-Phm5jLJXxJFKjM2hQn_2QgAFLVOa59MtZ7hGdHkwqaKtu7Baz2trvwcgY921r46qZkq3qTvZdKec8k9-NaaF47guwR15FioNixayXv1v2YSA7WCw34xCAdT8pRqnkW-NefRpQaUDujhtvFtsILnONHaQ)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJnTm45bURoT3h0
LVRVTlNxajdRcURtYVd3QjlKdmNWcnhQRG96a2o3cU53In0.eyJleHAiOjE3MTE2
MTYyODIsImlhdCI6MTcxMTYxNjIyMiwiYXV0aF90aW1lIjoxNzExNjE2MjIyLCJq
dGkiOiI2ZmM4OTgwZi0xZjc2LTRhZTQtYWYxMi1iZTlhZDc4YzA4YWQiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MTgzOTgvcmVhbG1zL21hc3RlciIsImF1ZCI6Indp
cmVhcHAiLCJzdWIiOiIxMWUwZTkyOC03MTAyLTQ1YjItYTk2Ni04YTdkYjEyMzNi
ZjciLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6IkRqLWpGVE5L
UEVnRHRTaWhUQVN5VFEiLCJzZXNzaW9uX3N0YXRlIjoiODhmODE0NDYtNzllYi00
Mjc1LWE5ZTktMjI1M2YzNDZmNTMzIiwiYXRfaGFzaCI6Ik5vbnRKTnNveGpKZ0g5
WGlzM3NReUEiLCJhY3IiOiIxIiwic2lkIjoiODhmODE0NDYtNzllYi00Mjc1LWE5
ZTktMjI1M2YzNDZmNTMzIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJB
bGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2ly
ZS5jb20iLCJhY21lX2F1ZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzc5L2FjbWUvd2ly
ZS9jaGFsbGVuZ2UvZERVSWtGS2FyYm1KckV6U0pub0NyVUIxZWlnZElZelUvVG51
b25pdER4QmhyWE8yTkpwTHV6ZzBhak9IUTliQnMiLCJrZXlhdXRoIjoiVzFGVFI5
aGE3OG9qZTRtdHVKS29hM252YU0yNXpiRTguOW9ZdklTV0pGMWlUcjM2ajVzcnli
MjFteVRxb2I5SHh5Tm43Wlg0aURQYyIsImdpdmVuX25hbWUiOiJBbGljZSIsImZh
bWlseV9uYW1lIjoiU21pdGgiLCJlbWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20i
fQ.p_ENaIhBSmMuZHkeOWu_VeL_XM3ip-n44zOINtskTmiGrhleXQOX3gm0M-KV1
qHePbv1q9gnFyV74uY0-4SzsVO0kH47qAnodYAyMpEcpWkea0l3uowbrxiwO4eMa
VPc4okuEIkW6aOu8kY0HwdjiUzIH_uO4g4NYHx3WIQrqoy3GkmQI6xR5gZAoLrn2
-Phm5jLJXxJFKjM2hQn_2QgAFLVOa59MtZ7hGdHkwqaKtu7Baz2trvwcgY921r46
qZkq3qTvZdKec8k9-NaaF47guwR15FioNixayXv1v2YSA7WCw34xCAdT8pRqnkW-
NefRpQaUDujhtvFtsILnONHaQ
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "gNn9mDhOxt-TUNSqj7QqDmaWwB9JvcVrxPDozkj7qNw",
  "typ": "JWT"
}
```

```json
{
  "acme_aud": "https://stepca:32779/acme/wire/challenge/dDUIkFKarbmJrEzSJnoCrUB1eigdIYzU/TnuonitDxBhrXO2NJpLuzg0ajOHQ9bBs",
  "acr": "1",
  "at_hash": "NontJNsoxjJgH9Xis3sQyA",
  "aud": "wireapp",
  "auth_time": 1711616222,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1711616282,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1711616222,
  "iss": "http://keycloak:18398/realms/master",
  "jti": "6fc8980f-1f76-4ae4-af12-be9ad78c08ad",
  "keyauth": "W1FTR9ha78oje4mtuJKoa3nvaM25zbE8.9oYvISWJF1iTr36j5sryb21myTqob9HxyNn7ZX4iDPc",
  "name": "Alice Smith",
  "nonce": "Dj-jFTNKPEgDtSihTASyTQ",
  "preferred_username": "alice_wire@wire.com",
  "session_state": "88f81446-79eb-4275-a9e9-2253f346f533",
  "sid": "88f81446-79eb-4275-a9e9-2253f346f533",
  "sub": "11e0e928-7102-45b2-a966-8a7db1233bf7",
  "typ": "ID"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2ZDYztANDTgcHchdUvsV
eRcsUCfBrXBUWfpjPlLkzRg86qv/i15Y081KxM5nrTCKazuhZ0IFLWz/bXd9drJH
a0jLIrXTcIT8XC2HN1yWgVznDT19RJaGAANxVXKvCxNyJHCuLtNMz3N1uiBhCJ/M
Z/japIDCOdjS2nD/PtYAe6fRqnYNhkm9i4TRxX60F/iWKpHlyfIH6Tv7+N/2Xqjt
cSV9wPzVNPYNM6dRxlAygDwbBhMxHNXEawHYpRPzw1PBAemduufumekxIIpM36Pi
mIa0V7lepurS01HmxqETLWlWuMIE+4zJ9xRXHAV8C33YDtoIz0z7nS+sQaLYjV3x
gQIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32779/acme/wire/challenge/dDUIkFKarbmJrEzSJnoCrUB1eigdIYzU/TnuonitDxBhrXO2NJpLuzg0ajOHQ9bBs
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzc5L2FjbWUvd2lyZS9hY2NvdW50L3A4S0YwVHBnUzVzNzRjVzkzYmxJd21CMkI2a0NTRDVwIiwidHlwIjoiSldUIiwibm9uY2UiOiJNemR1UjFoRVYwTk9hbk13Y21GeFNYZGhjbEJFVVhaSU0xSnFNMlp2TmxvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzkvYWNtZS93aXJlL2NoYWxsZW5nZS9kRFVJa0ZLYXJibUpyRXpTSm5vQ3JVQjFlaWdkSVl6VS9UbnVvbml0RHhCaHJYTzJOSnBMdXpnMGFqT0hROWJCcyJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSWdPaUFpU2xkVUlpd2lhMmxrSWlBNklDSm5UbTQ1YlVSb1QzaDBMVlJWVGxOeGFqZFJjVVJ0WVZkM1FqbEtkbU5XY25oUVJHOTZhMm8zY1U1M0luMC5leUpsZUhBaU9qRTNNVEUyTVRZeU9ESXNJbWxoZENJNk1UY3hNVFl4TmpJeU1pd2lZWFYwYUY5MGFXMWxJam94TnpFeE5qRTJNakl5TENKcWRHa2lPaUkyWm1NNE9UZ3daaTB4WmpjMkxUUmhaVFF0WVdZeE1pMWlaVGxoWkRjNFl6QTRZV1FpTENKcGMzTWlPaUpvZEhSd09pOHZhMlY1WTJ4dllXczZNVGd6T1RndmNtVmhiRzF6TDIxaGMzUmxjaUlzSW1GMVpDSTZJbmRwY21WaGNIQWlMQ0p6ZFdJaU9pSXhNV1V3WlRreU9DMDNNVEF5TFRRMVlqSXRZVGsyTmkwNFlUZGtZakV5TXpOaVpqY2lMQ0owZVhBaU9pSkpSQ0lzSW1GNmNDSTZJbmRwY21WaGNIQWlMQ0p1YjI1alpTSTZJa1JxTFdwR1ZFNUxVRVZuUkhSVGFXaFVRVk41VkZFaUxDSnpaWE56YVc5dVgzTjBZWFJsSWpvaU9EaG1PREUwTkRZdE56bGxZaTAwTWpjMUxXRTVaVGt0TWpJMU0yWXpORFptTlRNeklpd2lZWFJmYUdGemFDSTZJazV2Ym5SS1RuTnZlR3BLWjBnNVdHbHpNM05SZVVFaUxDSmhZM0lpT2lJeElpd2ljMmxrSWpvaU9EaG1PREUwTkRZdE56bGxZaTAwTWpjMUxXRTVaVGt0TWpJMU0yWXpORFptTlRNeklpd2laVzFoYVd4ZmRtVnlhV1pwWldRaU9uUnlkV1VzSW01aGJXVWlPaUpCYkdsalpTQlRiV2wwYUNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJbUZzYVdObFgzZHBjbVZBZDJseVpTNWpiMjBpTENKaFkyMWxYMkYxWkNJNkltaDBkSEJ6T2k4dmMzUmxjR05oT2pNeU56YzVMMkZqYldVdmQybHlaUzlqYUdGc2JHVnVaMlV2WkVSVlNXdEdTMkZ5WW0xS2NrVjZVMHB1YjBOeVZVSXhaV2xuWkVsWmVsVXZWRzUxYjI1cGRFUjRRbWh5V0U4eVRrcHdUSFY2WnpCaGFrOUlVVGxpUW5NaUxDSnJaWGxoZFhSb0lqb2lWekZHVkZJNWFHRTNPRzlxWlRSdGRIVktTMjloTTI1MllVMHlOWHBpUlRndU9XOVpka2xUVjBwR01XbFVjak0yYWpWemNubGlNakZ0ZVZSeGIySTVTSGg1VG00M1dsZzBhVVJRWXlJc0ltZHBkbVZ1WDI1aGJXVWlPaUpCYkdsalpTSXNJbVpoYldsc2VWOXVZVzFsSWpvaVUyMXBkR2dpTENKbGJXRnBiQ0k2SW1Gc2FXTmxjMjFwZEdoQWQybHlaUzVqYjIwaWZRLnBfRU5hSWhCU21NdVpIa2VPV3VfVmVMX1hNM2lwLW40NHpPSU50c2tUbWlHcmhsZVhRT1gzZ20wTS1LVjFxSGVQYnYxcTlnbkZ5Vjc0dVkwLTRTenNWTzBrSDQ3cUFub2RZQXlNcEVjcFdrZWEwbDN1b3dicnhpd080ZU1hVlBjNG9rdUVJa1c2YU91OGtZMEh3ZGppVXpJSF91TzRnNE5ZSHgzV0lRcnFveTNHa21RSTZ4UjVnWkFvTHJuMi1QaG01akxKWHhKRktqTTJoUW5fMlFnQUZMVk9hNTlNdFo3aEdkSGt3cWFLdHU3QmF6MnRydndjZ1k5MjFyNDZxWmtxM3FUdlpkS2VjOGs5LU5hYUY0N2d1d1IxNUZpb05peGF5WHYxdjJZU0E3V0N3MzR4Q0FkVDhwUnFua1ctTmVmUnBRYVVEdWpodHZGdHNJTG5PTkhhUSJ9",
  "signature": "APcayyFm0iZmJ2vFwT1OnKCs5iGA_fQBkANCtxtoyrpR2WZwrZHf-zROn1kdCh6VPf8FhgfLp3wqpoHA_reJBA"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJnTm45bURoT3h0LVRVTlNxajdRcURtYVd3QjlKdmNWcnhQRG96a2o3cU53In0.eyJleHAiOjE3MTE2MTYyODIsImlhdCI6MTcxMTYxNjIyMiwiYXV0aF90aW1lIjoxNzExNjE2MjIyLCJqdGkiOiI2ZmM4OTgwZi0xZjc2LTRhZTQtYWYxMi1iZTlhZDc4YzA4YWQiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTgzOTgvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiIxMWUwZTkyOC03MTAyLTQ1YjItYTk2Ni04YTdkYjEyMzNiZjciLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6IkRqLWpGVE5LUEVnRHRTaWhUQVN5VFEiLCJzZXNzaW9uX3N0YXRlIjoiODhmODE0NDYtNzllYi00Mjc1LWE5ZTktMjI1M2YzNDZmNTMzIiwiYXRfaGFzaCI6Ik5vbnRKTnNveGpKZ0g5WGlzM3NReUEiLCJhY3IiOiIxIiwic2lkIjoiODhmODE0NDYtNzllYi00Mjc1LWE5ZTktMjI1M2YzNDZmNTMzIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJhY21lX2F1ZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzc5L2FjbWUvd2lyZS9jaGFsbGVuZ2UvZERVSWtGS2FyYm1KckV6U0pub0NyVUIxZWlnZElZelUvVG51b25pdER4QmhyWE8yTkpwTHV6ZzBhak9IUTliQnMiLCJrZXlhdXRoIjoiVzFGVFI5aGE3OG9qZTRtdHVKS29hM252YU0yNXpiRTguOW9ZdklTV0pGMWlUcjM2ajVzcnliMjFteVRxb2I5SHh5Tm43Wlg0aURQYyIsImdpdmVuX25hbWUiOiJBbGljZSIsImZhbWlseV9uYW1lIjoiU21pdGgiLCJlbWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20ifQ.p_ENaIhBSmMuZHkeOWu_VeL_XM3ip-n44zOINtskTmiGrhleXQOX3gm0M-KV1qHePbv1q9gnFyV74uY0-4SzsVO0kH47qAnodYAyMpEcpWkea0l3uowbrxiwO4eMaVPc4okuEIkW6aOu8kY0HwdjiUzIH_uO4g4NYHx3WIQrqoy3GkmQI6xR5gZAoLrn2-Phm5jLJXxJFKjM2hQn_2QgAFLVOa59MtZ7hGdHkwqaKtu7Baz2trvwcgY921r46qZkq3qTvZdKec8k9-NaaF47guwR15FioNixayXv1v2YSA7WCw34xCAdT8pRqnkW-NefRpQaUDujhtvFtsILnONHaQ"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32779/acme/wire/account/p8KF0TpgS5s74cW93blIwmB2B6kCSD5p",
    "nonce": "MzduR1hEV0NOanMwcmFxSXdhclBEUXZIM1JqM2ZvNlo",
    "typ": "JWT",
    "url": "https://stepca:32779/acme/wire/challenge/dDUIkFKarbmJrEzSJnoCrUB1eigdIYzU/TnuonitDxBhrXO2NJpLuzg0ajOHQ9bBs"
  }
}
```
#### 24. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32779/acme/wire/directory>;rel="index"
link: <https://stepca:32779/acme/wire/authz/dDUIkFKarbmJrEzSJnoCrUB1eigdIYzU>;rel="up"
location: https://stepca:32779/acme/wire/challenge/dDUIkFKarbmJrEzSJnoCrUB1eigdIYzU/TnuonitDxBhrXO2NJpLuzg0ajOHQ9bBs
replay-nonce: UnNMWDZiSEg4eERSZjRXbGQ3ajdzb1UzVXMwYm9Dem4
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32779/acme/wire/challenge/dDUIkFKarbmJrEzSJnoCrUB1eigdIYzU/TnuonitDxBhrXO2NJpLuzg0ajOHQ9bBs",
  "status": "valid",
  "token": "W1FTR9ha78oje4mtuJKoa3nvaM25zbE8",
  "target": "http://keycloak:18398/realms/master"
}
```
### Client presents a CSR and gets its certificate
#### 25. verify the status of the order
```http request
POST https://stepca:32779/acme/wire/order/kkLyGo465YchWw6SdaO2Hnpk46CmxYPQ
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzc5L2FjbWUvd2lyZS9hY2NvdW50L3A4S0YwVHBnUzVzNzRjVzkzYmxJd21CMkI2a0NTRDVwIiwidHlwIjoiSldUIiwibm9uY2UiOiJVbk5NV0RaaVNFZzRlRVJTWmpSWGJHUTNhamR6YjFVelZYTXdZbTlEZW00IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzkvYWNtZS93aXJlL29yZGVyL2trTHlHbzQ2NVljaFd3NlNkYU8ySG5wazQ2Q214WVBRIn0",
  "payload": "",
  "signature": "TAoyLEbJ5_ISC-oqPG2KliuPyJ0yOCV5W16lAPORroln8Kc4oFq8K5yHpjdO7xfihkkAqGuFAqQ2TLC6_7z5Ag"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32779/acme/wire/account/p8KF0TpgS5s74cW93blIwmB2B6kCSD5p",
    "nonce": "UnNMWDZiSEg4eERSZjRXbGQ3ajdzb1UzVXMwYm9Dem4",
    "typ": "JWT",
    "url": "https://stepca:32779/acme/wire/order/kkLyGo465YchWw6SdaO2Hnpk46CmxYPQ"
  }
}
```
#### 26. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32779/acme/wire/directory>;rel="index"
location: https://stepca:32779/acme/wire/order/kkLyGo465YchWw6SdaO2Hnpk46CmxYPQ
replay-nonce: dlFWQ0ptRVpHVmdtRWFjMGRhM3cxdDB2NmExM1NrTmk
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32779/acme/wire/order/kkLyGo465YchWw6SdaO2Hnpk46CmxYPQ/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://Q0bg9PWCTZetW1YfSAKCxw!a5e43f34510177a6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32779/acme/wire/authz/OkCx2A56RIDYnkstTOf3hqCS79tgK8rQ",
    "https://stepca:32779/acme/wire/authz/dDUIkFKarbmJrEzSJnoCrUB1eigdIYzU"
  ],
  "expires": "2024-03-29T08:57:01Z",
  "notBefore": "2024-03-28T08:57:01.977412Z",
  "notAfter": "2034-03-26T08:57:01.977412Z"
}
```
#### 27. create a CSR and call finalize url
```http request
POST https://stepca:32779/acme/wire/order/kkLyGo465YchWw6SdaO2Hnpk46CmxYPQ/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzc5L2FjbWUvd2lyZS9hY2NvdW50L3A4S0YwVHBnUzVzNzRjVzkzYmxJd21CMkI2a0NTRDVwIiwidHlwIjoiSldUIiwibm9uY2UiOiJkbEZXUTBwdFJWcEhWbWR0UldGak1HUmhNM2N4ZERCMk5tRXhNMU5yVG1rIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzkvYWNtZS93aXJlL29yZGVyL2trTHlHbzQ2NVljaFd3NlNkYU8ySG5wazQ2Q214WVBRL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCS3pDQjNnSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBRFlnOFJoMnFZUnBEY2d1ZXVqX28zcnZUYkNZQzBCbXhrYW1HbXdxbzVEd29Ib3dlQVlKS29aSWh2Y05BUWtPTVdzd2FUQm5CZ05WSFJFRVlEQmVoanAzYVhKbFlYQndPaTh2VVRCaVp6bFFWME5VV21WMFZ6RlpabE5CUzBONGR5RmhOV1UwTTJZek5EVXhNREUzTjJFMlFIZHBjbVV1WTI5dGhpQjNhWEpsWVhCd09pOHZKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlRBRkJnTXJaWEFEUVFBeG1tSUZOMWd2Vk54NHZPTEF3bjB6SDE0b1M1cHpFdTQ1VS1PcnlyRjVjRzBoNXZGS2R2NjVlbnVaRjNXcVBwZk1zNnlBZkxoYmJpVlRQS2s0b1BrQSJ9",
  "signature": "8cHC6qU0R_H__9PoFWCz6gEvfMM5qV0gkil-n_aHNJQ6GSFY2CpuE6nssrrezK05VhIvdR1cwe8Us9e4nJFPCA"
}
```
```json
{
  "payload": {
    "csr": "MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhADYg8Rh2qYRpDcgueuj_o3rvTbCYC0BmxkamGmwqo5DwoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBwOi8vUTBiZzlQV0NUWmV0VzFZZlNBS0N4dyFhNWU0M2YzNDUxMDE3N2E2QHdpcmUuY29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQAxmmIFN1gvVNx4vOLAwn0zH14oS5pzEu45U-OryrF5cG0h5vFKdv65enuZF3WqPpfMs6yAfLhbbiVTPKk4oPkA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32779/acme/wire/account/p8KF0TpgS5s74cW93blIwmB2B6kCSD5p",
    "nonce": "dlFWQ0ptRVpHVmdtRWFjMGRhM3cxdDB2NmExM1NrTmk",
    "typ": "JWT",
    "url": "https://stepca:32779/acme/wire/order/kkLyGo465YchWw6SdaO2Hnpk46CmxYPQ/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhADYg8Rh2qYRpDcgueuj/o3rvTbCYC0Bm
xkamGmwqo5DwoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBw
Oi8vUTBiZzlQV0NUWmV0VzFZZlNBS0N4dyFhNWU0M2YzNDUxMDE3N2E2QHdpcmUu
Y29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQAx
mmIFN1gvVNx4vOLAwn0zH14oS5pzEu45U+OryrF5cG0h5vFKdv65enuZF3WqPpfM
s6yAfLhbbiVTPKk4oPkA
-----END CERTIFICATE REQUEST-----

```
```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O=wire.com, 2.16.840.1.113730.3.1.241=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    36:20:f1:18:76:a9:84:69:0d:c8:2e:7a:e8:ff:a3:
                    7a:ef:4d:b0:98:0b:40:66:c6:46:a6:1a:6c:2a:a3:
                    90:f0
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:wireapp://Q0bg9PWCTZetW1YfSAKCxw!a5e43f34510177a6@wire.com, URI:wireapp://%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        31:9a:62:05:37:58:2f:54:dc:78:bc:e2:c0:c2:7d:33:1f:5e:
        28:4b:9a:73:12:ee:39:53:e3:ab:ca:b1:79:70:6d:21:e6:f1:
        4a:76:fe:b9:7a:7b:99:17:75:aa:3e:97:cc:b3:ac:80:7c:b8:
        5b:6e:25:53:3c:a9:38:a0:f9:00

```

#### 28. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32779/acme/wire/directory>;rel="index"
location: https://stepca:32779/acme/wire/order/kkLyGo465YchWw6SdaO2Hnpk46CmxYPQ
replay-nonce: Rm9Dem8ycndDZWdYQU9pc29wb0RyOW8xYWwyVXV6QTY
```
```json
{
  "certificate": "https://stepca:32779/acme/wire/certificate/bZwcNOGlfXsZHmyf1xgh46pTMoau6iEd",
  "status": "valid",
  "finalize": "https://stepca:32779/acme/wire/order/kkLyGo465YchWw6SdaO2Hnpk46CmxYPQ/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://Q0bg9PWCTZetW1YfSAKCxw!a5e43f34510177a6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32779/acme/wire/authz/OkCx2A56RIDYnkstTOf3hqCS79tgK8rQ",
    "https://stepca:32779/acme/wire/authz/dDUIkFKarbmJrEzSJnoCrUB1eigdIYzU"
  ],
  "expires": "2024-03-29T08:57:01Z",
  "notBefore": "2024-03-28T08:57:01.977412Z",
  "notAfter": "2034-03-26T08:57:01.977412Z"
}
```
#### 29. fetch the certificate
```http request
POST https://stepca:32779/acme/wire/certificate/bZwcNOGlfXsZHmyf1xgh46pTMoau6iEd
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzc5L2FjbWUvd2lyZS9hY2NvdW50L3A4S0YwVHBnUzVzNzRjVzkzYmxJd21CMkI2a0NTRDVwIiwidHlwIjoiSldUIiwibm9uY2UiOiJSbTlEZW04eWNuZERaV2RZUVU5cGMyOXdiMFJ5T1c4eFlXd3lWWFY2UVRZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzkvYWNtZS93aXJlL2NlcnRpZmljYXRlL2Jad2NOT0dsZlhzWkhteWYxeGdoNDZwVE1vYXU2aUVkIn0",
  "payload": "",
  "signature": "fhR3Bcbg3eH3FOPGtw10vuXuTutgjTlpTNT6ykjg-eHv106vqsOyZs3Q33zpMzw4OayG7mm5zxA_DBDtvaMcAQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32779/acme/wire/account/p8KF0TpgS5s74cW93blIwmB2B6kCSD5p",
    "nonce": "Rm9Dem8ycndDZWdYQU9pc29wb0RyOW8xYWwyVXV6QTY",
    "typ": "JWT",
    "url": "https://stepca:32779/acme/wire/certificate/bZwcNOGlfXsZHmyf1xgh46pTMoau6iEd"
  }
}
```
#### 30. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32779/acme/wire/directory>;rel="index"
replay-nonce: cGVIcGh3YUN1MW45Y2NUYWVBY0xXZkpWYUduVGFQZFk
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGzCCAcCgAwIBAgIRAMGwnRDpnmOmAU/0kOHiZ64wCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjQwMzI4MDg1NzAxWhcNMzQwMzI2MDg1NzAxWjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQA2IPEYdqmEaQ3ILnro\n/6N6702wmAtAZsZGphpsKqOQ8KOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l\nBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFFGdTVQJKTBEa9pFSrE0DoHusg7gMB8G\nA1UdIwQYMBaAFCHKdixLYe0oaCPaKFIO3p91y+vCMGkGA1UdEQRiMGCGIHdpcmVh\ncHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vUTBiZzlQV0NU\nWmV0VzFZZlNBS0N4dyUyMWE1ZTQzZjM0NTEwMTc3YTZAd2lyZS5jb20wHQYMKwYB\nBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0kAMEYCIQD3E354\nqCXSIuVGrV83uK1yishEsW/0pzZJ8uB8SjOHRgIhAKxCXAKyn8FKX1JKbsnaiGRo\nKfqao2lHCo3QGALiZnyF\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBtzCCAV6gAwIBAgIQIk4ByEYBqnVuge4ErZMsUTAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMzI4MDg1\nNzAwWhcNMzQwMzI2MDg1NzAwWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGQc\nc5hqT4Z7Ie/o7be0B5d3EYSr39IRYjOKMQmr2cSa7r4z7y4G3S22yR94h431HyAu\ngY0SGwjvoxRX+92h8HCjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBQhynYsS2HtKGgj2ihSDt6fdcvrwjAfBgNVHSMEGDAW\ngBRor6K7BvCTzyRiRBX5a9jj1hS41DAKBggqhkjOPQQDAgNHADBEAiAfVJZMvsIk\n1qIMThynr+ilaHAFpEYqIZkx9MaX9veOFgIgF0hTm6eH2Ir1yhnCXqV7UWo4aA/z\nGAmvxBDD4GvwxQI=\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICGzCCAcCgAwIBAgIRAMGwnRDpnmOmAU/0kOHiZ64wCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjQwMzI4MDg1NzAxWhcNMzQwMzI2MDg1NzAxWjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQA2IPEYdqmEaQ3ILnro
/6N6702wmAtAZsZGphpsKqOQ8KOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFFGdTVQJKTBEa9pFSrE0DoHusg7gMB8G
A1UdIwQYMBaAFCHKdixLYe0oaCPaKFIO3p91y+vCMGkGA1UdEQRiMGCGIHdpcmVh
cHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vUTBiZzlQV0NU
WmV0VzFZZlNBS0N4dyUyMWE1ZTQzZjM0NTEwMTc3YTZAd2lyZS5jb20wHQYMKwYB
BAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0kAMEYCIQD3E354
qCXSIuVGrV83uK1yishEsW/0pzZJ8uB8SjOHRgIhAKxCXAKyn8FKX1JKbsnaiGRo
Kfqao2lHCo3QGALiZnyF
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            c1:b0:9d:10:e9:9e:63:a6:01:4f:f4:90:e1:e2:67:ae
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Intermediate CA
        Validity
            Not Before: Mar 28 08:57:01 2024 GMT
            Not After : Mar 26 08:57:01 2034 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    36:20:f1:18:76:a9:84:69:0d:c8:2e:7a:e8:ff:a3:
                    7a:ef:4d:b0:98:0b:40:66:c6:46:a6:1a:6c:2a:a3:
                    90:f0
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                51:9D:4D:54:09:29:30:44:6B:DA:45:4A:B1:34:0E:81:EE:B2:0E:E0
            X509v3 Authority Key Identifier: 
                21:CA:76:2C:4B:61:ED:28:68:23:DA:28:52:0E:DE:9F:75:CB:EB:C2
            X509v3 Subject Alternative Name: 
                URI:wireapp://%40alice_wire@wire.com, URI:wireapp://Q0bg9PWCTZetW1YfSAKCxw%21a5e43f34510177a6@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:f7:13:7e:78:a8:25:d2:22:e5:46:ad:5f:37:
        b8:ad:72:8a:c8:44:b1:6f:f4:a7:36:49:f2:e0:7c:4a:33:87:
        46:02:21:00:ac:42:5c:02:b2:9f:c1:4a:5f:52:4a:6e:c9:da:
        88:64:68:29:fa:9a:a3:69:47:0a:8d:d0:18:02:e2:66:7c:85

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIBtzCCAV6gAwIBAgIQIk4ByEYBqnVuge4ErZMsUTAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMzI4MDg1
NzAwWhcNMzQwMzI2MDg1NzAwWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGQc
c5hqT4Z7Ie/o7be0B5d3EYSr39IRYjOKMQmr2cSa7r4z7y4G3S22yR94h431HyAu
gY0SGwjvoxRX+92h8HCjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBQhynYsS2HtKGgj2ihSDt6fdcvrwjAfBgNVHSMEGDAW
gBRor6K7BvCTzyRiRBX5a9jj1hS41DAKBggqhkjOPQQDAgNHADBEAiAfVJZMvsIk
1qIMThynr+ilaHAFpEYqIZkx9MaX9veOFgIgF0hTm6eH2Ir1yhnCXqV7UWo4aA/z
GAmvxBDD4GvwxQI=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            22:4e:01:c8:46:01:aa:75:6e:81:ee:04:ad:93:2c:51
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Mar 28 08:57:00 2024 GMT
            Not After : Mar 26 08:57:00 2034 GMT
        Subject: O=wire, CN=wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:64:1c:73:98:6a:4f:86:7b:21:ef:e8:ed:b7:b4:
                    07:97:77:11:84:ab:df:d2:11:62:33:8a:31:09:ab:
                    d9:c4:9a:ee:be:33:ef:2e:06:dd:2d:b6:c9:1f:78:
                    87:8d:f5:1f:20:2e:81:8d:12:1b:08:ef:a3:14:57:
                    fb:dd:a1:f0:70
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                21:CA:76:2C:4B:61:ED:28:68:23:DA:28:52:0E:DE:9F:75:CB:EB:C2
            X509v3 Authority Key Identifier: 
                68:AF:A2:BB:06:F0:93:CF:24:62:44:15:F9:6B:D8:E3:D6:14:B8:D4
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:1f:54:96:4c:be:c2:24:d6:a2:0c:4e:1c:a7:af:
        e8:a5:68:70:05:a4:46:2a:21:99:31:f4:c6:97:f6:f7:8e:16:
        02:20:17:48:53:9b:a7:87:d8:8a:f5:ca:19:c2:5e:a5:7b:51:
        6a:38:68:0f:f3:18:09:af:c4:10:c3:e0:6b:f0:c5:02

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBkDCCATagAwIBAgIRAJHfeUN8vCGAV+jju/OcuyIwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDMyODA4
NTY1OVoXDTM0MDMyNjA4NTY1OVowJjENMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMM
d2lyZSBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4kw2VB/oPFBi
LgRLRz0AWZHAGmDhdUZ9XIYLe119E2/5//BIQIZPku8eBkTYQ87H69pn5sh33sXy
RMNcGIEnuqNFMEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEw
HQYDVR0OBBYEFGivorsG8JPPJGJEFflr2OPWFLjUMAoGCCqGSM49BAMCA0gAMEUC
IC6ZzQIKka2RIwfn5/6QKIjC5fH3fKg1lWkB4/P9xbEcAiEAjaFJqQfIV+CEHMlU
j2izyPVHL9m6jazFaddYv3k8iSo=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            91:df:79:43:7c:bc:21:80:57:e8:e3:bb:f3:9c:bb:22
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Mar 28 08:56:59 2024 GMT
            Not After : Mar 26 08:56:59 2034 GMT
        Subject: O=wire, CN=wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:e2:4c:36:54:1f:e8:3c:50:62:2e:04:4b:47:3d:
                    00:59:91:c0:1a:60:e1:75:46:7d:5c:86:0b:7b:5d:
                    7d:13:6f:f9:ff:f0:48:40:86:4f:92:ef:1e:06:44:
                    d8:43:ce:c7:eb:da:67:e6:c8:77:de:c5:f2:44:c3:
                    5c:18:81:27:ba
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                68:AF:A2:BB:06:F0:93:CF:24:62:44:15:F9:6B:D8:E3:D6:14:B8:D4
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:2e:99:cd:02:0a:91:ad:91:23:07:e7:e7:fe:90:
        28:88:c2:e5:f1:f7:7c:a8:35:95:69:01:e3:f3:fd:c5:b1:1c:
        02:21:00:8d:a1:49:a9:07:c8:57:e0:84:1c:c9:54:8f:68:b3:
        c8:f5:47:2f:d9:ba:8d:ac:c5:69:d7:58:bf:79:3c:89:2a

```

openssl verify chain ✅