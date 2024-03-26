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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/33y8eTP1jgI5pwuOxZvh9F0ZlK9gW50u
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/6v5MnzQwBvPXGcEfetxPPprCqBsbIKnH
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/f92c673e9c08f466/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/33y8eTP1jgI5pwuOxZvh9F0ZlK9gW50u/ejv5BlYMH0giREM4QAoTmzgwQb74cjEO
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /realms/master/protocol/openid-connect/auth
    IdP->>-wire-client: 200
    wire-client->>+IdP:  POST /realms/master/protocol/openid-connect/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/6v5MnzQwBvPXGcEfetxPPprCqBsbIKnH/YuhltIGhveq9nXh0NTv9qQ4PbKR7BvLH
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/iq3FmbOOTm51xcQ2piXHYXey2A40r4Wb
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/iq3FmbOOTm51xcQ2piXHYXey2A40r4Wb/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/RvlWlX6SCRKfRLZfA8DMlHCBzqXKcELQ
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32769/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:32769/acme/wire/new-nonce",
  "newAccount": "https://stepca:32769/acme/wire/new-account",
  "newOrder": "https://stepca:32769/acme/wire/new-order",
  "revokeCert": "https://stepca:32769/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32769/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32769/acme/wire/directory>;rel="index"
replay-nonce: YzE4aGticVhzZGNGN2ttcGZjbG1LcXNpWkUwSDdtY2s
```
```text
YzE4aGticVhzZGNGN2ttcGZjbG1LcXNpWkUwSDdtY2s
```
#### 5. create a new account
```http request
POST https://stepca:32769/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkU4WnZ5a3ZTZTI5RWJKaEdidzYzWW5kNEF6dDBoSGdqTEUtRTJLcDFud3MifSwibm9uY2UiOiJZekU0YUd0aWNWaHpaR05HTjJ0dGNHWmpiRzFMY1hOcFdrVXdTRGR0WTJzIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NjkvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "lf14B_pLMaMCcubySVgJjbxPjIgcpzyF9eFfoNmJllArvOi1Ec7Sa9f5HwZ_6AKK16qJa_oeZCxhvt7c-Ug7CQ"
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
      "x": "E8ZvykvSe29EbJhGbw63Ynd4Azt0hHgjLE-E2Kp1nws"
    },
    "nonce": "YzE4aGticVhzZGNGN2ttcGZjbG1LcXNpWkUwSDdtY2s",
    "typ": "JWT",
    "url": "https://stepca:32769/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32769/acme/wire/directory>;rel="index"
location: https://stepca:32769/acme/wire/account/3kfBFcBcMxFDR1dHrQk8RgAPcPX8CSYP
replay-nonce: Zk1iZjFZdllPZERXb2ptNGxhTGR4ZDQ2aVk3VFY3Nk4
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32769/acme/wire/account/3kfBFcBcMxFDR1dHrQk8RgAPcPX8CSYP/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32769/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzY5L2FjbWUvd2lyZS9hY2NvdW50LzNrZkJGY0JjTXhGRFIxZEhyUWs4UmdBUGNQWDhDU1lQIiwidHlwIjoiSldUIiwibm9uY2UiOiJaazFpWmpGWmRsbFBaRVJYYjJwdE5HeGhUR1I0WkRRMmFWazNWRlkzTms0IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NjkvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtZGV2aWNlIiwidmFsdWUiOiJ7XCJjbGllbnQtaWRcIjpcIndpcmVhcHA6Ly9sWVBNTWh4bFF5aUpIZzdmMFg0dFRnIWY5MmM2NzNlOWMwOGY0NjZAd2lyZS5jb21cIixcImhhbmRsZVwiOlwid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb21cIixcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCJ9In0seyJ0eXBlIjoid2lyZWFwcC11c2VyIiwidmFsdWUiOiJ7XCJoYW5kbGVcIjpcIndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tXCIsXCJuYW1lXCI6XCJBbGljZSBTbWl0aFwiLFwiZG9tYWluXCI6XCJ3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyNC0wMy0yNlQxMTowMzozMi44MzUxNzJaIiwibm90QWZ0ZXIiOiIyMDM0LTAzLTI0VDExOjAzOjMyLjgzNTE3MloifQ",
  "signature": "WaPLvCh2KlGpzCGuH987ffLXejhy72cbndE_Ww0T-yKgBMUXZ9UTAnGBZVRMTP0c1Je-4yc0uUXKSw-cxATZDQ"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-device",
        "value": "{\"client-id\":\"wireapp://lYPMMhxlQyiJHg7f0X4tTg!f92c673e9c08f466@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      },
      {
        "type": "wireapp-user",
        "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      }
    ],
    "notAfter": "2034-03-24T11:03:32.835172Z",
    "notBefore": "2024-03-26T11:03:32.835172Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32769/acme/wire/account/3kfBFcBcMxFDR1dHrQk8RgAPcPX8CSYP",
    "nonce": "Zk1iZjFZdllPZERXb2ptNGxhTGR4ZDQ2aVk3VFY3Nk4",
    "typ": "JWT",
    "url": "https://stepca:32769/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32769/acme/wire/directory>;rel="index"
location: https://stepca:32769/acme/wire/order/iq3FmbOOTm51xcQ2piXHYXey2A40r4Wb
replay-nonce: RUwzcURjeVl3cGdJZThZOEp4R2g0NVcwdlRza2lyTDY
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32769/acme/wire/order/iq3FmbOOTm51xcQ2piXHYXey2A40r4Wb/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://lYPMMhxlQyiJHg7f0X4tTg!f92c673e9c08f466@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32769/acme/wire/authz/33y8eTP1jgI5pwuOxZvh9F0ZlK9gW50u",
    "https://stepca:32769/acme/wire/authz/6v5MnzQwBvPXGcEfetxPPprCqBsbIKnH"
  ],
  "expires": "2024-03-27T11:03:32Z",
  "notBefore": "2024-03-26T11:03:32.835172Z",
  "notAfter": "2034-03-24T11:03:32.835172Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32769/acme/wire/authz/33y8eTP1jgI5pwuOxZvh9F0ZlK9gW50u
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzY5L2FjbWUvd2lyZS9hY2NvdW50LzNrZkJGY0JjTXhGRFIxZEhyUWs4UmdBUGNQWDhDU1lQIiwidHlwIjoiSldUIiwibm9uY2UiOiJSVXd6Y1VSamVWbDNjR2RKWlRoWk9FcDRSMmcwTlZjd2RsUnphMmx5VERZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NjkvYWNtZS93aXJlL2F1dGh6LzMzeThlVFAxamdJNXB3dU94WnZoOUYwWmxLOWdXNTB1In0",
  "payload": "",
  "signature": "ZuMbmfxQ3Gc3ZQ0VPgERwFqrHm-WO9JWsp6aivX4omAhEPWHX2hrOITUq3zaemNV0BKIFKFkFo-uw6iQXUc9BA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32769/acme/wire/account/3kfBFcBcMxFDR1dHrQk8RgAPcPX8CSYP",
    "nonce": "RUwzcURjeVl3cGdJZThZOEp4R2g0NVcwdlRza2lyTDY",
    "typ": "JWT",
    "url": "https://stepca:32769/acme/wire/authz/33y8eTP1jgI5pwuOxZvh9F0ZlK9gW50u"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32769/acme/wire/directory>;rel="index"
location: https://stepca:32769/acme/wire/authz/33y8eTP1jgI5pwuOxZvh9F0ZlK9gW50u
replay-nonce: bDI1S1NoV1JQOEtXMWRGUUFNUTBRTlE4TTczQjNjVzg
```
```json
{
  "status": "pending",
  "expires": "2024-03-27T11:03:32Z",
  "challenges": [
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32769/acme/wire/challenge/33y8eTP1jgI5pwuOxZvh9F0ZlK9gW50u/ejv5BlYMH0giREM4QAoTmzgwQb74cjEO",
      "status": "pending",
      "token": "HR0bDdgr1UogAnadpfULdy7UqtCpxkeQ",
      "target": "http://wire.com:18930/clients/f92c673e9c08f466/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-device",
    "value": "{\"client-id\":\"wireapp://lYPMMhxlQyiJHg7f0X4tTg!f92c673e9c08f466@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
  }
}
```
```http request
POST https://stepca:32769/acme/wire/authz/6v5MnzQwBvPXGcEfetxPPprCqBsbIKnH
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzY5L2FjbWUvd2lyZS9hY2NvdW50LzNrZkJGY0JjTXhGRFIxZEhyUWs4UmdBUGNQWDhDU1lQIiwidHlwIjoiSldUIiwibm9uY2UiOiJiREkxUzFOb1YxSlFPRXRYTVdSR1VVRk5VVEJSVGxFNFRUY3pRak5qVnpnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NjkvYWNtZS93aXJlL2F1dGh6LzZ2NU1uelF3QnZQWEdjRWZldHhQUHByQ3FCc2JJS25IIn0",
  "payload": "",
  "signature": "tdz0W9taS8FqWpVn4HxfsjRZbTnwRL6maZTMWJ7DwJXiYb29GkFuRuRVcZCW1oe5tXtvvd4VKF-u4aGSntUzCw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32769/acme/wire/account/3kfBFcBcMxFDR1dHrQk8RgAPcPX8CSYP",
    "nonce": "bDI1S1NoV1JQOEtXMWRGUUFNUTBRTlE4TTczQjNjVzg",
    "typ": "JWT",
    "url": "https://stepca:32769/acme/wire/authz/6v5MnzQwBvPXGcEfetxPPprCqBsbIKnH"
  }
}
```
#### 11. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32769/acme/wire/directory>;rel="index"
location: https://stepca:32769/acme/wire/authz/6v5MnzQwBvPXGcEfetxPPprCqBsbIKnH
replay-nonce: aXZFeFZDckYwRFNhVE5zaUpCc2VNSEtVUW92cGw4ZW0
```
```json
{
  "status": "pending",
  "expires": "2024-03-27T11:03:32Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32769/acme/wire/challenge/6v5MnzQwBvPXGcEfetxPPprCqBsbIKnH/YuhltIGhveq9nXh0NTv9qQ4PbKR7BvLH",
      "status": "pending",
      "token": "pLyGqtnqFdeFtp3AtXYW2EI99DI5Sqmc",
      "target": "http://keycloak:15955/realms/master"
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
GET http://wire.com:18930/clients/token/nonce
```
#### 13. get wire-server nonce
```http request
200

```
```text
cmV6OHM3eFFxWkVYMUQ0ZDF4Wm5sN1FwQTlqaFVUMTI
```
#### 14. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiRThadnlrdlNlMjlFYkpoR2J3NjNZbmQ0QXp0MGhIZ2pMRS1FMktwMW53cyJ9fQ.eyJpYXQiOjE3MTE0NDc0MTIsImV4cCI6MTcxMTQ1NDYxMiwibmJmIjoxNzExNDQ3NDEyLCJzdWIiOiJ3aXJlYXBwOi8vbFlQTU1oeGxReWlKSGc3ZjBYNHRUZyFmOTJjNjczZTljMDhmNDY2QHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NjkvYWNtZS93aXJlL2NoYWxsZW5nZS8zM3k4ZVRQMWpnSTVwd3VPeFp2aDlGMFpsSzlnVzUwdS9lanY1QmxZTUgwZ2lSRU00UUFvVG16Z3dRYjc0Y2pFTyIsImp0aSI6IjBmMzMxNmQ5LThkZWQtNDNmMy05N2ExLTFlNDdiZmNiYTdiZCIsIm5vbmNlIjoiY21WNk9ITTNlRkZ4V2tWWU1VUTBaREY0V201c04xRndRVGxxYUZWVU1USSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MTg5MzAvY2xpZW50cy9mOTJjNjczZTljMDhmNDY2L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJIUjBiRGRncjFVb2dBbmFkcGZVTGR5N1VxdENweGtlUSIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUiLCJuYW1lIjoiQWxpY2UgU21pdGgifQ.GB0Jzt3NL6ZRqkMlmrqePUY2DeYd6uxJ8ZBGS2K2A8TRypXEfKs0ReBvBMYtZgZJSyERaiGtppBSYQX3c07cDw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiRThadnlrdlNlMjlFYkpoR2J3NjNZbmQ0
QXp0MGhIZ2pMRS1FMktwMW53cyJ9fQ.eyJpYXQiOjE3MTE0NDc0MTIsImV4cCI6M
TcxMTQ1NDYxMiwibmJmIjoxNzExNDQ3NDEyLCJzdWIiOiJ3aXJlYXBwOi8vbFlQT
U1oeGxReWlKSGc3ZjBYNHRUZyFmOTJjNjczZTljMDhmNDY2QHdpcmUuY29tIiwiY
XVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NjkvYWNtZS93aXJlL2NoYWxsZW5nZS8zM
3k4ZVRQMWpnSTVwd3VPeFp2aDlGMFpsSzlnVzUwdS9lanY1QmxZTUgwZ2lSRU00U
UFvVG16Z3dRYjc0Y2pFTyIsImp0aSI6IjBmMzMxNmQ5LThkZWQtNDNmMy05N2ExL
TFlNDdiZmNiYTdiZCIsIm5vbmNlIjoiY21WNk9ITTNlRkZ4V2tWWU1VUTBaREY0V
201c04xRndRVGxxYUZWVU1USSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd
2lyZS5jb206MTg5MzAvY2xpZW50cy9mOTJjNjczZTljMDhmNDY2L2FjY2Vzcy10b
2tlbiIsImNoYWwiOiJIUjBiRGRncjFVb2dBbmFkcGZVTGR5N1VxdENweGtlUSIsI
mhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhb
SI6IndpcmUiLCJuYW1lIjoiQWxpY2UgU21pdGgifQ.GB0Jzt3NL6ZRqkMlmrqePU
Y2DeYd6uxJ8ZBGS2K2A8TRypXEfKs0ReBvBMYtZgZJSyERaiGtppBSYQX3c07cDw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "E8ZvykvSe29EbJhGbw63Ynd4Azt0hHgjLE-E2Kp1nws"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "aud": "https://stepca:32769/acme/wire/challenge/33y8eTP1jgI5pwuOxZvh9F0ZlK9gW50u/ejv5BlYMH0giREM4QAoTmzgwQb74cjEO",
  "chal": "HR0bDdgr1UogAnadpfULdy7UqtCpxkeQ",
  "exp": 1711454612,
  "handle": "wireapp://%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:18930/clients/f92c673e9c08f466/access-token",
  "iat": 1711447412,
  "jti": "0f3316d9-8ded-43f3-97a1-1e47bfcba7bd",
  "name": "Alice Smith",
  "nbf": 1711447412,
  "nonce": "cmV6OHM3eFFxWkVYMUQ0ZDF4Wm5sN1FwQTlqaFVUMTI",
  "sub": "wireapp://lYPMMhxlQyiJHg7f0X4tTg!f92c673e9c08f466@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIVTs9rOcUJhQJegmnLR8QNpBdR52rlcBykbOxY1cMMe
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAE8ZvykvSe29EbJhGbw63Ynd4Azt0hHgjLE+E2Kp1nws=
-----END PUBLIC KEY-----
```

</details>


#### 15. trade client DPoP token for an access token
```http request
POST http://wire.com:18930/clients/f92c673e9c08f466/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pUlRoYWRubHJkbE5sTWpsRllrcG9SMkozTmpOWmJtUTBRWHAwTUdoSVoycE1SUzFGTWt0d01XNTNjeUo5ZlEuZXlKcFlYUWlPakUzTVRFME5EYzBNVElzSW1WNGNDSTZNVGN4TVRRMU5EWXhNaXdpYm1KbUlqb3hOekV4TkRRM05ERXlMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZiRmxRVFUxb2VHeFJlV2xLU0djM1pqQllOSFJVWnlGbU9USmpOamN6WlRsak1EaG1ORFkyUUhkcGNtVXVZMjl0SWl3aVlYVmtJam9pYUhSMGNITTZMeTl6ZEdWd1kyRTZNekkzTmprdllXTnRaUzkzYVhKbEwyTm9ZV3hzWlc1blpTOHpNM2s0WlZSUU1XcG5TVFZ3ZDNWUGVGcDJhRGxHTUZwc1N6bG5WelV3ZFM5bGFuWTFRbXhaVFVnd1oybFNSVTAwVVVGdlZHMTZaM2RSWWpjMFkycEZUeUlzSW1wMGFTSTZJakJtTXpNeE5tUTVMVGhrWldRdE5ETm1NeTA1TjJFeExURmxORGRpWm1OaVlUZGlaQ0lzSW01dmJtTmxJam9pWTIxV05rOUlUVE5sUmtaNFYydFdXVTFWVVRCYVJFWTBWMjAxYzA0eFJuZFJWR3h4WVVaV1ZVMVVTU0lzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRnNU16QXZZMnhwWlc1MGN5OW1PVEpqTmpjelpUbGpNRGhtTkRZMkwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUpJVWpCaVJHUm5jakZWYjJkQmJtRmtjR1pWVEdSNU4xVnhkRU53ZUd0bFVTSXNJbWhoYm1Sc1pTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2lkR1ZoYlNJNkluZHBjbVVpTENKdVlXMWxJam9pUVd4cFkyVWdVMjFwZEdnaWZRLkdCMEp6dDNOTDZaUnFrTWxtcnFlUFVZMkRlWWQ2dXhKOFpCR1MySzJBOFRSeXBYRWZLczBSZUJ2Qk1ZdFpnWkpTeUVSYWlHdHBwQlNZUVgzYzA3Y0R3
```
#### 16. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlZOZFFxVkZPQUEtWnhwRHRKR1N0aFR4NlFhY19ySGc0YU1qVmpVb2tWRm8ifX0.eyJpYXQiOjE3MTE0NDc0MTIsImV4cCI6MTcxMTQ1MTM3MiwibmJmIjoxNzExNDQ3NDEyLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTg5MzAvY2xpZW50cy9mOTJjNjczZTljMDhmNDY2L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9sWVBNTWh4bFF5aUpIZzdmMFg0dFRnIWY5MmM2NzNlOWMwOGY0NjZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjc2OS9hY21lL3dpcmUvY2hhbGxlbmdlLzMzeThlVFAxamdJNXB3dU94WnZoOUYwWmxLOWdXNTB1L2VqdjVCbFlNSDBnaVJFTTRRQW9UbXpnd1FiNzRjakVPIiwianRpIjoiOWQ3YmYzMTMtNjEwMS00YjNmLTk0MjEtYjc3ODRiMzU0NjYxIiwibm9uY2UiOiJjbVY2T0hNM2VGRnhXa1ZZTVVRMFpERjRXbTVzTjFGd1FUbHFhRlZVTVRJIiwiY2hhbCI6IkhSMGJEZGdyMVVvZ0FuYWRwZlVMZHk3VXF0Q3B4a2VRIiwiY25mIjp7ImtpZCI6IjJrUTVYMnV0WS1jNm1iLXB4WGhkczVyR00ycWQ2X3pxRldZVGs5OFdvWGcifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lSVGhhZG5scmRsTmxNamxGWWtwb1IySjNOak5aYm1RMFFYcDBNR2hJWjJwTVJTMUZNa3R3TVc1M2N5SjlmUS5leUpwWVhRaU9qRTNNVEUwTkRjME1USXNJbVY0Y0NJNk1UY3hNVFExTkRZeE1pd2libUptSWpveE56RXhORFEzTkRFeUxDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dmJGbFFUVTFvZUd4UmVXbEtTR2MzWmpCWU5IUlVaeUZtT1RKak5qY3paVGxqTURobU5EWTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STNOamt2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM4ek0zazRaVlJRTVdwblNUVndkM1ZQZUZwMmFEbEdNRnBzU3psblZ6VXdkUzlsYW5ZMVFteFpUVWd3WjJsU1JVMDBVVUZ2VkcxNlozZFJZamMwWTJwRlR5SXNJbXAwYVNJNklqQm1Nek14Tm1RNUxUaGtaV1F0TkRObU15MDVOMkV4TFRGbE5EZGlabU5pWVRkaVpDSXNJbTV2Ym1ObElqb2lZMjFXTms5SVRUTmxSa1o0VjJ0V1dVMVZVVEJhUkVZMFYyMDFjMDR4Um5kUlZHeHhZVVpXVlUxVVNTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVGc1TXpBdlkyeHBaVzUwY3k5bU9USmpOamN6WlRsak1EaG1ORFkyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSklVakJpUkdSbmNqRlZiMmRCYm1Ga2NHWlZUR1I1TjFWeGRFTndlR3RsVVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlMQ0p1WVcxbElqb2lRV3hwWTJVZ1UyMXBkR2dpZlEuR0IwSnp0M05MNlpScWtNbG1ycWVQVVkyRGVZZDZ1eEo4WkJHUzJLMkE4VFJ5cFhFZktzMFJlQnZCTVl0WmdaSlN5RVJhaUd0cHBCU1lRWDNjMDdjRHciLCJjbGllbnRfaWQiOiJ3aXJlYXBwOi8vbFlQTU1oeGxReWlKSGc3ZjBYNHRUZyFmOTJjNjczZTljMDhmNDY2QHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.gxBS1iWM42xNFJUFk-3PZM-xhyrAxWba6yFTe0FYzJi3b2s4eAAWbmliUOBcQHR4o1XJ-rqP8oMgxgftyzXnDg",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlZOZFFxVkZPQUEtWnhwRHRKR1N0aFR4NlFhY19ySGc0YU1qVmpVb2tWRm8ifX0.eyJpYXQiOjE3MTE0NDc0MTIsImV4cCI6MTcxMTQ1MTM3MiwibmJmIjoxNzExNDQ3NDEyLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTg5MzAvY2xpZW50cy9mOTJjNjczZTljMDhmNDY2L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9sWVBNTWh4bFF5aUpIZzdmMFg0dFRnIWY5MmM2NzNlOWMwOGY0NjZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjc2OS9hY21lL3dpcmUvY2hhbGxlbmdlLzMzeThlVFAxamdJNXB3dU94WnZoOUYwWmxLOWdXNTB1L2VqdjVCbFlNSDBnaVJFTTRRQW9UbXpnd1FiNzRjakVPIiwianRpIjoiOWQ3YmYzMTMtNjEwMS00YjNmLTk0MjEtYjc3ODRiMzU0NjYxIiwibm9uY2UiOiJjbVY2T0hNM2VGRnhXa1ZZTVVRMFpERjRXbTVzTjFGd1FUbHFhRlZVTVRJIiwiY2hhbCI6IkhSMGJEZGdyMVVvZ0FuYWRwZlVMZHk3VXF0Q3B4a2VRIiwiY25mIjp7ImtpZCI6IjJrUTVYMnV0WS1jNm1iLXB4WGhkczVyR00ycWQ2X3pxRldZVGs5OFdvWGcifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lSVGhhZG5scmRsTmxNamxGWWtwb1IySjNOak5aYm1RMFFYcDBNR2hJWjJwTVJTMUZNa3R3TVc1M2N5SjlmUS5leUpwWVhRaU9qRTNNVEUwTkRjME1USXNJbVY0Y0NJNk1UY3hNVFExTkRZeE1pd2libUptSWpveE56RXhORFEzTkRFeUxDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dmJGbFFUVTFvZUd4UmVXbEtTR2MzWmpCWU5IUlVaeUZtT1RKak5qY3paVGxqTURobU5EWTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STNOamt2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM4ek0zazRaVlJRTVdwblNUVndkM1ZQZUZwMmFEbEdNRnBzU3psblZ6VXdkUzlsYW5ZMVFteFpUVWd3WjJsU1JVMDBVVUZ2VkcxNlozZFJZamMwWTJwRlR5SXNJbXAwYVNJNklqQm1Nek14Tm1RNUxUaGtaV1F0TkRObU15MDVOMkV4TFRGbE5EZGlabU5pWVRkaVpDSXNJbTV2Ym1ObElqb2lZMjFXTms5SVRUTmxSa1o0VjJ0V1dVMVZVVEJhUkVZMFYyMDFjMDR4Um5kUlZHeHhZVVpXVlUxVVNTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVGc1TXpBdlkyeHBaVzUwY3k5bU9USmpOamN6WlRsak1EaG1ORFkyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSklVakJpUkdSbmNqRlZiMmRCYm1Ga2NHWlZUR1I1TjFWeGRFTndlR3RsVVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlMQ0p1WVcxbElqb2lRV3hwWTJVZ1UyMXBkR2dpZlEuR0IwSnp0M05MNlpScWtNbG1ycWVQVVkyRGVZZDZ1eEo4WkJHUzJLMkE4VFJ5cFhFZktzMFJlQnZCTVl0WmdaSlN5RVJhaUd0cHBCU1lRWDNjMDdjRHciLCJjbGllbnRfaWQiOiJ3aXJlYXBwOi8vbFlQTU1oeGxReWlKSGc3ZjBYNHRUZyFmOTJjNjczZTljMDhmNDY2QHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.gxBS1iWM42xNFJUFk-3PZM-xhyrAxWba6yFTe0FYzJi3b2s4eAAWbmliUOBcQHR4o1XJ-rqP8oMgxgftyzXnDg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6IlZOZFFxVkZPQUEtWnhwRHRKR1N0aFR4NlFh
Y19ySGc0YU1qVmpVb2tWRm8ifX0.eyJpYXQiOjE3MTE0NDc0MTIsImV4cCI6MTcx
MTQ1MTM3MiwibmJmIjoxNzExNDQ3NDEyLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MTg5MzAvY2xpZW50cy9mOTJjNjczZTljMDhmNDY2L2FjY2Vzcy10b2tlbiIsInN1
YiI6IndpcmVhcHA6Ly9sWVBNTWh4bFF5aUpIZzdmMFg0dFRnIWY5MmM2NzNlOWMw
OGY0NjZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjc2OS9hY21l
L3dpcmUvY2hhbGxlbmdlLzMzeThlVFAxamdJNXB3dU94WnZoOUYwWmxLOWdXNTB1
L2VqdjVCbFlNSDBnaVJFTTRRQW9UbXpnd1FiNzRjakVPIiwianRpIjoiOWQ3YmYz
MTMtNjEwMS00YjNmLTk0MjEtYjc3ODRiMzU0NjYxIiwibm9uY2UiOiJjbVY2T0hN
M2VGRnhXa1ZZTVVRMFpERjRXbTVzTjFGd1FUbHFhRlZVTVRJIiwiY2hhbCI6IkhS
MGJEZGdyMVVvZ0FuYWRwZlVMZHk3VXF0Q3B4a2VRIiwiY25mIjp7ImtpZCI6IjJr
UTVYMnV0WS1jNm1iLXB4WGhkczVyR00ycWQ2X3pxRldZVGs5OFdvWGcifSwicHJv
b2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3
aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENK
NElqb2lSVGhhZG5scmRsTmxNamxGWWtwb1IySjNOak5aYm1RMFFYcDBNR2hJWjJw
TVJTMUZNa3R3TVc1M2N5SjlmUS5leUpwWVhRaU9qRTNNVEUwTkRjME1USXNJbVY0
Y0NJNk1UY3hNVFExTkRZeE1pd2libUptSWpveE56RXhORFEzTkRFeUxDSnpkV0lp
T2lKM2FYSmxZWEJ3T2k4dmJGbFFUVTFvZUd4UmVXbEtTR2MzWmpCWU5IUlVaeUZt
T1RKak5qY3paVGxqTURobU5EWTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIw
Y0hNNkx5OXpkR1Z3WTJFNk16STNOamt2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVu
WlM4ek0zazRaVlJRTVdwblNUVndkM1ZQZUZwMmFEbEdNRnBzU3psblZ6VXdkUzls
YW5ZMVFteFpUVWd3WjJsU1JVMDBVVUZ2VkcxNlozZFJZamMwWTJwRlR5SXNJbXAw
YVNJNklqQm1Nek14Tm1RNUxUaGtaV1F0TkRObU15MDVOMkV4TFRGbE5EZGlabU5p
WVRkaVpDSXNJbTV2Ym1ObElqb2lZMjFXTms5SVRUTmxSa1o0VjJ0V1dVMVZVVEJh
UkVZMFYyMDFjMDR4Um5kUlZHeHhZVVpXVlUxVVNTSXNJbWgwYlNJNklsQlBVMVFp
TENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVGc1TXpBdlkyeHBaVzUw
Y3k5bU9USmpOamN6WlRsak1EaG1ORFkyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5v
WVd3aU9pSklVakJpUkdSbmNqRlZiMmRCYm1Ga2NHWlZUR1I1TjFWeGRFTndlR3Rs
VVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEps
UUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlMQ0p1WVcxbElqb2lRV3hw
WTJVZ1UyMXBkR2dpZlEuR0IwSnp0M05MNlpScWtNbG1ycWVQVVkyRGVZZDZ1eEo4
WkJHUzJLMkE4VFJ5cFhFZktzMFJlQnZCTVl0WmdaSlN5RVJhaUd0cHBCU1lRWDNj
MDdjRHciLCJjbGllbnRfaWQiOiJ3aXJlYXBwOi8vbFlQTU1oeGxReWlKSGc3ZjBY
NHRUZyFmOTJjNjczZTljMDhmNDY2QHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUs
InNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.gxBS1iWM42xNFJUFk-3PZM-xhyrAx
Wba6yFTe0FYzJi3b2s4eAAWbmliUOBcQHR4o1XJ-rqP8oMgxgftyzXnDg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "VNdQqVFOAA-ZxpDtJGSthTx6Qac_rHg4aMjVjUokVFo"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "https://stepca:32769/acme/wire/challenge/33y8eTP1jgI5pwuOxZvh9F0ZlK9gW50u/ejv5BlYMH0giREM4QAoTmzgwQb74cjEO",
  "chal": "HR0bDdgr1UogAnadpfULdy7UqtCpxkeQ",
  "client_id": "wireapp://lYPMMhxlQyiJHg7f0X4tTg!f92c673e9c08f466@wire.com",
  "cnf": {
    "kid": "2kQ5X2utY-c6mb-pxXhds5rGM2qd6_zqFWYTk98WoXg"
  },
  "exp": 1711451372,
  "iat": 1711447412,
  "iss": "http://wire.com:18930/clients/f92c673e9c08f466/access-token",
  "jti": "9d7bf313-6101-4b3f-9421-b7784b354661",
  "nbf": 1711447412,
  "nonce": "cmV6OHM3eFFxWkVYMUQ0ZDF4Wm5sN1FwQTlqaFVUMTI",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiRThadnlrdlNlMjlFYkpoR2J3NjNZbmQ0QXp0MGhIZ2pMRS1FMktwMW53cyJ9fQ.eyJpYXQiOjE3MTE0NDc0MTIsImV4cCI6MTcxMTQ1NDYxMiwibmJmIjoxNzExNDQ3NDEyLCJzdWIiOiJ3aXJlYXBwOi8vbFlQTU1oeGxReWlKSGc3ZjBYNHRUZyFmOTJjNjczZTljMDhmNDY2QHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NjkvYWNtZS93aXJlL2NoYWxsZW5nZS8zM3k4ZVRQMWpnSTVwd3VPeFp2aDlGMFpsSzlnVzUwdS9lanY1QmxZTUgwZ2lSRU00UUFvVG16Z3dRYjc0Y2pFTyIsImp0aSI6IjBmMzMxNmQ5LThkZWQtNDNmMy05N2ExLTFlNDdiZmNiYTdiZCIsIm5vbmNlIjoiY21WNk9ITTNlRkZ4V2tWWU1VUTBaREY0V201c04xRndRVGxxYUZWVU1USSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MTg5MzAvY2xpZW50cy9mOTJjNjczZTljMDhmNDY2L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJIUjBiRGRncjFVb2dBbmFkcGZVTGR5N1VxdENweGtlUSIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUiLCJuYW1lIjoiQWxpY2UgU21pdGgifQ.GB0Jzt3NL6ZRqkMlmrqePUY2DeYd6uxJ8ZBGS2K2A8TRypXEfKs0ReBvBMYtZgZJSyERaiGtppBSYQX3c07cDw",
  "scope": "wire_client_id",
  "sub": "wireapp://lYPMMhxlQyiJHg7f0X4tTg!f92c673e9c08f466@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIFy4HhQZ1tlLuKdYKZQb2LxzsZBuJp96Bkawxi4+N1Z1
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAVNdQqVFOAA+ZxpDtJGSthTx6Qac/rHg4aMjVjUokVFo=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 17. validate Dpop challenge (clientId)
```http request
POST https://stepca:32769/acme/wire/challenge/33y8eTP1jgI5pwuOxZvh9F0ZlK9gW50u/ejv5BlYMH0giREM4QAoTmzgwQb74cjEO
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzY5L2FjbWUvd2lyZS9hY2NvdW50LzNrZkJGY0JjTXhGRFIxZEhyUWs4UmdBUGNQWDhDU1lQIiwidHlwIjoiSldUIiwibm9uY2UiOiJhWFpGZUZaRGNrWXdSRk5oVkU1emFVcENjMlZOU0V0VlVXOTJjR3c0WlcwIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NjkvYWNtZS93aXJlL2NoYWxsZW5nZS8zM3k4ZVRQMWpnSTVwd3VPeFp2aDlGMFpsSzlnVzUwdS9lanY1QmxZTUgwZ2lSRU00UUFvVG16Z3dRYjc0Y2pFTyJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklsWk9aRkZ4VmtaUFFVRXRXbmh3UkhSS1IxTjBhRlI0TmxGaFkxOXlTR2MwWVUxcVZtcFZiMnRXUm04aWZYMC5leUpwWVhRaU9qRTNNVEUwTkRjME1USXNJbVY0Y0NJNk1UY3hNVFExTVRNM01pd2libUptSWpveE56RXhORFEzTkRFeUxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRnNU16QXZZMnhwWlc1MGN5OW1PVEpqTmpjelpUbGpNRGhtTkRZMkwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbmRwY21WaGNIQTZMeTlzV1ZCTlRXaDRiRkY1YVVwSVp6ZG1NRmcwZEZSbklXWTVNbU0yTnpObE9XTXdPR1kwTmpaQWQybHlaUzVqYjIwaUxDSmhkV1FpT2lKb2RIUndjem92TDNOMFpYQmpZVG96TWpjMk9TOWhZMjFsTDNkcGNtVXZZMmhoYkd4bGJtZGxMek16ZVRobFZGQXhhbWRKTlhCM2RVOTRXblpvT1VZd1dteExPV2RYTlRCMUwyVnFkalZDYkZsTlNEQm5hVkpGVFRSUlFXOVViWHBuZDFGaU56Umpha1ZQSWl3aWFuUnBJam9pT1dRM1ltWXpNVE10TmpFd01TMDBZak5tTFRrME1qRXRZamMzT0RSaU16VTBOall4SWl3aWJtOXVZMlVpT2lKamJWWTJUMGhOTTJWR1JuaFhhMVpaVFZWUk1GcEVSalJYYlRWelRqRkdkMUZVYkhGaFJsWlZUVlJKSWl3aVkyaGhiQ0k2SWtoU01HSkVaR2R5TVZWdlowRnVZV1J3WmxWTVpIazNWWEYwUTNCNGEyVlJJaXdpWTI1bUlqcDdJbXRwWkNJNklqSnJVVFZZTW5WMFdTMWpObTFpTFhCNFdHaGtjelZ5UjAweWNXUTJYM3B4UmxkWlZHczVPRmR2V0djaWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsU1ZHaGhaRzVzY21Sc1RteE5hbXhHV1d0d2IxSXlTak5PYWs1YVltMVJNRkZZY0RCTlIyaEpXakp3VFZKVE1VWk5hM1IzVFZjMU0yTjVTamxtVVM1bGVVcHdXVmhSYVU5cVJUTk5WRVV3VGtSak1FMVVTWE5KYlZZMFkwTkpOazFVWTNoTlZGRXhUa1JaZUUxcGQybGliVXB0U1dwdmVFNTZSWGhPUkZFelRrUkZlVXhEU25wa1YwbHBUMmxLTTJGWVNteFpXRUozVDJrNGRtSkdiRkZVVlRGdlpVZDRVbVZYYkV0VFIyTXpXbXBDV1U1SVVsVmFlVVp0VDFSS2FrNXFZM3BhVkd4cVRVUm9iVTVFV1RKUlNHUndZMjFWZFZreU9YUkphWGRwV1ZoV2EwbHFiMmxoU0ZJd1kwaE5Oa3g1T1hwa1IxWjNXVEpGTmsxNlNUTk9hbXQyV1ZkT2RGcFRPVE5oV0Vwc1RESk9iMWxYZUhOYVZ6VnVXbE00ZWswemF6UmFWbEpSVFZkd2JsTlVWbmRrTTFaUVpVWndNbUZFYkVkTlJuQnpVM3BzYmxaNlZYZGtVemxzWVc1Wk1WRnRlRnBVVldkM1dqSnNVMUpWTURCVlZVWjJWa2N4TmxvelpGSlphbU13V1RKd1JsUjVTWE5KYlhBd1lWTkpOa2xxUW0xTmVrMTRUbTFSTlV4VWFHdGFWMUYwVGtST2JVMTVNRFZPTWtWNFRGUkdiRTVFWkdsYWJVNXBXVlJrYVZwRFNYTkpiVFYyWW0xT2JFbHFiMmxaTWpGWFRtczVTVlJVVG14U2ExbzBWakowVjFkVk1WWlZWRUpoVWtWWk1GWXlNREZqTURSNFVtNWtVbFpIZUhoWlZWcFhWbFV4VlZOVFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOVkdjMVRYcEJkbGt5ZUhCYVZ6VXdZM2s1YlU5VVNtcE9hbU42V2xSc2FrMUVhRzFPUkZreVRESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTa2xWYWtKcFVrZFNibU5xUmxaaU1tUkNZbTFHYTJOSFdsWlVSMUkxVGpGV2VHUkZUbmRsUjNSc1ZWTkpjMGx0YUdoaWJWSnpXbE5KTmtsdVpIQmpiVlpvWTBoQk5reDVPR3hPUkVKb1lrZHNhbHBXT1ROaFdFcHNVVWhrY0dOdFZYVlpNamwwU1dsM2FXUkhWbWhpVTBrMlNXNWtjR050VldsTVEwcDFXVmN4YkVscWIybFJWM2h3V1RKVloxVXlNWEJrUjJkcFpsRXVSMEl3U25wME0wNU1ObHBTY1d0TmJHMXljV1ZRVlZreVJHVlpaRFoxZUVvNFdrSkhVekpMTWtFNFZGSjVjRmhGWmt0ek1GSmxRblpDVFZsMFdtZGFTbE41UlZKaGFVZDBjSEJDVTFsUldETmpNRGRqUkhjaUxDSmpiR2xsYm5SZmFXUWlPaUozYVhKbFlYQndPaTh2YkZsUVRVMW9lR3hSZVdsS1NHYzNaakJZTkhSVVp5Rm1PVEpqTmpjelpUbGpNRGhtTkRZMlFIZHBjbVV1WTI5dElpd2lZWEJwWDNabGNuTnBiMjRpT2pVc0luTmpiM0JsSWpvaWQybHlaVjlqYkdsbGJuUmZhV1FpZlEuZ3hCUzFpV000MnhORkpVRmstM1BaTS14aHlyQXhXYmE2eUZUZTBGWXpKaTNiMnM0ZUFBV2JtbGlVT0JjUUhSNG8xWEotcnFQOG9NZ3hnZnR5elhuRGcifQ",
  "signature": "TyazpFbodCKFUCWI_FBxDlgSCi9MYhVFThEdrTkKTX1psBeHhc0QPRSZpDsB_Zrr6LmzXDKG-SJIXVSY45xaAg"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlZOZFFxVkZPQUEtWnhwRHRKR1N0aFR4NlFhY19ySGc0YU1qVmpVb2tWRm8ifX0.eyJpYXQiOjE3MTE0NDc0MTIsImV4cCI6MTcxMTQ1MTM3MiwibmJmIjoxNzExNDQ3NDEyLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTg5MzAvY2xpZW50cy9mOTJjNjczZTljMDhmNDY2L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9sWVBNTWh4bFF5aUpIZzdmMFg0dFRnIWY5MmM2NzNlOWMwOGY0NjZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjc2OS9hY21lL3dpcmUvY2hhbGxlbmdlLzMzeThlVFAxamdJNXB3dU94WnZoOUYwWmxLOWdXNTB1L2VqdjVCbFlNSDBnaVJFTTRRQW9UbXpnd1FiNzRjakVPIiwianRpIjoiOWQ3YmYzMTMtNjEwMS00YjNmLTk0MjEtYjc3ODRiMzU0NjYxIiwibm9uY2UiOiJjbVY2T0hNM2VGRnhXa1ZZTVVRMFpERjRXbTVzTjFGd1FUbHFhRlZVTVRJIiwiY2hhbCI6IkhSMGJEZGdyMVVvZ0FuYWRwZlVMZHk3VXF0Q3B4a2VRIiwiY25mIjp7ImtpZCI6IjJrUTVYMnV0WS1jNm1iLXB4WGhkczVyR00ycWQ2X3pxRldZVGs5OFdvWGcifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lSVGhhZG5scmRsTmxNamxGWWtwb1IySjNOak5aYm1RMFFYcDBNR2hJWjJwTVJTMUZNa3R3TVc1M2N5SjlmUS5leUpwWVhRaU9qRTNNVEUwTkRjME1USXNJbVY0Y0NJNk1UY3hNVFExTkRZeE1pd2libUptSWpveE56RXhORFEzTkRFeUxDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dmJGbFFUVTFvZUd4UmVXbEtTR2MzWmpCWU5IUlVaeUZtT1RKak5qY3paVGxqTURobU5EWTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STNOamt2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM4ek0zazRaVlJRTVdwblNUVndkM1ZQZUZwMmFEbEdNRnBzU3psblZ6VXdkUzlsYW5ZMVFteFpUVWd3WjJsU1JVMDBVVUZ2VkcxNlozZFJZamMwWTJwRlR5SXNJbXAwYVNJNklqQm1Nek14Tm1RNUxUaGtaV1F0TkRObU15MDVOMkV4TFRGbE5EZGlabU5pWVRkaVpDSXNJbTV2Ym1ObElqb2lZMjFXTms5SVRUTmxSa1o0VjJ0V1dVMVZVVEJhUkVZMFYyMDFjMDR4Um5kUlZHeHhZVVpXVlUxVVNTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVGc1TXpBdlkyeHBaVzUwY3k5bU9USmpOamN6WlRsak1EaG1ORFkyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSklVakJpUkdSbmNqRlZiMmRCYm1Ga2NHWlZUR1I1TjFWeGRFTndlR3RsVVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlMQ0p1WVcxbElqb2lRV3hwWTJVZ1UyMXBkR2dpZlEuR0IwSnp0M05MNlpScWtNbG1ycWVQVVkyRGVZZDZ1eEo4WkJHUzJLMkE4VFJ5cFhFZktzMFJlQnZCTVl0WmdaSlN5RVJhaUd0cHBCU1lRWDNjMDdjRHciLCJjbGllbnRfaWQiOiJ3aXJlYXBwOi8vbFlQTU1oeGxReWlKSGc3ZjBYNHRUZyFmOTJjNjczZTljMDhmNDY2QHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.gxBS1iWM42xNFJUFk-3PZM-xhyrAxWba6yFTe0FYzJi3b2s4eAAWbmliUOBcQHR4o1XJ-rqP8oMgxgftyzXnDg"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32769/acme/wire/account/3kfBFcBcMxFDR1dHrQk8RgAPcPX8CSYP",
    "nonce": "aXZFeFZDckYwRFNhVE5zaUpCc2VNSEtVUW92cGw4ZW0",
    "typ": "JWT",
    "url": "https://stepca:32769/acme/wire/challenge/33y8eTP1jgI5pwuOxZvh9F0ZlK9gW50u/ejv5BlYMH0giREM4QAoTmzgwQb74cjEO"
  }
}
```
#### 18. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32769/acme/wire/directory>;rel="index"
link: <https://stepca:32769/acme/wire/authz/33y8eTP1jgI5pwuOxZvh9F0ZlK9gW50u>;rel="up"
location: https://stepca:32769/acme/wire/challenge/33y8eTP1jgI5pwuOxZvh9F0ZlK9gW50u/ejv5BlYMH0giREM4QAoTmzgwQb74cjEO
replay-nonce: QmlJN1BWUEVpejBrcFVNZWNROW5kMlA5ak1DZ0pnckE
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32769/acme/wire/challenge/33y8eTP1jgI5pwuOxZvh9F0ZlK9gW50u/ejv5BlYMH0giREM4QAoTmzgwQb74cjEO",
  "status": "valid",
  "token": "HR0bDdgr1UogAnadpfULdy7UqtCpxkeQ",
  "target": "http://wire.com:18930/clients/f92c673e9c08f466/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 19. OAUTH authorization request

```text
code_verifier=741tMryHbZN-bLQKLMu7EC4AiyZpjTa_iSxUCeXCKEo&code_challenge=iFnbypDYXUZmMJLAzLsi93DRDAdoHSF_qu7QCL8Hs84
```
#### 20. OAUTH authorization request (auth code endpoint)
```http request
GET http://keycloak:15955/realms/master/protocol/openid-connect/auth?response_type=code&client_id=wireapp&state=Y2sZxU7kGjuRjQTx7OFT9Q&code_challenge=iFnbypDYXUZmMJLAzLsi93DRDAdoHSF_qu7QCL8Hs84&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A18930%2Fcallback&scope=openid+profile&claims=%7B%22id_token%22%3A%7B%22acme_aud%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22https%3A%2F%2Fstepca%3A32769%2Facme%2Fwire%2Fchallenge%2F6v5MnzQwBvPXGcEfetxPPprCqBsbIKnH%2FYuhltIGhveq9nXh0NTv9qQ4PbKR7BvLH%22%7D%2C%22keyauth%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22pLyGqtnqFdeFtp3AtXYW2EI99DI5Sqmc.2kQ5X2utY-c6mb-pxXhds5rGM2qd6_zqFWYTk98WoXg%22%7D%7D%7D&nonce=8xokSV_vVcZPXUVRoIp6jA
```

#### 21. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://keycloak:15955/realms/master/protocol/openid-connect/token
accept: application/json
content-type: application/x-www-form-urlencoded
```
```text
grant_type=authorization_code&code=26cb61d1-1361-476f-adfd-5b56cd51defd.9364e051-57d7-4847-ac17-8208752040b4.ce9e6c46-8cff-47e8-bf4d-2bb8b76219b1&code_verifier=741tMryHbZN-bLQKLMu7EC4AiyZpjTa_iSxUCeXCKEo&client_id=wireapp&redirect_uri=http%3A%2F%2Fwire.com%3A18930%2Fcallback
```
#### 22. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmUUJEZHdqbEMwWVI0YWlSWV93UEFvTGFPMFprdkVqS2JJZWFSTl9WcF8wIn0.eyJleHAiOjE3MTE0NTEwNzMsImlhdCI6MTcxMTQ1MTAxMywiYXV0aF90aW1lIjoxNzExNDUxMDEzLCJqdGkiOiJkYmY4NGRiMC04NjMxLTQxZjktOTVlZi04MmJmMzY0NTc3ZjQiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTU5NTUvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJkZjE0OTU2NC1jMGEwLTQ2OGItODAxMi1lYWFlNWFkODJiMDkiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiI4eG9rU1ZfdlZjWlBYVVZSb0lwNmpBIiwic2Vzc2lvbl9zdGF0ZSI6IjkzNjRlMDUxLTU3ZDctNDg0Ny1hYzE3LTgyMDg3NTIwNDBiNCIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjE4OTMwIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiOTM2NGUwNTEtNTdkNy00ODQ3LWFjMTctODIwODc1MjA0MGI0IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.gEqlI2QLRqxoQXEfq4CMJ3ZWOp6WwYD-YYfz9TyjblWvboeWAHd6E5ICBIKDN8BbfLX4-P5VWt8JYQFLO1nKyg2oYm6WPyJFuZIFXLP67z1_NrxiZShjyHexjIOK28YMKWUHP2AUEUdSsJ6Vjiu0VNuMtkHf2pPuDPq0tzEsLinjICU42ut__LAGdoPAeUm-D7v9NEd88c8sve49d29W-2RfrMwlmNS_RwYalHCaY4dkugNeif0p-7E7HoP61XGso-u-UkwE5w__44c6cm80N_R6tOLmoyHO_tOhCOuu1ZO7etQHNiQyGztLJdoAPhFo1bmRW4Z1zqQ_xGhbFutxlA",
  "expires_in": 60,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmUUJEZHdqbEMwWVI0YWlSWV93UEFvTGFPMFprdkVqS2JJZWFSTl9WcF8wIn0.eyJleHAiOjE3MTE0NTEwNzMsImlhdCI6MTcxMTQ1MTAxMywiYXV0aF90aW1lIjoxNzExNDUxMDEzLCJqdGkiOiI0OWVkMmE4Yy03YzFkLTQ1ZGItOWMxNy1iMGNiZGIwYThkNDUiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTU5NTUvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiJkZjE0OTU2NC1jMGEwLTQ2OGItODAxMi1lYWFlNWFkODJiMDkiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Ijh4b2tTVl92VmNaUFhVVlJvSXA2akEiLCJzZXNzaW9uX3N0YXRlIjoiOTM2NGUwNTEtNTdkNy00ODQ3LWFjMTctODIwODc1MjA0MGI0IiwiYXRfaGFzaCI6IkFYRXp1MjhXdWl3YUxsQTR6cUFmZWciLCJhY3IiOiIxIiwic2lkIjoiOTM2NGUwNTEtNTdkNy00ODQ3LWFjMTctODIwODc1MjA0MGI0IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJhY21lX2F1ZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzY5L2FjbWUvd2lyZS9jaGFsbGVuZ2UvNnY1TW56UXdCdlBYR2NFZmV0eFBQcHJDcUJzYklLbkgvWXVobHRJR2h2ZXE5blhoME5UdjlxUTRQYktSN0J2TEgiLCJrZXlhdXRoIjoicEx5R3F0bnFGZGVGdHAzQXRYWVcyRUk5OURJNVNxbWMuMmtRNVgydXRZLWM2bWItcHhYaGRzNXJHTTJxZDZfenFGV1lUazk4V29YZyIsImZhbWlseV9uYW1lIjoiU21pdGgiLCJlbWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20ifQ.LbWTlybeBXwtKtZ483yPhakFGeiyumVnegZyxMK4vk9pZC4aKhgmv8SYnkW78HBa5bN5BTkeCv0N2mm3q8gRkdGj4l0vM_hXtJycnEx977JUgfmzBEyWCF0ZfPet1481SsxtanHgsA5fBS9XdPsDWrpAMVKVyH_4dNt13aAIOMvd__Mk0HjzWFUNK9Em9X7NwwgLuqf9T9Mfrl8Hsz5Smy6myqBLh22YlUTIIfKEEB4eHsiqSWUov96PlYgiDvCTRAYC2EGg8oF8pEilKjTW3awDzi985XetzNj7yeGmUFWAYQ2F5zUvElRzjMnBsnMePB-BDkQZW6a94elrL80xuw",
  "not-before-policy": 0,
  "refresh_expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI2M2MwZDQ2Yy0wNGYxLTQ3OGUtOTc5NC1mY2JiZWM2NjYzOTcifQ.eyJleHAiOjE3MTE0NTI4MTMsImlhdCI6MTcxMTQ1MTAxMywianRpIjoiNjNlMzhmMGEtMjhjYi00MDgzLTkxM2UtYTQwZDQ4NTk0ZDhiIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE1OTU1L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTU5NTUvcmVhbG1zL21hc3RlciIsInN1YiI6ImRmMTQ5NTY0LWMwYTAtNDY4Yi04MDEyLWVhYWU1YWQ4MmIwOSIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiI4eG9rU1ZfdlZjWlBYVVZSb0lwNmpBIiwic2Vzc2lvbl9zdGF0ZSI6IjkzNjRlMDUxLTU3ZDctNDg0Ny1hYzE3LTgyMDg3NTIwNDBiNCIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiI5MzY0ZTA1MS01N2Q3LTQ4NDctYWMxNy04MjA4NzUyMDQwYjQifQ.MUC1rCVomUlZtPzYpfILG15u_NJ_dAtq5eC0ZJcSzfg",
  "scope": "openid profile email",
  "session_state": "9364e051-57d7-4847-ac17-8208752040b4",
  "token_type": "Bearer"
}
```

<details>
<summary><b>OAuth Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmUUJEZHdqbEMwWVI0YWlSWV93UEFvTGFPMFprdkVqS2JJZWFSTl9WcF8wIn0.eyJleHAiOjE3MTE0NTEwNzMsImlhdCI6MTcxMTQ1MTAxMywiYXV0aF90aW1lIjoxNzExNDUxMDEzLCJqdGkiOiJkYmY4NGRiMC04NjMxLTQxZjktOTVlZi04MmJmMzY0NTc3ZjQiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTU5NTUvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJkZjE0OTU2NC1jMGEwLTQ2OGItODAxMi1lYWFlNWFkODJiMDkiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiI4eG9rU1ZfdlZjWlBYVVZSb0lwNmpBIiwic2Vzc2lvbl9zdGF0ZSI6IjkzNjRlMDUxLTU3ZDctNDg0Ny1hYzE3LTgyMDg3NTIwNDBiNCIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjE4OTMwIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiOTM2NGUwNTEtNTdkNy00ODQ3LWFjMTctODIwODc1MjA0MGI0IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.gEqlI2QLRqxoQXEfq4CMJ3ZWOp6WwYD-YYfz9TyjblWvboeWAHd6E5ICBIKDN8BbfLX4-P5VWt8JYQFLO1nKyg2oYm6WPyJFuZIFXLP67z1_NrxiZShjyHexjIOK28YMKWUHP2AUEUdSsJ6Vjiu0VNuMtkHf2pPuDPq0tzEsLinjICU42ut__LAGdoPAeUm-D7v9NEd88c8sve49d29W-2RfrMwlmNS_RwYalHCaY4dkugNeif0p-7E7HoP61XGso-u-UkwE5w__44c6cm80N_R6tOLmoyHO_tOhCOuu1ZO7etQHNiQyGztLJdoAPhFo1bmRW4Z1zqQ_xGhbFutxlA)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmUUJEZHdqbEMw
WVI0YWlSWV93UEFvTGFPMFprdkVqS2JJZWFSTl9WcF8wIn0.eyJleHAiOjE3MTE0
NTEwNzMsImlhdCI6MTcxMTQ1MTAxMywiYXV0aF90aW1lIjoxNzExNDUxMDEzLCJq
dGkiOiJkYmY4NGRiMC04NjMxLTQxZjktOTVlZi04MmJmMzY0NTc3ZjQiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MTU5NTUvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFj
Y291bnQiLCJzdWIiOiJkZjE0OTU2NC1jMGEwLTQ2OGItODAxMi1lYWFlNWFkODJi
MDkiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiI4eG9r
U1ZfdlZjWlBYVVZSb0lwNmpBIiwic2Vzc2lvbl9zdGF0ZSI6IjkzNjRlMDUxLTU3
ZDctNDg0Ny1hYzE3LTgyMDg3NTIwNDBiNCIsImFjciI6IjEiLCJhbGxvd2VkLW9y
aWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjE4OTMwIl0sInJlYWxtX2FjY2VzcyI6
eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNz
IiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2Nv
dW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQt
bGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxl
IGVtYWlsIiwic2lkIjoiOTM2NGUwNTEtNTdkNy00ODQ3LWFjMTctODIwODc1MjA0
MGI0IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIs
InByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJnaXZl
bl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJh
bGljZXNtaXRoQHdpcmUuY29tIn0.gEqlI2QLRqxoQXEfq4CMJ3ZWOp6WwYD-YYfz
9TyjblWvboeWAHd6E5ICBIKDN8BbfLX4-P5VWt8JYQFLO1nKyg2oYm6WPyJFuZIF
XLP67z1_NrxiZShjyHexjIOK28YMKWUHP2AUEUdSsJ6Vjiu0VNuMtkHf2pPuDPq0
tzEsLinjICU42ut__LAGdoPAeUm-D7v9NEd88c8sve49d29W-2RfrMwlmNS_RwYa
lHCaY4dkugNeif0p-7E7HoP61XGso-u-UkwE5w__44c6cm80N_R6tOLmoyHO_tOh
COuu1ZO7etQHNiQyGztLJdoAPhFo1bmRW4Z1zqQ_xGhbFutxlA
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "fQBDdwjlC0YR4aiRY_wPAoLaO0ZkvEjKbIeaRN_Vp_0",
  "typ": "JWT"
}
```

```json
{
  "acr": "1",
  "allowed-origins": [
    "http://wire.com:18930"
  ],
  "aud": "account",
  "auth_time": 1711451013,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1711451073,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1711451013,
  "iss": "http://keycloak:15955/realms/master",
  "jti": "dbf84db0-8631-41f9-95ef-82bf364577f4",
  "name": "Alice Smith",
  "nonce": "8xokSV_vVcZPXUVRoIp6jA",
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
  "session_state": "9364e051-57d7-4847-ac17-8208752040b4",
  "sid": "9364e051-57d7-4847-ac17-8208752040b4",
  "sub": "df149564-c0a0-468b-8012-eaae5ad82b09",
  "typ": "Bearer"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2sX2FeGrim09RzVEQSbK
3hVIBnBXI68a31gnC4ZBfyQkYSQ5N9BrWU2u8eNLQf8od+g5ZlUV4fdfn9ZkWZI7
ULVacSiazRx7GMlfoLcWZ0fuwpLy+jCtWMXpqqzFYAZ3AJw7vZA24NILvHNDcoWo
ZcaP/Tu8cgHN06Lzt1hVA2L4Fdoy2b2NZ31/J/UaAuijQOC5po1ZSNB8rswhJraS
Xygd1aKPpyhcQs0Q1dlrX1vBErek8IOMBeob53XXxHnV8x5vbCKcXwjk2jH1sdgC
vol62sDfZJg3Nq+J3txv0dD/6DEkeDUdaBCfIKZGA0gHUV+ZzoY389zQJhr4RIr5
8wIDAQAB
-----END PUBLIC KEY-----
```

</details>



<details>
<summary><b>OAuth Refresh token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI2M2MwZDQ2Yy0wNGYxLTQ3OGUtOTc5NC1mY2JiZWM2NjYzOTcifQ.eyJleHAiOjE3MTE0NTI4MTMsImlhdCI6MTcxMTQ1MTAxMywianRpIjoiNjNlMzhmMGEtMjhjYi00MDgzLTkxM2UtYTQwZDQ4NTk0ZDhiIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE1OTU1L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTU5NTUvcmVhbG1zL21hc3RlciIsInN1YiI6ImRmMTQ5NTY0LWMwYTAtNDY4Yi04MDEyLWVhYWU1YWQ4MmIwOSIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiI4eG9rU1ZfdlZjWlBYVVZSb0lwNmpBIiwic2Vzc2lvbl9zdGF0ZSI6IjkzNjRlMDUxLTU3ZDctNDg0Ny1hYzE3LTgyMDg3NTIwNDBiNCIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiI5MzY0ZTA1MS01N2Q3LTQ4NDctYWMxNy04MjA4NzUyMDQwYjQifQ.MUC1rCVomUlZtPzYpfILG15u_NJ_dAtq5eC0ZJcSzfg)

Raw:
```text
eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI2M2MwZDQ2Yy0w
NGYxLTQ3OGUtOTc5NC1mY2JiZWM2NjYzOTcifQ.eyJleHAiOjE3MTE0NTI4MTMsI
mlhdCI6MTcxMTQ1MTAxMywianRpIjoiNjNlMzhmMGEtMjhjYi00MDgzLTkxM2UtY
TQwZDQ4NTk0ZDhiIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE1OTU1L3JlYWxtc
y9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTU5NTUvcmVhbG1zL21hc
3RlciIsInN1YiI6ImRmMTQ5NTY0LWMwYTAtNDY4Yi04MDEyLWVhYWU1YWQ4MmIwO
SIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiI4eG9rU
1ZfdlZjWlBYVVZSb0lwNmpBIiwic2Vzc2lvbl9zdGF0ZSI6IjkzNjRlMDUxLTU3Z
DctNDg0Ny1hYzE3LTgyMDg3NTIwNDBiNCIsInNjb3BlIjoib3BlbmlkIHByb2Zpb
GUgZW1haWwiLCJzaWQiOiI5MzY0ZTA1MS01N2Q3LTQ4NDctYWMxNy04MjA4NzUyM
DQwYjQifQ.MUC1rCVomUlZtPzYpfILG15u_NJ_dAtq5eC0ZJcSzfg
```

Decoded:

```json
{
  "alg": "HS256",
  "kid": "63c0d46c-04f1-478e-9794-fcbbec666397",
  "typ": "JWT"
}
```

```json
{
  "aud": "http://keycloak:15955/realms/master",
  "azp": "wireapp",
  "exp": 1711452813,
  "iat": 1711451013,
  "iss": "http://keycloak:15955/realms/master",
  "jti": "63e38f0a-28cb-4083-913e-a40d48594d8b",
  "nonce": "8xokSV_vVcZPXUVRoIp6jA",
  "scope": "openid profile email",
  "session_state": "9364e051-57d7-4847-ac17-8208752040b4",
  "sid": "9364e051-57d7-4847-ac17-8208752040b4",
  "sub": "df149564-c0a0-468b-8012-eaae5ad82b09",
  "typ": "Refresh"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2sX2FeGrim09RzVEQSbK
3hVIBnBXI68a31gnC4ZBfyQkYSQ5N9BrWU2u8eNLQf8od+g5ZlUV4fdfn9ZkWZI7
ULVacSiazRx7GMlfoLcWZ0fuwpLy+jCtWMXpqqzFYAZ3AJw7vZA24NILvHNDcoWo
ZcaP/Tu8cgHN06Lzt1hVA2L4Fdoy2b2NZ31/J/UaAuijQOC5po1ZSNB8rswhJraS
Xygd1aKPpyhcQs0Q1dlrX1vBErek8IOMBeob53XXxHnV8x5vbCKcXwjk2jH1sdgC
vol62sDfZJg3Nq+J3txv0dD/6DEkeDUdaBCfIKZGA0gHUV+ZzoY389zQJhr4RIr5
8wIDAQAB
-----END PUBLIC KEY-----
```

</details>


#### 23. validate oidc challenge (userId + displayName)

<details>
<summary><b>OIDC Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmUUJEZHdqbEMwWVI0YWlSWV93UEFvTGFPMFprdkVqS2JJZWFSTl9WcF8wIn0.eyJleHAiOjE3MTE0NTEwNzMsImlhdCI6MTcxMTQ1MTAxMywiYXV0aF90aW1lIjoxNzExNDUxMDEzLCJqdGkiOiI0OWVkMmE4Yy03YzFkLTQ1ZGItOWMxNy1iMGNiZGIwYThkNDUiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTU5NTUvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiJkZjE0OTU2NC1jMGEwLTQ2OGItODAxMi1lYWFlNWFkODJiMDkiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Ijh4b2tTVl92VmNaUFhVVlJvSXA2akEiLCJzZXNzaW9uX3N0YXRlIjoiOTM2NGUwNTEtNTdkNy00ODQ3LWFjMTctODIwODc1MjA0MGI0IiwiYXRfaGFzaCI6IkFYRXp1MjhXdWl3YUxsQTR6cUFmZWciLCJhY3IiOiIxIiwic2lkIjoiOTM2NGUwNTEtNTdkNy00ODQ3LWFjMTctODIwODc1MjA0MGI0IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJhY21lX2F1ZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzY5L2FjbWUvd2lyZS9jaGFsbGVuZ2UvNnY1TW56UXdCdlBYR2NFZmV0eFBQcHJDcUJzYklLbkgvWXVobHRJR2h2ZXE5blhoME5UdjlxUTRQYktSN0J2TEgiLCJrZXlhdXRoIjoicEx5R3F0bnFGZGVGdHAzQXRYWVcyRUk5OURJNVNxbWMuMmtRNVgydXRZLWM2bWItcHhYaGRzNXJHTTJxZDZfenFGV1lUazk4V29YZyIsImZhbWlseV9uYW1lIjoiU21pdGgiLCJlbWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20ifQ.LbWTlybeBXwtKtZ483yPhakFGeiyumVnegZyxMK4vk9pZC4aKhgmv8SYnkW78HBa5bN5BTkeCv0N2mm3q8gRkdGj4l0vM_hXtJycnEx977JUgfmzBEyWCF0ZfPet1481SsxtanHgsA5fBS9XdPsDWrpAMVKVyH_4dNt13aAIOMvd__Mk0HjzWFUNK9Em9X7NwwgLuqf9T9Mfrl8Hsz5Smy6myqBLh22YlUTIIfKEEB4eHsiqSWUov96PlYgiDvCTRAYC2EGg8oF8pEilKjTW3awDzi985XetzNj7yeGmUFWAYQ2F5zUvElRzjMnBsnMePB-BDkQZW6a94elrL80xuw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmUUJEZHdqbEMw
WVI0YWlSWV93UEFvTGFPMFprdkVqS2JJZWFSTl9WcF8wIn0.eyJleHAiOjE3MTE0
NTEwNzMsImlhdCI6MTcxMTQ1MTAxMywiYXV0aF90aW1lIjoxNzExNDUxMDEzLCJq
dGkiOiI0OWVkMmE4Yy03YzFkLTQ1ZGItOWMxNy1iMGNiZGIwYThkNDUiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MTU5NTUvcmVhbG1zL21hc3RlciIsImF1ZCI6Indp
cmVhcHAiLCJzdWIiOiJkZjE0OTU2NC1jMGEwLTQ2OGItODAxMi1lYWFlNWFkODJi
MDkiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Ijh4b2tTVl92
VmNaUFhVVlJvSXA2akEiLCJzZXNzaW9uX3N0YXRlIjoiOTM2NGUwNTEtNTdkNy00
ODQ3LWFjMTctODIwODc1MjA0MGI0IiwiYXRfaGFzaCI6IkFYRXp1MjhXdWl3YUxs
QTR6cUFmZWciLCJhY3IiOiIxIiwic2lkIjoiOTM2NGUwNTEtNTdkNy00ODQ3LWFj
MTctODIwODc1MjA0MGI0IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJB
bGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2ly
ZS5jb20iLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJhY21lX2F1ZCI6Imh0dHBzOi8v
c3RlcGNhOjMyNzY5L2FjbWUvd2lyZS9jaGFsbGVuZ2UvNnY1TW56UXdCdlBYR2NF
ZmV0eFBQcHJDcUJzYklLbkgvWXVobHRJR2h2ZXE5blhoME5UdjlxUTRQYktSN0J2
TEgiLCJrZXlhdXRoIjoicEx5R3F0bnFGZGVGdHAzQXRYWVcyRUk5OURJNVNxbWMu
MmtRNVgydXRZLWM2bWItcHhYaGRzNXJHTTJxZDZfenFGV1lUazk4V29YZyIsImZh
bWlseV9uYW1lIjoiU21pdGgiLCJlbWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20i
fQ.LbWTlybeBXwtKtZ483yPhakFGeiyumVnegZyxMK4vk9pZC4aKhgmv8SYnkW78
HBa5bN5BTkeCv0N2mm3q8gRkdGj4l0vM_hXtJycnEx977JUgfmzBEyWCF0ZfPet1
481SsxtanHgsA5fBS9XdPsDWrpAMVKVyH_4dNt13aAIOMvd__Mk0HjzWFUNK9Em9
X7NwwgLuqf9T9Mfrl8Hsz5Smy6myqBLh22YlUTIIfKEEB4eHsiqSWUov96PlYgiD
vCTRAYC2EGg8oF8pEilKjTW3awDzi985XetzNj7yeGmUFWAYQ2F5zUvElRzjMnBs
nMePB-BDkQZW6a94elrL80xuw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "fQBDdwjlC0YR4aiRY_wPAoLaO0ZkvEjKbIeaRN_Vp_0",
  "typ": "JWT"
}
```

```json
{
  "acme_aud": "https://stepca:32769/acme/wire/challenge/6v5MnzQwBvPXGcEfetxPPprCqBsbIKnH/YuhltIGhveq9nXh0NTv9qQ4PbKR7BvLH",
  "acr": "1",
  "at_hash": "AXEzu28WuiwaLlA4zqAfeg",
  "aud": "wireapp",
  "auth_time": 1711451013,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1711451073,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1711451013,
  "iss": "http://keycloak:15955/realms/master",
  "jti": "49ed2a8c-7c1d-45db-9c17-b0cbdb0a8d45",
  "keyauth": "pLyGqtnqFdeFtp3AtXYW2EI99DI5Sqmc.2kQ5X2utY-c6mb-pxXhds5rGM2qd6_zqFWYTk98WoXg",
  "name": "Alice Smith",
  "nonce": "8xokSV_vVcZPXUVRoIp6jA",
  "preferred_username": "alice_wire@wire.com",
  "session_state": "9364e051-57d7-4847-ac17-8208752040b4",
  "sid": "9364e051-57d7-4847-ac17-8208752040b4",
  "sub": "df149564-c0a0-468b-8012-eaae5ad82b09",
  "typ": "ID"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2sX2FeGrim09RzVEQSbK
3hVIBnBXI68a31gnC4ZBfyQkYSQ5N9BrWU2u8eNLQf8od+g5ZlUV4fdfn9ZkWZI7
ULVacSiazRx7GMlfoLcWZ0fuwpLy+jCtWMXpqqzFYAZ3AJw7vZA24NILvHNDcoWo
ZcaP/Tu8cgHN06Lzt1hVA2L4Fdoy2b2NZ31/J/UaAuijQOC5po1ZSNB8rswhJraS
Xygd1aKPpyhcQs0Q1dlrX1vBErek8IOMBeob53XXxHnV8x5vbCKcXwjk2jH1sdgC
vol62sDfZJg3Nq+J3txv0dD/6DEkeDUdaBCfIKZGA0gHUV+ZzoY389zQJhr4RIr5
8wIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32769/acme/wire/challenge/6v5MnzQwBvPXGcEfetxPPprCqBsbIKnH/YuhltIGhveq9nXh0NTv9qQ4PbKR7BvLH
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzY5L2FjbWUvd2lyZS9hY2NvdW50LzNrZkJGY0JjTXhGRFIxZEhyUWs4UmdBUGNQWDhDU1lQIiwidHlwIjoiSldUIiwibm9uY2UiOiJRbWxKTjFCV1VFVnBlakJyY0ZWTlpXTlJPVzVrTWxBNWFrMURaMHBuY2tFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NjkvYWNtZS93aXJlL2NoYWxsZW5nZS82djVNbnpRd0J2UFhHY0VmZXR4UFBwckNxQnNiSUtuSC9ZdWhsdElHaHZlcTluWGgwTlR2OXFRNFBiS1I3QnZMSCJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSWdPaUFpU2xkVUlpd2lhMmxrSWlBNklDSm1VVUpFWkhkcWJFTXdXVkkwWVdsU1dWOTNVRUZ2VEdGUE1GcHJka1ZxUzJKSlpXRlNUbDlXY0Y4d0luMC5leUpsZUhBaU9qRTNNVEUwTlRFd056TXNJbWxoZENJNk1UY3hNVFExTVRBeE15d2lZWFYwYUY5MGFXMWxJam94TnpFeE5EVXhNREV6TENKcWRHa2lPaUkwT1dWa01tRTRZeTAzWXpGa0xUUTFaR0l0T1dNeE55MWlNR05pWkdJd1lUaGtORFVpTENKcGMzTWlPaUpvZEhSd09pOHZhMlY1WTJ4dllXczZNVFU1TlRVdmNtVmhiRzF6TDIxaGMzUmxjaUlzSW1GMVpDSTZJbmRwY21WaGNIQWlMQ0p6ZFdJaU9pSmtaakUwT1RVMk5DMWpNR0V3TFRRMk9HSXRPREF4TWkxbFlXRmxOV0ZrT0RKaU1Ea2lMQ0owZVhBaU9pSkpSQ0lzSW1GNmNDSTZJbmRwY21WaGNIQWlMQ0p1YjI1alpTSTZJamg0YjJ0VFZsOTJWbU5hVUZoVlZsSnZTWEEyYWtFaUxDSnpaWE56YVc5dVgzTjBZWFJsSWpvaU9UTTJOR1V3TlRFdE5UZGtOeTAwT0RRM0xXRmpNVGN0T0RJd09EYzFNakEwTUdJMElpd2lZWFJmYUdGemFDSTZJa0ZZUlhwMU1qaFhkV2wzWVV4c1FUUjZjVUZtWldjaUxDSmhZM0lpT2lJeElpd2ljMmxrSWpvaU9UTTJOR1V3TlRFdE5UZGtOeTAwT0RRM0xXRmpNVGN0T0RJd09EYzFNakEwTUdJMElpd2laVzFoYVd4ZmRtVnlhV1pwWldRaU9uUnlkV1VzSW01aGJXVWlPaUpCYkdsalpTQlRiV2wwYUNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJbUZzYVdObFgzZHBjbVZBZDJseVpTNWpiMjBpTENKbmFYWmxibDl1WVcxbElqb2lRV3hwWTJVaUxDSmhZMjFsWDJGMVpDSTZJbWgwZEhCek9pOHZjM1JsY0dOaE9qTXlOelk1TDJGamJXVXZkMmx5WlM5amFHRnNiR1Z1WjJVdk5uWTFUVzU2VVhkQ2RsQllSMk5GWm1WMGVGQlFjSEpEY1VKellrbExia2d2V1hWb2JIUkpSMmgyWlhFNWJsaG9NRTVVZGpseFVUUlFZa3RTTjBKMlRFZ2lMQ0pyWlhsaGRYUm9Jam9pY0V4NVIzRjBibkZHWkdWR2RIQXpRWFJZV1ZjeVJVazVPVVJKTlZOeGJXTXVNbXRSTlZneWRYUlpMV00yYldJdGNIaFlhR1J6TlhKSFRUSnhaRFpmZW5GR1YxbFVhems0VjI5WVp5SXNJbVpoYldsc2VWOXVZVzFsSWpvaVUyMXBkR2dpTENKbGJXRnBiQ0k2SW1Gc2FXTmxjMjFwZEdoQWQybHlaUzVqYjIwaWZRLkxiV1RseWJlQlh3dEt0WjQ4M3lQaGFrRkdlaXl1bVZuZWdaeXhNSzR2azlwWkM0YUtoZ212OFNZbmtXNzhIQmE1Yk41QlRrZUN2ME4ybW0zcThnUmtkR2o0bDB2TV9oWHRKeWNuRXg5NzdKVWdmbXpCRXlXQ0YwWmZQZXQxNDgxU3N4dGFuSGdzQTVmQlM5WGRQc0RXcnBBTVZLVnlIXzRkTnQxM2FBSU9NdmRfX01rMEhqeldGVU5LOUVtOVg3Tnd3Z0x1cWY5VDlNZnJsOEhzejVTbXk2bXlxQkxoMjJZbFVUSUlmS0VFQjRlSHNpcVNXVW92OTZQbFlnaUR2Q1RSQVlDMkVHZzhvRjhwRWlsS2pUVzNhd0R6aTk4NVhldHpOajd5ZUdtVUZXQVlRMkY1elV2RWxSempNbkJzbk1lUEItQkRrUVpXNmE5NGVsckw4MHh1dyJ9",
  "signature": "sqmJvDxAdd77M8euTwRDDm_D6Z9gdoCv-C6N--YrVIgTCNLtIy2NWVmfVi4uIA6YIwwaQioWf7ML1ZdrSdt6Dw"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmUUJEZHdqbEMwWVI0YWlSWV93UEFvTGFPMFprdkVqS2JJZWFSTl9WcF8wIn0.eyJleHAiOjE3MTE0NTEwNzMsImlhdCI6MTcxMTQ1MTAxMywiYXV0aF90aW1lIjoxNzExNDUxMDEzLCJqdGkiOiI0OWVkMmE4Yy03YzFkLTQ1ZGItOWMxNy1iMGNiZGIwYThkNDUiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTU5NTUvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiJkZjE0OTU2NC1jMGEwLTQ2OGItODAxMi1lYWFlNWFkODJiMDkiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Ijh4b2tTVl92VmNaUFhVVlJvSXA2akEiLCJzZXNzaW9uX3N0YXRlIjoiOTM2NGUwNTEtNTdkNy00ODQ3LWFjMTctODIwODc1MjA0MGI0IiwiYXRfaGFzaCI6IkFYRXp1MjhXdWl3YUxsQTR6cUFmZWciLCJhY3IiOiIxIiwic2lkIjoiOTM2NGUwNTEtNTdkNy00ODQ3LWFjMTctODIwODc1MjA0MGI0IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJhY21lX2F1ZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzY5L2FjbWUvd2lyZS9jaGFsbGVuZ2UvNnY1TW56UXdCdlBYR2NFZmV0eFBQcHJDcUJzYklLbkgvWXVobHRJR2h2ZXE5blhoME5UdjlxUTRQYktSN0J2TEgiLCJrZXlhdXRoIjoicEx5R3F0bnFGZGVGdHAzQXRYWVcyRUk5OURJNVNxbWMuMmtRNVgydXRZLWM2bWItcHhYaGRzNXJHTTJxZDZfenFGV1lUazk4V29YZyIsImZhbWlseV9uYW1lIjoiU21pdGgiLCJlbWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20ifQ.LbWTlybeBXwtKtZ483yPhakFGeiyumVnegZyxMK4vk9pZC4aKhgmv8SYnkW78HBa5bN5BTkeCv0N2mm3q8gRkdGj4l0vM_hXtJycnEx977JUgfmzBEyWCF0ZfPet1481SsxtanHgsA5fBS9XdPsDWrpAMVKVyH_4dNt13aAIOMvd__Mk0HjzWFUNK9Em9X7NwwgLuqf9T9Mfrl8Hsz5Smy6myqBLh22YlUTIIfKEEB4eHsiqSWUov96PlYgiDvCTRAYC2EGg8oF8pEilKjTW3awDzi985XetzNj7yeGmUFWAYQ2F5zUvElRzjMnBsnMePB-BDkQZW6a94elrL80xuw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32769/acme/wire/account/3kfBFcBcMxFDR1dHrQk8RgAPcPX8CSYP",
    "nonce": "QmlJN1BWUEVpejBrcFVNZWNROW5kMlA5ak1DZ0pnckE",
    "typ": "JWT",
    "url": "https://stepca:32769/acme/wire/challenge/6v5MnzQwBvPXGcEfetxPPprCqBsbIKnH/YuhltIGhveq9nXh0NTv9qQ4PbKR7BvLH"
  }
}
```
#### 24. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32769/acme/wire/directory>;rel="index"
link: <https://stepca:32769/acme/wire/authz/6v5MnzQwBvPXGcEfetxPPprCqBsbIKnH>;rel="up"
location: https://stepca:32769/acme/wire/challenge/6v5MnzQwBvPXGcEfetxPPprCqBsbIKnH/YuhltIGhveq9nXh0NTv9qQ4PbKR7BvLH
replay-nonce: VmNkREdPNzN4S280VlhKb2xvV0RDamQyVkRMdjZGenM
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32769/acme/wire/challenge/6v5MnzQwBvPXGcEfetxPPprCqBsbIKnH/YuhltIGhveq9nXh0NTv9qQ4PbKR7BvLH",
  "status": "valid",
  "token": "pLyGqtnqFdeFtp3AtXYW2EI99DI5Sqmc",
  "target": "http://keycloak:15955/realms/master"
}
```
### Client presents a CSR and gets its certificate
#### 25. verify the status of the order
```http request
POST https://stepca:32769/acme/wire/order/iq3FmbOOTm51xcQ2piXHYXey2A40r4Wb
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzY5L2FjbWUvd2lyZS9hY2NvdW50LzNrZkJGY0JjTXhGRFIxZEhyUWs4UmdBUGNQWDhDU1lQIiwidHlwIjoiSldUIiwibm9uY2UiOiJWbU5rUkVkUE56TjRTMjgwVmxoS2IyeHZWMFJEYW1ReVZrUk1kalpHZW5NIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NjkvYWNtZS93aXJlL29yZGVyL2lxM0ZtYk9PVG01MXhjUTJwaVhIWVhleTJBNDByNFdiIn0",
  "payload": "",
  "signature": "8g5LMVLou6jv1wQrBw-BgO-poqhfnccL1_BNjjr5mVBlplerBzG7stq3aWXsEKbxPCFn8GT-pyHj0Kucg7SMDg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32769/acme/wire/account/3kfBFcBcMxFDR1dHrQk8RgAPcPX8CSYP",
    "nonce": "VmNkREdPNzN4S280VlhKb2xvV0RDamQyVkRMdjZGenM",
    "typ": "JWT",
    "url": "https://stepca:32769/acme/wire/order/iq3FmbOOTm51xcQ2piXHYXey2A40r4Wb"
  }
}
```
#### 26. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32769/acme/wire/directory>;rel="index"
location: https://stepca:32769/acme/wire/order/iq3FmbOOTm51xcQ2piXHYXey2A40r4Wb
replay-nonce: ZVNOd3VVQWdJTmNwMWp3dXBQSFhDUWZmMEJQekh2NGs
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32769/acme/wire/order/iq3FmbOOTm51xcQ2piXHYXey2A40r4Wb/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://lYPMMhxlQyiJHg7f0X4tTg!f92c673e9c08f466@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32769/acme/wire/authz/33y8eTP1jgI5pwuOxZvh9F0ZlK9gW50u",
    "https://stepca:32769/acme/wire/authz/6v5MnzQwBvPXGcEfetxPPprCqBsbIKnH"
  ],
  "expires": "2024-03-27T11:03:32Z",
  "notBefore": "2024-03-26T11:03:32.835172Z",
  "notAfter": "2034-03-24T11:03:32.835172Z"
}
```
#### 27. create a CSR and call finalize url
```http request
POST https://stepca:32769/acme/wire/order/iq3FmbOOTm51xcQ2piXHYXey2A40r4Wb/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzY5L2FjbWUvd2lyZS9hY2NvdW50LzNrZkJGY0JjTXhGRFIxZEhyUWs4UmdBUGNQWDhDU1lQIiwidHlwIjoiSldUIiwibm9uY2UiOiJaVk5PZDNWVlFXZEpUbU53TVdwM2RYQlFTRmhEVVdabU1FSlFla2gyTkdzIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NjkvYWNtZS93aXJlL29yZGVyL2lxM0ZtYk9PVG01MXhjUTJwaVhIWVhleTJBNDByNFdiL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCS3pDQjNnSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBTElHbW1nSTl1TS1TbXdCSkNFeWllWjhKelNiVkUwdUNwN1RkUjRBSlR6cm9Ib3dlQVlKS29aSWh2Y05BUWtPTVdzd2FUQm5CZ05WSFJFRVlEQmVoanAzYVhKbFlYQndPaTh2YkZsUVRVMW9lR3hSZVdsS1NHYzNaakJZTkhSVVp5Rm1PVEpqTmpjelpUbGpNRGhtTkRZMlFIZHBjbVV1WTI5dGhpQjNhWEpsWVhCd09pOHZKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlRBRkJnTXJaWEFEUVFEMnhKTnRjczJnNU5YSDkycUVQZFpDVmhMTlNqRk9YUXJWVUhJZG8xajlvRC1mMjZyTUVSU2pIRUhVcVN3Q1NYcjRrbUVHLTVudkxCbGZhQi1kNklNRCJ9",
  "signature": "9p72qsNzn24GZiEtLtAoQxbHqrta2qJbo0tjQCPUtf2Yuevs95HDmHK6woHn2ELWCMkwz11fcdZQleA6RsTaDQ"
}
```
```json
{
  "payload": {
    "csr": "MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhALIGmmgI9uM-SmwBJCEyieZ8JzSbVE0uCp7TdR4AJTzroHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBwOi8vbFlQTU1oeGxReWlKSGc3ZjBYNHRUZyFmOTJjNjczZTljMDhmNDY2QHdpcmUuY29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQD2xJNtcs2g5NXH92qEPdZCVhLNSjFOXQrVUHIdo1j9oD-f26rMERSjHEHUqSwCSXr4kmEG-5nvLBlfaB-d6IMD"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32769/acme/wire/account/3kfBFcBcMxFDR1dHrQk8RgAPcPX8CSYP",
    "nonce": "ZVNOd3VVQWdJTmNwMWp3dXBQSFhDUWZmMEJQekh2NGs",
    "typ": "JWT",
    "url": "https://stepca:32769/acme/wire/order/iq3FmbOOTm51xcQ2piXHYXey2A40r4Wb/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhALIGmmgI9uM+SmwBJCEyieZ8JzSbVE0u
Cp7TdR4AJTzroHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBw
Oi8vbFlQTU1oeGxReWlKSGc3ZjBYNHRUZyFmOTJjNjczZTljMDhmNDY2QHdpcmUu
Y29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQD2
xJNtcs2g5NXH92qEPdZCVhLNSjFOXQrVUHIdo1j9oD+f26rMERSjHEHUqSwCSXr4
kmEG+5nvLBlfaB+d6IMD
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
                    b2:06:9a:68:08:f6:e3:3e:4a:6c:01:24:21:32:89:
                    e6:7c:27:34:9b:54:4d:2e:0a:9e:d3:75:1e:00:25:
                    3c:eb
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:wireapp://lYPMMhxlQyiJHg7f0X4tTg!f92c673e9c08f466@wire.com, URI:wireapp://%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        f6:c4:93:6d:72:cd:a0:e4:d5:c7:f7:6a:84:3d:d6:42:56:12:
        cd:4a:31:4e:5d:0a:d5:50:72:1d:a3:58:fd:a0:3f:9f:db:aa:
        cc:11:14:a3:1c:41:d4:a9:2c:02:49:7a:f8:92:61:06:fb:99:
        ef:2c:19:5f:68:1f:9d:e8:83:03

```

#### 28. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32769/acme/wire/directory>;rel="index"
location: https://stepca:32769/acme/wire/order/iq3FmbOOTm51xcQ2piXHYXey2A40r4Wb
replay-nonce: QkR1UERaOHl1TG92OHhWUUhtaG51RXd5MmN0Vk9pelE
```
```json
{
  "certificate": "https://stepca:32769/acme/wire/certificate/RvlWlX6SCRKfRLZfA8DMlHCBzqXKcELQ",
  "status": "valid",
  "finalize": "https://stepca:32769/acme/wire/order/iq3FmbOOTm51xcQ2piXHYXey2A40r4Wb/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://lYPMMhxlQyiJHg7f0X4tTg!f92c673e9c08f466@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32769/acme/wire/authz/33y8eTP1jgI5pwuOxZvh9F0ZlK9gW50u",
    "https://stepca:32769/acme/wire/authz/6v5MnzQwBvPXGcEfetxPPprCqBsbIKnH"
  ],
  "expires": "2024-03-27T11:03:32Z",
  "notBefore": "2024-03-26T11:03:32.835172Z",
  "notAfter": "2034-03-24T11:03:32.835172Z"
}
```
#### 29. fetch the certificate
```http request
POST https://stepca:32769/acme/wire/certificate/RvlWlX6SCRKfRLZfA8DMlHCBzqXKcELQ
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzY5L2FjbWUvd2lyZS9hY2NvdW50LzNrZkJGY0JjTXhGRFIxZEhyUWs4UmdBUGNQWDhDU1lQIiwidHlwIjoiSldUIiwibm9uY2UiOiJRa1IxVUVSYU9IbDFURzkyT0hoV1VVaHRhRzUxUlhkNU1tTjBWazlwZWxFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NjkvYWNtZS93aXJlL2NlcnRpZmljYXRlL1J2bFdsWDZTQ1JLZlJMWmZBOERNbEhDQnpxWEtjRUxRIn0",
  "payload": "",
  "signature": "lk3m9rOS4ccA93TeTf_TeppcMfdZj2RiUYSthJSLc5tcbJfoLxBVImz3XpMWAiVggqrf_E8WiWLXV9_OuYySAg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32769/acme/wire/account/3kfBFcBcMxFDR1dHrQk8RgAPcPX8CSYP",
    "nonce": "QkR1UERaOHl1TG92OHhWUUhtaG51RXd5MmN0Vk9pelE",
    "typ": "JWT",
    "url": "https://stepca:32769/acme/wire/certificate/RvlWlX6SCRKfRLZfA8DMlHCBzqXKcELQ"
  }
}
```
#### 30. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32769/acme/wire/directory>;rel="index"
replay-nonce: d3BIVlhISnRXcmVXQU5wRmtVVElKU1NuTGxFU0FOcFg
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGjCCAb+gAwIBAgIQOIXuc1ZqKVU80JrvS88GJTAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nNDAzMjYxMTAzMzJaFw0zNDAzMjQxMTAzMzJaMCkxETAPBgNVBAoTCHdpcmUuY29t\nMRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhALIGmmgI9uM+SmwBJCEy\nieZ8JzSbVE0uCp7TdR4AJTzro4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE\nDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQURcXiKoLlNpLiXmwBekJHo2HASgIwHwYD\nVR0jBBgwFoAU9icm15FoSZn3PDB0hOHjILRHf+gwaQYDVR0RBGIwYIYgd2lyZWFw\ncDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb22GPHdpcmVhcHA6Ly9sWVBNTWh4bFF5\naUpIZzdmMFg0dFRnJTIxZjkyYzY3M2U5YzA4ZjQ2NkB3aXJlLmNvbTAdBgwrBgEE\nAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSQAwRgIhAIIi1H9G\nBwtbctuv0iKgU5LXx6rdYNXe1IBfyxsSQSFTAiEA/FG6Q6pqalATcHck5lu8HVG9\nKGZb/i+Ne9YcjKtJiww=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuDCCAV6gAwIBAgIQVYvujgrLroo+FS47z7V9XTAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMzI2MTEw\nMzMxWhcNMzQwMzI0MTEwMzMxWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPcL\nftRCDLjpfvz3lwIK77AyR9jDhEAnzhN4F5GGmywORWHurYNjYavpc65kqq5VGKVN\nhD3j3atDujY8p8nfvg6jZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBT2JybXkWhJmfc8MHSE4eMgtEd/6DAfBgNVHSMEGDAW\ngBQ06fjoy0xr5Iz05d3TrZXmvrx4JDAKBggqhkjOPQQDAgNIADBFAiEAsvMotnAG\n2KEaaweGSn5u2UTNl6cYwcdci86ys8DHgFICICGWmlBUOo9TB/9SHhE4eguU57h6\n1raQVZReG6vgjxvv\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICGjCCAb+gAwIBAgIQOIXuc1ZqKVU80JrvS88GJTAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
NDAzMjYxMTAzMzJaFw0zNDAzMjQxMTAzMzJaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhALIGmmgI9uM+SmwBJCEy
ieZ8JzSbVE0uCp7TdR4AJTzro4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQURcXiKoLlNpLiXmwBekJHo2HASgIwHwYD
VR0jBBgwFoAU9icm15FoSZn3PDB0hOHjILRHf+gwaQYDVR0RBGIwYIYgd2lyZWFw
cDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb22GPHdpcmVhcHA6Ly9sWVBNTWh4bFF5
aUpIZzdmMFg0dFRnJTIxZjkyYzY3M2U5YzA4ZjQ2NkB3aXJlLmNvbTAdBgwrBgEE
AYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSQAwRgIhAIIi1H9G
Bwtbctuv0iKgU5LXx6rdYNXe1IBfyxsSQSFTAiEA/FG6Q6pqalATcHck5lu8HVG9
KGZb/i+Ne9YcjKtJiww=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            38:85:ee:73:56:6a:29:55:3c:d0:9a:ef:4b:cf:06:25
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Intermediate CA
        Validity
            Not Before: Mar 26 11:03:32 2024 GMT
            Not After : Mar 24 11:03:32 2034 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    b2:06:9a:68:08:f6:e3:3e:4a:6c:01:24:21:32:89:
                    e6:7c:27:34:9b:54:4d:2e:0a:9e:d3:75:1e:00:25:
                    3c:eb
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                45:C5:E2:2A:82:E5:36:92:E2:5E:6C:01:7A:42:47:A3:61:C0:4A:02
            X509v3 Authority Key Identifier: 
                F6:27:26:D7:91:68:49:99:F7:3C:30:74:84:E1:E3:20:B4:47:7F:E8
            X509v3 Subject Alternative Name: 
                URI:wireapp://%40alice_wire@wire.com, URI:wireapp://lYPMMhxlQyiJHg7f0X4tTg%21f92c673e9c08f466@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:82:22:d4:7f:46:07:0b:5b:72:db:af:d2:22:
        a0:53:92:d7:c7:aa:dd:60:d5:de:d4:80:5f:cb:1b:12:41:21:
        53:02:21:00:fc:51:ba:43:aa:6a:6a:50:13:70:77:24:e6:5b:
        bc:1d:51:bd:28:66:5b:fe:2f:8d:7b:d6:1c:8c:ab:49:8b:0c

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIBuDCCAV6gAwIBAgIQVYvujgrLroo+FS47z7V9XTAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMzI2MTEw
MzMxWhcNMzQwMzI0MTEwMzMxWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPcL
ftRCDLjpfvz3lwIK77AyR9jDhEAnzhN4F5GGmywORWHurYNjYavpc65kqq5VGKVN
hD3j3atDujY8p8nfvg6jZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBT2JybXkWhJmfc8MHSE4eMgtEd/6DAfBgNVHSMEGDAW
gBQ06fjoy0xr5Iz05d3TrZXmvrx4JDAKBggqhkjOPQQDAgNIADBFAiEAsvMotnAG
2KEaaweGSn5u2UTNl6cYwcdci86ys8DHgFICICGWmlBUOo9TB/9SHhE4eguU57h6
1raQVZReG6vgjxvv
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            55:8b:ee:8e:0a:cb:ae:8a:3e:15:2e:3b:cf:b5:7d:5d
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Mar 26 11:03:31 2024 GMT
            Not After : Mar 24 11:03:31 2034 GMT
        Subject: O=wire, CN=wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:f7:0b:7e:d4:42:0c:b8:e9:7e:fc:f7:97:02:0a:
                    ef:b0:32:47:d8:c3:84:40:27:ce:13:78:17:91:86:
                    9b:2c:0e:45:61:ee:ad:83:63:61:ab:e9:73:ae:64:
                    aa:ae:55:18:a5:4d:84:3d:e3:dd:ab:43:ba:36:3c:
                    a7:c9:df:be:0e
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                F6:27:26:D7:91:68:49:99:F7:3C:30:74:84:E1:E3:20:B4:47:7F:E8
            X509v3 Authority Key Identifier: 
                34:E9:F8:E8:CB:4C:6B:E4:8C:F4:E5:DD:D3:AD:95:E6:BE:BC:78:24
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:b2:f3:28:b6:70:06:d8:a1:1a:6b:07:86:4a:
        7e:6e:d9:44:cd:97:a7:18:c1:c7:5c:8b:ce:b2:b3:c0:c7:80:
        52:02:20:21:96:9a:50:54:3a:8f:53:07:ff:52:1e:11:38:7a:
        0b:94:e7:b8:7a:d6:b6:90:55:94:5e:1b:ab:e0:8f:1b:ef

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBkDCCATagAwIBAgIRAONuQfanMv87nj2wQ3uhom4wCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDMyNjEx
MDMzMFoXDTM0MDMyNDExMDMzMFowJjENMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMM
d2lyZSBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9sVQZP8gOB7d
H1eai1/JZylEUcSV6kKtFjC5k597EvoXOEwq1tna1ZYq+ntdOpJYW/wbQZ4c3iOP
wQwBl7+nFqNFMEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEw
HQYDVR0OBBYEFDTp+OjLTGvkjPTl3dOtlea+vHgkMAoGCCqGSM49BAMCA0gAMEUC
IE8Op0hygbufwR95TDBhyMStkWbIauufoyTQ3bqV9gV3AiEA/u6PHQy3mImYLe45
hGIeV3LGfIZdNZcBGFOoESNTL9g=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            e3:6e:41:f6:a7:32:ff:3b:9e:3d:b0:43:7b:a1:a2:6e
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Mar 26 11:03:30 2024 GMT
            Not After : Mar 24 11:03:30 2034 GMT
        Subject: O=wire, CN=wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:f6:c5:50:64:ff:20:38:1e:dd:1f:57:9a:8b:5f:
                    c9:67:29:44:51:c4:95:ea:42:ad:16:30:b9:93:9f:
                    7b:12:fa:17:38:4c:2a:d6:d9:da:d5:96:2a:fa:7b:
                    5d:3a:92:58:5b:fc:1b:41:9e:1c:de:23:8f:c1:0c:
                    01:97:bf:a7:16
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                34:E9:F8:E8:CB:4C:6B:E4:8C:F4:E5:DD:D3:AD:95:E6:BE:BC:78:24
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:4f:0e:a7:48:72:81:bb:9f:c1:1f:79:4c:30:61:
        c8:c4:ad:91:66:c8:6a:eb:9f:a3:24:d0:dd:ba:95:f6:05:77:
        02:21:00:fe:ee:8f:1d:0c:b7:98:89:98:2d:ee:39:84:62:1e:
        57:72:c6:7c:86:5d:35:97:01:18:53:a8:11:23:53:2f:d8

```

openssl verify chain ✅