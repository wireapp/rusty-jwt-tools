# Wire end to end identity example
Ed25519 - SHA256
```mermaid
sequenceDiagram
    autonumber
    wire-client->>+acme-server: GET /acme/wire-acme/directory
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: HEAD /acme/wire-acme/new-nonce
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/new-account
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/new-order
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/authz/iV5OrpkWrYDHbLeFlAwXk6bPAbunXhcc
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/authz/dVCVUoelDPedjjW4N7dPfazcMhFqav4W
    acme-server->>-wire-client: 200
    wire-client->>+wire-server: GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>+wire-server: POST /clients/4032539123756628277/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/challenge/iV5OrpkWrYDHbLeFlAwXk6bPAbunXhcc/nS1G5RVJITFMS9OYn2zU1GOKuWVRJU8h
    acme-server->>+wire-server: GET /.well-known/acme-challenge/dZadliwq2O3I5j2MHAxXkYT2y2jx3prI
    wire-server->>-acme-server: empty
    acme-server->>+wire-server: GET /.well-known/acme-challenge/yTdzwTxhJ776cngqaequ3GV6UbLse5VB
    wire-server->>-acme-server: empty
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/sj9qAuZoVL05zdjRWEzQfPUdrTqYkNSD
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/sj9qAuZoVL05zdjRWEzQfPUdrTqYkNSD/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/certificate/4ublxoIR1VDss079xCVQGNDK3cFYBASR
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://localhost:55964/acme/wire-acme/directory

```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://localhost:55964/acme/wire-acme/new-nonce",
  "newAccount": "https://localhost:55964/acme/wire-acme/new-account",
  "newOrder": "https://localhost:55964/acme/wire-acme/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://localhost:55964/acme/wire-acme/new-nonce

```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
replay-nonce: SmhlNWl1WVdtOGdUWXZONXU4Q1VVVFRSZUFJU2VWNGo
```
```json
"SmhlNWl1WVdtOGdUWXZONXU4Q1VVVFRSZUFJU2VWNGo"
```
#### 5. create a new account
```http request
POST https://localhost:55964/acme/wire-acme/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImMzZV9ia2xCZ2ZPRHprVkJ2c0ZKczhYVGZNQ3NhbmRHenZZQWFfTWZ4b00ifSwibm9uY2UiOiJTbWhsTldsMVdWZHRPR2RVV1haT05YVTRRMVZWVkZSU1pVRkpVMlZXTkdvIiwidXJsIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTU5NjQvYWNtZS93aXJlLWFjbWUvbmV3LWFjY291bnQifQ",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "IjKeb3lEuBMjRe0gh8-u_z1oVpsrhpDUAfqlThmHr57HOgMdqcTKTwUtWaDfEZwI3OCIb7vKWOwIcdW6uYA9DA"
}
...decoded...
{
  "protected": {
    "alg": "EdDSA",
    "typ": "JWT",
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "c3e_bklBgfODzkVBvsFJs8XTfMCsandGzvYAa_MfxoM"
    },
    "nonce": "SmhlNWl1WVdtOGdUWXZONXU4Q1VVVFRSZUFJU2VWNGo",
    "url": "https://localhost:55964/acme/wire-acme/new-account"
  },
  "payload": {
    "termsOfServiceAgreed": true,
    "contact": [
      "unknown@example.com"
    ],
    "onlyReturnExisting": false
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/account/EBb6YebtDKX6OgUkTmuQ17tq6bysDcBC
replay-nonce: eEdpZXNYa1YzNUNoS25TR251bnp6VzdtSEtnZld5dks
```
```json
{
  "status": "valid",
  "orders": "https://localhost:55964/acme/wire-acme/account/EBb6YebtDKX6OgUkTmuQ17tq6bysDcBC/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://localhost:55964/acme/wire-acme/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvRUJiNlllYnRES1g2T2dVa1RtdVExN3RxNmJ5c0RjQkMiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImVFZHBaWE5ZYTFZek5VTm9TMjVUUjI1MWJucDZWemR0U0V0blpsZDVka3MiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9uZXctb3JkZXIifQ",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoibG9naW4ud2lyZS5jb20ifSx7InR5cGUiOiJkbnMiLCJ2YWx1ZSI6IndpcmUuY29tIn1dLCJub3RCZWZvcmUiOiIyMDIzLTAxLTEwVDE1OjMwOjM1LjU3MDAzNFoiLCJub3RBZnRlciI6IjIwMjMtMDEtMTBUMTY6MzA6MzUuNTcwMDM0WiJ9",
  "signature": "qFTYBd96bUbSSX4-525cc8100EQmZnh7ig-b7SCcqq4k5xrUQ70rkAfY4BZy3pksHdRs-Ux0eDb8U_n4AKmDDA"
}
...decoded...
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://localhost:55964/acme/wire-acme/account/EBb6YebtDKX6OgUkTmuQ17tq6bysDcBC",
    "typ": "JWT",
    "nonce": "eEdpZXNYa1YzNUNoS25TR251bnp6VzdtSEtnZld5dks",
    "url": "https://localhost:55964/acme/wire-acme/new-order"
  },
  "payload": {
    "identifiers": [
      {
        "type": "dns",
        "value": "login.wire.com"
      },
      {
        "type": "dns",
        "value": "wire.com"
      }
    ],
    "notBefore": "2023-01-10T15:30:35.570034Z",
    "notAfter": "2023-01-10T16:30:35.570034Z"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/order/sj9qAuZoVL05zdjRWEzQfPUdrTqYkNSD
replay-nonce: emFwcFZDekkzU1hHbld4UHk4SUFFQmQ3bHZtNktFTEQ
```
```json
{
  "status": "pending",
  "finalize": "https://localhost:55964/acme/wire-acme/order/sj9qAuZoVL05zdjRWEzQfPUdrTqYkNSD/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "login.wire.com"
    },
    {
      "type": "dns",
      "value": "wire.com"
    }
  ],
  "authorizations": [
    "https://localhost:55964/acme/wire-acme/authz/iV5OrpkWrYDHbLeFlAwXk6bPAbunXhcc",
    "https://localhost:55964/acme/wire-acme/authz/dVCVUoelDPedjjW4N7dPfazcMhFqav4W"
  ],
  "expires": "2023-01-11T15:30:35Z",
  "notBefore": "2023-01-10T15:30:35.570034Z",
  "notAfter": "2023-01-10T16:30:35.570034Z"
}
```
### Display-name and handle already authorized
#### 9. fetch first challenge
```http request
POST https://localhost:55964/acme/wire-acme/authz/iV5OrpkWrYDHbLeFlAwXk6bPAbunXhcc
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvRUJiNlllYnRES1g2T2dVa1RtdVExN3RxNmJ5c0RjQkMiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImVtRndjRlpEZWtrelUxaEhibGQ0VUhrNFNVRkZRbVEzYkhadE5rdEZURVEiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9hdXRoei9pVjVPcnBrV3JZREhiTGVGbEF3WGs2YlBBYnVuWGhjYyJ9",
  "payload": "",
  "signature": "klPzk8tXYlL2DIJg6DZbXDkF5MZilncglwT79MsfwvrNzh_U9iCRa8_45Tw_0Wt-OFYGcTWvQ0kyV5UlDZHfBg"
}
```
#### 10. get back first challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/authz/iV5OrpkWrYDHbLeFlAwXk6bPAbunXhcc
replay-nonce: Y25BQ1IwcExETnN3ZGNxalZoc0V2aElWUkExa3pmRnE
```
```json
{
  "status": "pending",
  "expires": "2023-01-11T15:30:35Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/iV5OrpkWrYDHbLeFlAwXk6bPAbunXhcc/pXsZzHI0TT5q4WidQOO9UZE48r2o98tT",
      "status": "pending",
      "token": "dZadliwq2O3I5j2MHAxXkYT2y2jx3prI"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/iV5OrpkWrYDHbLeFlAwXk6bPAbunXhcc/nS1G5RVJITFMS9OYn2zU1GOKuWVRJU8h",
      "status": "pending",
      "token": "dZadliwq2O3I5j2MHAxXkYT2y2jx3prI"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/iV5OrpkWrYDHbLeFlAwXk6bPAbunXhcc/OoGricZFnvpLJRGiVVJw6k0vhTOCn4oY",
      "status": "pending",
      "token": "dZadliwq2O3I5j2MHAxXkYT2y2jx3prI"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "login.wire.com"
  }
}
```
### ACME provides a Wire client ID challenge
#### 11. fetch second challenge
```http request
POST https://localhost:55964/acme/wire-acme/authz/dVCVUoelDPedjjW4N7dPfazcMhFqav4W
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvRUJiNlllYnRES1g2T2dVa1RtdVExN3RxNmJ5c0RjQkMiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlkyNUJRMUl3Y0V4RVRuTjNaR054YWxab2MwVjJhRWxXVWtFeGEzcG1SbkUiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9hdXRoei9kVkNWVW9lbERQZWRqalc0TjdkUGZhemNNaEZxYXY0VyJ9",
  "payload": "",
  "signature": "oJxJaUsvYxPbCC_-FQTuko0AZI20P4zPIHhhfWJ1td-ADTOFi6HCFnpqsRDoQ6OZXKoqGLeFmBqjpSZyhFhwAg"
}
```
#### 12. get back second challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/authz/dVCVUoelDPedjjW4N7dPfazcMhFqav4W
replay-nonce: bHFVRFB2Q0FXVTc1ZTIxZVdGdmV6WkxsVmE3RGFmZUE
```
```json
{
  "status": "pending",
  "expires": "2023-01-11T15:30:35Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/dVCVUoelDPedjjW4N7dPfazcMhFqav4W/aeubEakKOMENWHJRYOoFPWcWbq6PltGy",
      "status": "pending",
      "token": "yTdzwTxhJ776cngqaequ3GV6UbLse5VB"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/dVCVUoelDPedjjW4N7dPfazcMhFqav4W/EReowIYwh4QCeAuoIH4BN2yKrknmEWuj",
      "status": "pending",
      "token": "yTdzwTxhJ776cngqaequ3GV6UbLse5VB"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/dVCVUoelDPedjjW4N7dPfazcMhFqav4W/lo1NYtxF6RGqmRpuvCd3qdONcOP8qlBP",
      "status": "pending",
      "token": "yTdzwTxhJ776cngqaequ3GV6UbLse5VB"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "wire.com"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 13. fetch a nonce from wire-server
```http request
GET http://localhost:60412/clients/token/nonce

```
#### 14. get wire-server nonce
```http request
200

```
```json
"Vldra0RrQ3dpbmxJOGV6T1RWdUFDVWN1cnhOYXhLa0Y"
```
#### 15. create the client Dpop token with both nonces
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiYzNlX2JrbEJnZk9EemtWQnZzRkpzOFhUZk1Dc2FuZEd6dllBYV9NZnhvTSJ9fQ.eyJpYXQiOjE2NzMzNjQ2MzUsImV4cCI6MTY3MzQ1MTAzNSwibmJmIjoxNjczMzY0NjM1LCJzdWIiOiJpbTp3aXJlYXBwOk1qUXhNR1ZrTW1KaE1tWXpORFJrWkRsaE1EYzVNRFUzWVdSbE9UQTJNRFkvMzdmNjc0ZjdiZTYwZjkzNUB3aXJlLmNvbSIsImp0aSI6Ijg1N2FjMjg3LWUxM2QtNDA4YS04MjNjLWFmNGE5NmI2N2UwMCIsIm5vbmNlIjoiVmxkcmEwUnJRM2RwYm14Sk9HVjZUMVJXZFVGRFZXTjFjbmhPWVhoTGEwWSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vbG9jYWxob3N0OjYwNDEyL2NsaWVudHMvNDAzMjUzOTEyMzc1NjYyODI3Ny9hY2Nlc3MtdG9rZW4iLCJjaGFsIjoiZFphZGxpd3EyTzNJNWoyTUhBeFhrWVQyeTJqeDNwckkifQ.2gG2Y5ZrVnLMQtBavCo8KniEqXEuHt24l4wI1OjDbqJC3pJP_A3_iOda_ZngnDjUZRFKqrvHoOt8tT--qD_FCQ)
```http request
POST http://localhost:60412/clients/4032539123756628277/access-token

```
#### 16. get a Dpop access token from wire-server
```http request
200

```
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkVybnFlUzZVQThOMnBNNEpwSFlKVl9SQTdmc2dFLTN6LUowQ3RLZmZQTXcifX0.eyJpYXQiOjE2NzMzNjQ2MzUsImV4cCI6MTY4MTE0MDYzNSwibmJmIjoxNjczMzY0NjM1LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjYwNDEyL2NsaWVudHMvNDAzMjUzOTEyMzc1NjYyODI3Ny9hY2Nlc3MtdG9rZW4iLCJzdWIiOiJpbTp3aXJlYXBwOk1qUXhNR1ZrTW1KaE1tWXpORFJrWkRsaE1EYzVNRFUzWVdSbE9UQTJNRFkvMzdmNjc0ZjdiZTYwZjkzNUB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NjA0MTIvY2xpZW50cy80MDMyNTM5MTIzNzU2NjI4Mjc3L2FjY2Vzcy10b2tlbiIsImp0aSI6Ijk2YTgyMTBlLTZhYzItNDI3Yy05MjhhLWE2NDljZWFmY2I3ZCIsIm5vbmNlIjoiVmxkcmEwUnJRM2RwYm14Sk9HVjZUMVJXZFVGRFZXTjFjbmhPWVhoTGEwWSIsImNoYWwiOiJkWmFkbGl3cTJPM0k1ajJNSEF4WGtZVDJ5Mmp4M3BySSIsImNuZiI6eyJraWQiOiI4T3N3cnhhUjVpbmdDVWlqZjFvX01QTEdFSGhFdEg4TlVqeERLWlpWU2Q4In0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pWXpObFgySnJiRUpuWms5RWVtdFdRblp6Umtwek9GaFVaazFEYzJGdVpFZDZkbGxCWVY5TlpuaHZUU0o5ZlEuZXlKcFlYUWlPakUyTnpNek5qUTJNelVzSW1WNGNDSTZNVFkzTXpRMU1UQXpOU3dpYm1KbUlqb3hOamN6TXpZME5qTTFMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndPazFxVVhoTlIxWnJUVzFLYUUxdFdYcE9SRkpyV2tSc2FFMUVZelZOUkZVeldWZFNiRTlVUVRKTlJGa3ZNemRtTmpjMFpqZGlaVFl3Wmprek5VQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqZzFOMkZqTWpnM0xXVXhNMlF0TkRBNFlTMDRNak5qTFdGbU5HRTVObUkyTjJVd01DSXNJbTV2Ym1ObElqb2lWbXhrY21Fd1VuSlJNMlJ3WW0xNFNrOUhWalpVTVZKWFpGVkdSRlpYVGpGamJtaFBXVmhvVEdFd1dTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZiRzlqWVd4b2IzTjBPall3TkRFeUwyTnNhV1Z1ZEhNdk5EQXpNalV6T1RFeU16YzFOall5T0RJM055OWhZMk5sYzNNdGRHOXJaVzRpTENKamFHRnNJam9pWkZwaFpHeHBkM0V5VHpOSk5Xb3lUVWhCZUZocldWUXllVEpxZUROd2Nra2lmUS4yZ0cyWTVaclZuTE1RdEJhdkNvOEtuaUVxWEV1SHQyNGw0d0kxT2pEYnFKQzNwSlBfQTNfaU9kYV9abmduRGpVWlJGS3FydkhvT3Q4dFQtLXFEX0ZDUSIsImNsaWVudF9pZCI6ImltOndpcmVhcHA6TWpReE1HVmtNbUpoTW1Zek5EUmtaRGxoTURjNU1EVTNZV1JsT1RBMk1EWS8zN2Y2NzRmN2JlNjBmOTM1QHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjMsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.mMqWlYlbDWGCfwZEInJcp3Vhy530ojO6Og6CyrBexm-JeeO-6DoReXY1IGGHtLxIFBjjfiyLbWaNEuUylWe1CA)
### Client provides access token
#### 17. send DPoP access token to acme server to have it validated
```http request
POST https://localhost:55964/acme/wire-acme/challenge/iV5OrpkWrYDHbLeFlAwXk6bPAbunXhcc/nS1G5RVJITFMS9OYn2zU1GOKuWVRJU8h
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvRUJiNlllYnRES1g2T2dVa1RtdVExN3RxNmJ5c0RjQkMiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImJIRlZSRkIyUTBGWFZUYzFaVEl4WlZkR2RtVjZXa3hzVm1FM1JHRm1aVUUiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9jaGFsbGVuZ2UvaVY1T3Jwa1dyWURIYkxlRmxBd1hrNmJQQWJ1blhoY2MvblMxRzVSVkpJVEZNUzlPWW4yelUxR09LdVdWUkpVOGgifQ",
  "payload": "",
  "signature": "FMm9384tHYaV_wZ_uUZ6aJc2rSQsDLXCEpKL4RygvHVcqjv--w1WFzXDj-r-MnFnA_43hdkFyh2qoxVsmYMVCA"
}
```
#### 18. acme server verifies client-id with an http challenge
```http request
GET http://wire.com/.well-known/acme-challenge/dZadliwq2O3I5j2MHAxXkYT2y2jx3prI

```

#### 19. acme server verifies handle + display-name with an OIDC challenge
```http request
GET http://wire.com/.well-known/acme-challenge/yTdzwTxhJ776cngqaequ3GV6UbLse5VB

```

#### 20. both challenges are valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
link: <https://localhost:55964/acme/wire-acme/authz/iV5OrpkWrYDHbLeFlAwXk6bPAbunXhcc>;rel="up"
location: https://localhost:55964/acme/wire-acme/challenge/iV5OrpkWrYDHbLeFlAwXk6bPAbunXhcc/nS1G5RVJITFMS9OYn2zU1GOKuWVRJU8h
replay-nonce: UHk1UkRpWEVpZ1ZuTkozY01nMHdNVmd2QmJucmtWeEY
```
```json
{
  "type": "http-01",
  "url": "https://localhost:55964/acme/wire-acme/challenge/iV5OrpkWrYDHbLeFlAwXk6bPAbunXhcc/nS1G5RVJITFMS9OYn2zU1GOKuWVRJU8h",
  "status": "valid",
  "token": "dZadliwq2O3I5j2MHAxXkYT2y2jx3prI"
}
```
### Client presents a CSR and gets its certificate
#### 21. verify the status of the order
```http request
POST https://localhost:55964/acme/wire-acme/order/sj9qAuZoVL05zdjRWEzQfPUdrTqYkNSD
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvRUJiNlllYnRES1g2T2dVa1RtdVExN3RxNmJ5c0RjQkMiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlZFVlhNekpWVHpCa1drZFdkM2hTVDA1M1RqQjZORzVaV1VwbU4yNVJORlkiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9vcmRlci9zajlxQXVab1ZMMDV6ZGpSV0V6UWZQVWRyVHFZa05TRCJ9",
  "payload": "",
  "signature": "iNWLIQ-CSV5VMh6qXGnyjSIBxk5UXf-3NSB0HwPNmWDMMEAH1gnCKJhncM_AXHhwElWZZDOO5HrPcEVGoCHFCA"
}
```
#### 22. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/order/sj9qAuZoVL05zdjRWEzQfPUdrTqYkNSD
replay-nonce: ZVZ6R3JCVDFaM2pHeEN2WXMwV3Z2dVNwVlI4RFhOdnA
```
```json
{
  "status": "ready",
  "finalize": "https://localhost:55964/acme/wire-acme/order/sj9qAuZoVL05zdjRWEzQfPUdrTqYkNSD/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "login.wire.com"
    },
    {
      "type": "dns",
      "value": "wire.com"
    }
  ],
  "authorizations": [
    "https://localhost:55964/acme/wire-acme/authz/iV5OrpkWrYDHbLeFlAwXk6bPAbunXhcc",
    "https://localhost:55964/acme/wire-acme/authz/dVCVUoelDPedjjW4N7dPfazcMhFqav4W"
  ],
  "expires": "2023-01-11T15:30:35Z",
  "notBefore": "2023-01-10T15:30:35.570034Z",
  "notAfter": "2023-01-10T16:30:35.570034Z"
}
```
#### 23. create a CSR and call finalize url
```http request
POST https://localhost:55964/acme/wire-acme/order/sj9qAuZoVL05zdjRWEzQfPUdrTqYkNSD/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvRUJiNlllYnRES1g2T2dVa1RtdVExN3RxNmJ5c0RjQkMiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlpWWjZSM0pDVkRGYU0ycEhlRU4yV1hNd1YzWjJkVk53VmxJNFJGaE9kbkEiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9vcmRlci9zajlxQXVab1ZMMDV6ZGpSV0V6UWZQVWRyVHFZa05TRC9maW5hbGl6ZSJ9",
  "payload": "eyJjc3IiOiJNSUcxTUdrQ0FRQXdBREFxTUFVR0F5dGxjQU1oQUhOM3YyNUpRWUh6Zzg1RlFiN0JTYlBGMDN6QXJHcDNSczcyQUd2ekg4YURvRFl3TkFZSktvWklodmNOQVFrT01TY3dKVEFqQmdOVkhSRUVIREFhZ2doM2FYSmxMbU52YllJT2JHOW5hVzR1ZDJseVpTNWpiMjB3QlFZREsyVndBMEVBUjNwQ052b2VGQjZZUkpFR0p5a25UdU44UGxBZzFTdlE2MnBmZG15WTQtWi00R3R1Q1FaUkp0ekYwOUhYTkZYV3NibUtEZEp1cHRkOHlHOEFlbkkyQncifQ",
  "signature": "KC_uQ5SO2qYHH6HrvULLNdEfN4IXF-8HLhr0y8DOcHdyXhl0sMg0ja43NCP78jv4JP5VdWHoZ3KbYqeTQvbKAw"
}
...decoded...
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://localhost:55964/acme/wire-acme/account/EBb6YebtDKX6OgUkTmuQ17tq6bysDcBC",
    "typ": "JWT",
    "nonce": "ZVZ6R3JCVDFaM2pHeEN2WXMwV3Z2dVNwVlI4RFhOdnA",
    "url": "https://localhost:55964/acme/wire-acme/order/sj9qAuZoVL05zdjRWEzQfPUdrTqYkNSD/finalize"
  },
  "payload": {
    "csr": "MIG1MGkCAQAwADAqMAUGAytlcAMhAHN3v25JQYHzg85FQb7BSbPF03zArGp3Rs72AGvzH8aDoDYwNAYJKoZIhvcNAQkOMScwJTAjBgNVHREEHDAaggh3aXJlLmNvbYIObG9naW4ud2lyZS5jb20wBQYDK2VwA0EAR3pCNvoeFB6YRJEGJyknTuN8PlAg1SvQ62pfdmyY4-Z-4GtuCQZRJtzF09HXNFXWsbmKDdJuptd8yG8AenI2Bw"
  }
}
```
#### 24. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/order/sj9qAuZoVL05zdjRWEzQfPUdrTqYkNSD
replay-nonce: aE9FckJlZXVjOFk0NnVQN1h6OUM3dmQ1WTdTR1N3bFo
```
```json
{
  "certificate": "https://localhost:55964/acme/wire-acme/certificate/4ublxoIR1VDss079xCVQGNDK3cFYBASR",
  "status": "valid",
  "finalize": "https://localhost:55964/acme/wire-acme/order/sj9qAuZoVL05zdjRWEzQfPUdrTqYkNSD/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "login.wire.com"
    },
    {
      "type": "dns",
      "value": "wire.com"
    }
  ],
  "authorizations": [
    "https://localhost:55964/acme/wire-acme/authz/iV5OrpkWrYDHbLeFlAwXk6bPAbunXhcc",
    "https://localhost:55964/acme/wire-acme/authz/dVCVUoelDPedjjW4N7dPfazcMhFqav4W"
  ],
  "expires": "2023-01-11T15:30:35Z",
  "notBefore": "2023-01-10T15:30:35.570034Z",
  "notAfter": "2023-01-10T16:30:35.570034Z"
}
```
#### 25. fetch the certificate
```http request
POST https://localhost:55964/acme/wire-acme/certificate/4ublxoIR1VDss079xCVQGNDK3cFYBASR
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvRUJiNlllYnRES1g2T2dVa1RtdVExN3RxNmJ5c0RjQkMiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImFFOUZja0psWlhWak9GazBOblZRTjFoNk9VTTNkbVExV1RkVFIxTjNiRm8iLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9jZXJ0aWZpY2F0ZS80dWJseG9JUjFWRHNzMDc5eENWUUdOREszY0ZZQkFTUiJ9",
  "payload": "",
  "signature": "EGuYNCr0EcKISB0uQZzFOJTWpHDhWkNSxf2eEDMaj9TWy-Eidulq3-4H22JZ5eHDvaMtQ0sbsQMNg_4fTeI2AA"
}
```
#### 26. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
replay-nonce: djlTU2RZb0h6WmF4U1R0QXp1UER6ZURzSExlT3FNTEs
```
```json
[
  "MIIBvjCCAWOgAwIBAgIRAKomm5ajWa2oB3Zamy8CRSwwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMwMTEwMTUzMDM1WhcNMjMwMTEwMTYzMDM1WjAAMCowBQYDK2VwAyEAc3e/bklB\ngfODzkVBvsFJs8XTfMCsandGzvYAa/MfxoOjgb4wgbswDgYDVR0PAQH/BAQDAgeA\nMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUNClgQ+L1\n0sf8DQHljZj7q9jHGrYwHwYDVR0jBBgwFoAUcVj0JPchJ9PZfPZ9Jw4ufjl2I8Uw\nJgYDVR0RAQH/BBwwGoIObG9naW4ud2lyZS5jb22CCHdpcmUuY29tMCIGDCsGAQQB\ngqRkxihAAQQSMBACAQYECXdpcmUtYWNtZQQAMAoGCCqGSM49BAMCA0kAMEYCIQC/\nc86OrbNfLA2TgeKpDtSokLAB1/aR1syp+MfLOuERRQIhAMUCtRXhVkzYRvxszvyT\n/kkiBx4gyVje8HAgh2mLe5ou",
  "MIIBuDCCAV6gAwIBAgIQed+5/kGfM5vfxxEX1t1UGDAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwMTEwMTUz\nMDMyWhcNMzMwMTA3MTUzMDMyWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLA+\n9Dky+wBtuuVr4HhDmpWycxRPF0iv28bqfuM38jLJc8r3Gb0melSimjkZftihVAdk\nm4xOcx/NnQny3jNhmqCjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBRxWPQk9yEn09l89n0nDi5+OXYjxTAfBgNVHSMEGDAW\ngBQPIjaIafwYTbpN50iU9ET8BLkSRjAKBggqhkjOPQQDAgNIADBFAiEAqxR5MV6R\n5QYqw290T4M7DJe7vuhwHVZBxb7TvfDRzt8CIB36nXKJOaf6Hze2BWlvC0srMZxO\nW7WA0XZD//8O2YWQ"
]
```
P256 - SHA256
```mermaid
sequenceDiagram
    autonumber
    wire-client->>+acme-server: GET /acme/wire-acme/directory
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: HEAD /acme/wire-acme/new-nonce
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/new-account
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/new-order
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/authz/1fJYIDuOaF5QDhB3scSxgjiFHS9GM7JU
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/authz/lZjrwuuiuNHv4wajmFpBMSQT37NLfV2n
    acme-server->>-wire-client: 200
    wire-client->>+wire-server: GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>+wire-server: POST /clients/12831139479195323442/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/challenge/1fJYIDuOaF5QDhB3scSxgjiFHS9GM7JU/66KBICWLrzxxolJlBH9sJUEYvkWt40US
    acme-server->>+wire-server: GET /.well-known/acme-challenge/W8gbXLNB5R0WOGXgNJMiM9EEh0SURE5W
    wire-server->>-acme-server: empty
    acme-server->>+wire-server: GET /.well-known/acme-challenge/Un9DTRTf9YJKYvuEANJcnYxDeGVOx1mt
    wire-server->>-acme-server: empty
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/gJpx9XjxqVCp5S66gX9latROkS2CrBbM
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/gJpx9XjxqVCp5S66gX9latROkS2CrBbM/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/certificate/BprMwjVhN69BAihopUjswHVMRChwyK3B
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://localhost:55964/acme/wire-acme/directory

```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://localhost:55964/acme/wire-acme/new-nonce",
  "newAccount": "https://localhost:55964/acme/wire-acme/new-account",
  "newOrder": "https://localhost:55964/acme/wire-acme/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://localhost:55964/acme/wire-acme/new-nonce

```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
replay-nonce: VWFVSWg5WWQxZkdEM3FXVFNpY1ZZZG00NGZ6amlMOGw
```
```json
"VWFVSWg5WWQxZkdEM3FXVFNpY1ZZZG00NGZ6amlMOGw"
```
#### 5. create a new account
```http request
POST https://localhost:55964/acme/wire-acme/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IkJVRExTWHZjVG5aRnNCSnpKOFFjNXZmVFROLVl3aFJudy03VDBwVHVoRmciLCJ5IjoiU1NrQ3lFVjVaN1REdHFJV3JBTlpQQktaV042aHdQLUZMdVM5c245emxDcyJ9LCJub25jZSI6IlZXRlZTV2c1V1dReFprZEVNM0ZYVkZOcFkxWlpaRzAwTkdaNmFtbE1PR3ciLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9uZXctYWNjb3VudCJ9",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "rBORcZZApdkxWRo6IMmx3eV6FX93biZ1lwMsJkFpulc-M7Jt4IvvE9YlmGEfRh0Nj7tIKmiw1JEICkFAbJRhOQ"
}
...decoded...
{
  "protected": {
    "alg": "ES256",
    "typ": "JWT",
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "BUDLSXvcTnZFsBJzJ8Qc5vfTTN-YwhRnw-7T0pTuhFg",
      "y": "SSkCyEV5Z7TDtqIWrANZPBKZWN6hwP-FLuS9sn9zlCs"
    },
    "nonce": "VWFVSWg5WWQxZkdEM3FXVFNpY1ZZZG00NGZ6amlMOGw",
    "url": "https://localhost:55964/acme/wire-acme/new-account"
  },
  "payload": {
    "termsOfServiceAgreed": true,
    "contact": [
      "unknown@example.com"
    ],
    "onlyReturnExisting": false
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/account/vEvdjKEQMkrOs7Nkm9VOKEBSzFa4phBQ
replay-nonce: TlRrdUlCb2d0RHI3YWpZa242bHlacEhBak12dk5JYmI
```
```json
{
  "status": "valid",
  "orders": "https://localhost:55964/acme/wire-acme/account/vEvdjKEQMkrOs7Nkm9VOKEBSzFa4phBQ/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://localhost:55964/acme/wire-acme/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvdkV2ZGpLRVFNa3JPczdOa205Vk9LRUJTekZhNHBoQlEiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlRsUnJkVWxDYjJkMFJISTNZV3BaYTI0MmJIbGFjRWhCYWsxMmRrNUpZbUkiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9uZXctb3JkZXIifQ",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoibG9naW4ud2lyZS5jb20ifSx7InR5cGUiOiJkbnMiLCJ2YWx1ZSI6IndpcmUuY29tIn1dLCJub3RCZWZvcmUiOiIyMDIzLTAxLTEwVDE1OjMwOjM4LjkxOTI1NFoiLCJub3RBZnRlciI6IjIwMjMtMDEtMTBUMTY6MzA6MzguOTE5MjU0WiJ9",
  "signature": "m8Vo-QhY6oOA7c-PbTpjfFztyoxwkKGUjJnstBRsl04JntCPYzFbYHBXW5LeVyIg0Ohv3DL6JG_qkNfFgF8DgA"
}
...decoded...
{
  "protected": {
    "alg": "ES256",
    "kid": "https://localhost:55964/acme/wire-acme/account/vEvdjKEQMkrOs7Nkm9VOKEBSzFa4phBQ",
    "typ": "JWT",
    "nonce": "TlRrdUlCb2d0RHI3YWpZa242bHlacEhBak12dk5JYmI",
    "url": "https://localhost:55964/acme/wire-acme/new-order"
  },
  "payload": {
    "identifiers": [
      {
        "type": "dns",
        "value": "login.wire.com"
      },
      {
        "type": "dns",
        "value": "wire.com"
      }
    ],
    "notBefore": "2023-01-10T15:30:38.919254Z",
    "notAfter": "2023-01-10T16:30:38.919254Z"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/order/gJpx9XjxqVCp5S66gX9latROkS2CrBbM
replay-nonce: SU0xUTJ2SDdzSFZCeFM1a3FYYTBpbnRNQU5UMVRBTW4
```
```json
{
  "status": "pending",
  "finalize": "https://localhost:55964/acme/wire-acme/order/gJpx9XjxqVCp5S66gX9latROkS2CrBbM/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "login.wire.com"
    },
    {
      "type": "dns",
      "value": "wire.com"
    }
  ],
  "authorizations": [
    "https://localhost:55964/acme/wire-acme/authz/1fJYIDuOaF5QDhB3scSxgjiFHS9GM7JU",
    "https://localhost:55964/acme/wire-acme/authz/lZjrwuuiuNHv4wajmFpBMSQT37NLfV2n"
  ],
  "expires": "2023-01-11T15:30:38Z",
  "notBefore": "2023-01-10T15:30:38.919254Z",
  "notAfter": "2023-01-10T16:30:38.919254Z"
}
```
### Display-name and handle already authorized
#### 9. fetch first challenge
```http request
POST https://localhost:55964/acme/wire-acme/authz/1fJYIDuOaF5QDhB3scSxgjiFHS9GM7JU
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvdkV2ZGpLRVFNa3JPczdOa205Vk9LRUJTekZhNHBoQlEiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlNVMHhVVEoyU0RkelNGWkNlRk0xYTNGWVlUQnBiblJOUVU1VU1WUkJUVzQiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9hdXRoei8xZkpZSUR1T2FGNVFEaEIzc2NTeGdqaUZIUzlHTTdKVSJ9",
  "payload": "",
  "signature": "4SklAQs2nXX5kuKtlZMuBxIIpiik1i2esC__YPkcBe-UlKoz7064UlSg_fKJNwV9IK648AmONnJ3WU-RmQmdgg"
}
```
#### 10. get back first challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/authz/1fJYIDuOaF5QDhB3scSxgjiFHS9GM7JU
replay-nonce: VE9qTEtxN1pVVWFEeElkNjRaUVJmU3ZuYmhweHZmVDI
```
```json
{
  "status": "pending",
  "expires": "2023-01-11T15:30:38Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/1fJYIDuOaF5QDhB3scSxgjiFHS9GM7JU/XrNyUrV06b6YdT2Cu4qeYQhsh5g7UrWu",
      "status": "pending",
      "token": "W8gbXLNB5R0WOGXgNJMiM9EEh0SURE5W"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/1fJYIDuOaF5QDhB3scSxgjiFHS9GM7JU/66KBICWLrzxxolJlBH9sJUEYvkWt40US",
      "status": "pending",
      "token": "W8gbXLNB5R0WOGXgNJMiM9EEh0SURE5W"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/1fJYIDuOaF5QDhB3scSxgjiFHS9GM7JU/JJVRmmYLMAe3HokIF0o3cqB09wtkDayj",
      "status": "pending",
      "token": "W8gbXLNB5R0WOGXgNJMiM9EEh0SURE5W"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "login.wire.com"
  }
}
```
### ACME provides a Wire client ID challenge
#### 11. fetch second challenge
```http request
POST https://localhost:55964/acme/wire-acme/authz/lZjrwuuiuNHv4wajmFpBMSQT37NLfV2n
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvdkV2ZGpLRVFNa3JPczdOa205Vk9LRUJTekZhNHBoQlEiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlZFOXFURXR4TjFwVlZXRkVlRWxrTmpSYVVWSm1VM1p1WW1od2VIWm1WREkiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9hdXRoei9sWmpyd3V1aXVOSHY0d2FqbUZwQk1TUVQzN05MZlYybiJ9",
  "payload": "",
  "signature": "ZhpeYsHSpuqr6kF8rfLYz77TwTnDx3MIZ2Y2Cp8thQ60WAZOPCKKYV4jhUXpvpB-xET4VkYZ3julVq2d3Kf9BA"
}
```
#### 12. get back second challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/authz/lZjrwuuiuNHv4wajmFpBMSQT37NLfV2n
replay-nonce: c0hZVUVmOU9pejE1dEVVcFhuUFlOWllMUnpiMGNablM
```
```json
{
  "status": "pending",
  "expires": "2023-01-11T15:30:38Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/lZjrwuuiuNHv4wajmFpBMSQT37NLfV2n/kvoqBDMfShJ6jqUZ3T4vWAtwsME3lNdw",
      "status": "pending",
      "token": "Un9DTRTf9YJKYvuEANJcnYxDeGVOx1mt"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/lZjrwuuiuNHv4wajmFpBMSQT37NLfV2n/l8smH2l2XaP1jdfolYpIKWXp085ex3pu",
      "status": "pending",
      "token": "Un9DTRTf9YJKYvuEANJcnYxDeGVOx1mt"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/lZjrwuuiuNHv4wajmFpBMSQT37NLfV2n/tOZiI1eL5Z79p95X9ZPhYbYWXSRBGBhr",
      "status": "pending",
      "token": "Un9DTRTf9YJKYvuEANJcnYxDeGVOx1mt"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "wire.com"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 13. fetch a nonce from wire-server
```http request
GET http://localhost:60412/clients/token/nonce

```
#### 14. get wire-server nonce
```http request
200

```
```json
"aGJUeUtGeXdhR1BTZkJ2cGJOZXVGdHk2ZWNmR0tYN0g"
```
#### 15. create the client Dpop token with both nonces
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiQlVETFNYdmNUblpGc0JKeko4UWM1dmZUVE4tWXdoUm53LTdUMHBUdWhGZyIsInkiOiJTU2tDeUVWNVo3VER0cUlXckFOWlBCS1pXTjZod1AtRkx1Uzlzbjl6bENzIn19.eyJpYXQiOjE2NzMzNjQ2MzgsImV4cCI6MTY3MzQ1MTAzOCwibmJmIjoxNjczMzY0NjM4LCJzdWIiOiJpbTp3aXJlYXBwOk5UVXhZbVU1T1dWaE56ZGtORFJrT1Rnd05qRXpNakV6WVdNMlkyTmhOREkvYjIxMTVkNWZjMGVkOGMzMkB3aXJlLmNvbSIsImp0aSI6ImRjZmM3ZjFiLTIxNTAtNDNmZC04Njg4LTkzMzliNjg1MThjYyIsIm5vbmNlIjoiYUdKVWVVdEdlWGRoUjFCVFprSjJjR0pPWlhWR2RIazJaV05tUjB0WU4wZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vbG9jYWxob3N0OjYwNDEyL2NsaWVudHMvMTI4MzExMzk0NzkxOTUzMjM0NDIvYWNjZXNzLXRva2VuIiwiY2hhbCI6Ilc4Z2JYTE5CNVIwV09HWGdOSk1pTTlFRWgwU1VSRTVXIn0.BMpKSQPGNZ0jFxTAAj5TPVK7xNEebXrX5CbmyF4MTYaYKypxV80zjrAyt8-HdDZMgQGb7zlhHyuXMhqr1qD-dA)
```http request
POST http://localhost:60412/clients/12831139479195323442/access-token

```
#### 16. get a Dpop access token from wire-server
```http request
200

```
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ikx2RlRDWWJiUDkzY3R4YzRDNGFVUE16endwWDFtTzRJOHA0amRDcEdBSnciLCJ5IjoiQUZYMGVqVlpZZ2F1UGpEeWtObFF4TlU3V2tsQ3VOb2haeFFmdDh0YnpvSSJ9fQ.eyJpYXQiOjE2NzMzNjQ2MzgsImV4cCI6MTY4MTE0MDYzOCwibmJmIjoxNjczMzY0NjM4LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjYwNDEyL2NsaWVudHMvMTI4MzExMzk0NzkxOTUzMjM0NDIvYWNjZXNzLXRva2VuIiwic3ViIjoiaW06d2lyZWFwcDpOVFV4WW1VNU9XVmhOemRrTkRSa09UZ3dOakV6TWpFellXTTJZMk5oTkRJL2IyMTE1ZDVmYzBlZDhjMzJAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjYwNDEyL2NsaWVudHMvMTI4MzExMzk0NzkxOTUzMjM0NDIvYWNjZXNzLXRva2VuIiwianRpIjoiZDA3ODAyYTktZDg0Zi00MGMwLTlkNGQtYTViMDU1YTkyMGRmIiwibm9uY2UiOiJhR0pVZVV0R2VYZGhSMUJUWmtKMmNHSk9aWFZHZEhrMlpXTm1SMHRZTjBnIiwiY2hhbCI6Ilc4Z2JYTE5CNVIwV09HWGdOSk1pTTlFRWgwU1VSRTVXIiwiY25mIjp7ImtpZCI6ImVlc2xxSEF1SUt3b2NfM2tPa1VmN1lrbHdQMnJpV1JhN2hmckxMWTZRVUUifSwicHJvb2YiOiJleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVFsVkVURk5ZZG1OVWJscEdjMEpLZWtvNFVXTTFkbVpVVkU0dFdYZG9VbTUzTFRkVU1IQlVkV2hHWnlJc0lua2lPaUpUVTJ0RGVVVldOVm8zVkVSMGNVbFhja0ZPV2xCQ1MxcFhUalpvZDFBdFJreDFVemx6YmpsNmJFTnpJbjE5LmV5SnBZWFFpT2pFMk56TXpOalEyTXpnc0ltVjRjQ0k2TVRZM016UTFNVEF6T0N3aWJtSm1Jam94Tmpjek16WTBOak00TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3T2s1VVZYaFpiVlUxVDFkV2FFNTZaR3RPUkZKclQxUm5kMDVxUlhwTmFrVjZXVmROTWxreVRtaE9SRWt2WWpJeE1UVmtOV1pqTUdWa09HTXpNa0IzYVhKbExtTnZiU0lzSW1wMGFTSTZJbVJqWm1NM1pqRmlMVEl4TlRBdE5ETm1aQzA0TmpnNExUa3pNemxpTmpnMU1UaGpZeUlzSW01dmJtTmxJam9pWVVkS1ZXVlZkRWRsV0dSb1VqRkNWRnByU2pKalIwcFBXbGhXUjJSSWF6SmFWMDV0VWpCMFdVNHdaeUlzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2Ykc5allXeG9iM04wT2pZd05ERXlMMk5zYVdWdWRITXZNVEk0TXpFeE16azBOemt4T1RVek1qTTBOREl2WVdOalpYTnpMWFJ2YTJWdUlpd2lZMmhoYkNJNklsYzRaMkpZVEU1Q05WSXdWMDlIV0dkT1NrMXBUVGxGUldnd1UxVlNSVFZYSW4wLkJNcEtTUVBHTlowakZ4VEFBajVUUFZLN3hORWViWHJYNUNibXlGNE1UWWFZS3lweFY4MHpqckF5dDgtSGREWk1nUUdiN3psaEh5dVhNaHFyMXFELWRBIiwiY2xpZW50X2lkIjoiaW06d2lyZWFwcDpOVFV4WW1VNU9XVmhOemRrTkRSa09UZ3dOakV6TWpFellXTTJZMk5oTkRJL2IyMTE1ZDVmYzBlZDhjMzJAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6Mywic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.GnigbWISRnkJ7074TCBA_YhqQg_LebEz3_hMoNRbzorsF4cYC84gO-C9kxE-Rd1EvpBM00_Pf5GyJFsR7pS2vg)
### Client provides access token
#### 17. send DPoP access token to acme server to have it validated
```http request
POST https://localhost:55964/acme/wire-acme/challenge/1fJYIDuOaF5QDhB3scSxgjiFHS9GM7JU/66KBICWLrzxxolJlBH9sJUEYvkWt40US
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvdkV2ZGpLRVFNa3JPczdOa205Vk9LRUJTekZhNHBoQlEiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImMwaFpWVVZtT1U5cGVqRTFkRVZWY0ZodVVGbE9XbGxNVW5waU1HTmFibE0iLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9jaGFsbGVuZ2UvMWZKWUlEdU9hRjVRRGhCM3NjU3hnamlGSFM5R003SlUvNjZLQklDV0xyenh4b2xKbEJIOXNKVUVZdmtXdDQwVVMifQ",
  "payload": "",
  "signature": "vJ0cSvVAgTgcHsvVp06DUfkVBnc9iCrNl3BYpgwV7CU9Yw6SGyFLalUMwsPbUfnawJ-0zLZg0agRh0AmQZ--3A"
}
```
#### 18. acme server verifies client-id with an http challenge
```http request
GET http://wire.com/.well-known/acme-challenge/W8gbXLNB5R0WOGXgNJMiM9EEh0SURE5W

```

#### 19. acme server verifies handle + display-name with an OIDC challenge
```http request
GET http://wire.com/.well-known/acme-challenge/Un9DTRTf9YJKYvuEANJcnYxDeGVOx1mt

```

#### 20. both challenges are valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
link: <https://localhost:55964/acme/wire-acme/authz/1fJYIDuOaF5QDhB3scSxgjiFHS9GM7JU>;rel="up"
location: https://localhost:55964/acme/wire-acme/challenge/1fJYIDuOaF5QDhB3scSxgjiFHS9GM7JU/66KBICWLrzxxolJlBH9sJUEYvkWt40US
replay-nonce: YkRvUFk1RERTM1R6OUZaZ29yZ3pBTlJzS09maVFSWkM
```
```json
{
  "type": "http-01",
  "url": "https://localhost:55964/acme/wire-acme/challenge/1fJYIDuOaF5QDhB3scSxgjiFHS9GM7JU/66KBICWLrzxxolJlBH9sJUEYvkWt40US",
  "status": "valid",
  "token": "W8gbXLNB5R0WOGXgNJMiM9EEh0SURE5W"
}
```
### Client presents a CSR and gets its certificate
#### 21. verify the status of the order
```http request
POST https://localhost:55964/acme/wire-acme/order/gJpx9XjxqVCp5S66gX9latROkS2CrBbM
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvdkV2ZGpLRVFNa3JPczdOa205Vk9LRUJTekZhNHBoQlEiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImRYQlNUblF3UW5KcE5EQXdRVlJPVGxCaE56RjBUamx0ZVdFNE9YazFXak0iLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9vcmRlci9nSnB4OVhqeHFWQ3A1UzY2Z1g5bGF0Uk9rUzJDckJiTSJ9",
  "payload": "",
  "signature": "AWCmB67IBqUE0mPxXUTODCju8lua7yLPVxmCSJEnUAACnGpNoPTMvREYZmExTfDID2j0m0leic5nzt8vTaUYfQ"
}
```
#### 22. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/order/gJpx9XjxqVCp5S66gX9latROkS2CrBbM
replay-nonce: T1lWRGJzS3ZPeDh3cG45WnBLVHRnUFNxeFhEYjEwU1A
```
```json
{
  "status": "ready",
  "finalize": "https://localhost:55964/acme/wire-acme/order/gJpx9XjxqVCp5S66gX9latROkS2CrBbM/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "login.wire.com"
    },
    {
      "type": "dns",
      "value": "wire.com"
    }
  ],
  "authorizations": [
    "https://localhost:55964/acme/wire-acme/authz/1fJYIDuOaF5QDhB3scSxgjiFHS9GM7JU",
    "https://localhost:55964/acme/wire-acme/authz/lZjrwuuiuNHv4wajmFpBMSQT37NLfV2n"
  ],
  "expires": "2023-01-11T15:30:38Z",
  "notBefore": "2023-01-10T15:30:38.919254Z",
  "notAfter": "2023-01-10T16:30:38.919254Z"
}
```
#### 23. create a CSR and call finalize url
```http request
POST https://localhost:55964/acme/wire-acme/order/gJpx9XjxqVCp5S66gX9latROkS2CrBbM/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvdkV2ZGpLRVFNa3JPczdOa205Vk9LRUJTekZhNHBoQlEiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlQxbFdSR0p6UzNaUGVEaDNjRzQ1V25CTFZIUm5VRk54ZUZoRVlqRXdVMUEiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9vcmRlci9nSnB4OVhqeHFWQ3A1UzY2Z1g5bGF0Uk9rUzJDckJiTS9maW5hbGl6ZSJ9",
  "payload": "eyJjc3IiOiJNSUh4TUlHWUFnRUFNQUF3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVFGUU10SmU5eE9ka1d3RW5NbnhCem05OU5NMzVqQ0ZHZkQ3dFBTbE82RVdFa3BBc2hGZVdlMHc3YWlGcXdEV1R3U21WamVvY0RfaFM3a3ZiSl9jNVFyb0RZd05BWUpLb1pJaHZjTkFRa09NU2N3SlRBakJnTlZIUkVFSERBYWdnaDNhWEpsTG1OdmJZSU9iRzluYVc0dWQybHlaUzVqYjIwd0NnWUlLb1pJemowRUF3SURTQUF3UlFJZ2QzMjBIaDZ3T0pwSkx5QURWQUotYjlMQjBPdlJNck9zUUg3eHZPRWw2YzhDSVFEM1l3SXhhTDZnVUVNMFBWS0xtUjZtMkMtVXhvQ1BUbndacURFR1JFT2ZQdyJ9",
  "signature": "3e3UcUxCuPRON86BeNKwdkhvR36fXLfVp9WuUJijP4NHZFqBJNyP_PCUcPYlBkiNbONGUjZOHA-VBcFpBfZhng"
}
...decoded...
{
  "protected": {
    "alg": "ES256",
    "kid": "https://localhost:55964/acme/wire-acme/account/vEvdjKEQMkrOs7Nkm9VOKEBSzFa4phBQ",
    "typ": "JWT",
    "nonce": "T1lWRGJzS3ZPeDh3cG45WnBLVHRnUFNxeFhEYjEwU1A",
    "url": "https://localhost:55964/acme/wire-acme/order/gJpx9XjxqVCp5S66gX9latROkS2CrBbM/finalize"
  },
  "payload": {
    "csr": "MIHxMIGYAgEAMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQFQMtJe9xOdkWwEnMnxBzm99NM35jCFGfD7tPSlO6EWEkpAshFeWe0w7aiFqwDWTwSmVjeocD_hS7kvbJ_c5QroDYwNAYJKoZIhvcNAQkOMScwJTAjBgNVHREEHDAaggh3aXJlLmNvbYIObG9naW4ud2lyZS5jb20wCgYIKoZIzj0EAwIDSAAwRQIgd320Hh6wOJpJLyADVAJ-b9LB0OvRMrOsQH7xvOEl6c8CIQD3YwIxaL6gUEM0PVKLmR6m2C-UxoCPTnwZqDEGREOfPw"
  }
}
```
#### 24. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/order/gJpx9XjxqVCp5S66gX9latROkS2CrBbM
replay-nonce: Qnd4cFByanBlMnRGVmNDTmQ3MFZyREg1RE5PV2FEbEk
```
```json
{
  "certificate": "https://localhost:55964/acme/wire-acme/certificate/BprMwjVhN69BAihopUjswHVMRChwyK3B",
  "status": "valid",
  "finalize": "https://localhost:55964/acme/wire-acme/order/gJpx9XjxqVCp5S66gX9latROkS2CrBbM/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "login.wire.com"
    },
    {
      "type": "dns",
      "value": "wire.com"
    }
  ],
  "authorizations": [
    "https://localhost:55964/acme/wire-acme/authz/1fJYIDuOaF5QDhB3scSxgjiFHS9GM7JU",
    "https://localhost:55964/acme/wire-acme/authz/lZjrwuuiuNHv4wajmFpBMSQT37NLfV2n"
  ],
  "expires": "2023-01-11T15:30:38Z",
  "notBefore": "2023-01-10T15:30:38.919254Z",
  "notAfter": "2023-01-10T16:30:38.919254Z"
}
```
#### 25. fetch the certificate
```http request
POST https://localhost:55964/acme/wire-acme/certificate/BprMwjVhN69BAihopUjswHVMRChwyK3B
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvdkV2ZGpLRVFNa3JPczdOa205Vk9LRUJTekZhNHBoQlEiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlFuZDRjRkJ5YW5CbE1uUkdWbU5EVG1RM01GWnlSRWcxUkU1UFYyRkViRWsiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9jZXJ0aWZpY2F0ZS9CcHJNd2pWaE42OUJBaWhvcFVqc3dIVk1SQ2h3eUszQiJ9",
  "payload": "",
  "signature": "jIEtnQDb5ECezED4bIs9ggXLh7tnzrHTDKbCzscpPZoQVYVL3wIygB5tQyVKlU8YWWtw6G00FFbB9xRLsESXjA"
}
```
#### 26. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
replay-nonce: YjRQMEZKczQyMU56THQzc0NuRU5SdTlWb2pDWDl1dnM
```
```json
[
  "MIIB6zCCAZGgAwIBAgIQNf8VCiJkBfp6lzkQHSLoBjAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nMzAxMTAxNTMwMzhaFw0yMzAxMTAxNjMwMzhaMAAwWTATBgcqhkjOPQIBBggqhkjO\nPQMBBwNCAAQFQMtJe9xOdkWwEnMnxBzm99NM35jCFGfD7tPSlO6EWEkpAshFeWe0\nw7aiFqwDWTwSmVjeocD/hS7kvbJ/c5Qro4G+MIG7MA4GA1UdDwEB/wQEAwIHgDAd\nBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFNu9/lDXetSa\neWSOmXgLJYm3SjNbMB8GA1UdIwQYMBaAFHFY9CT3ISfT2Xz2fScOLn45diPFMCYG\nA1UdEQEB/wQcMBqCDmxvZ2luLndpcmUuY29tggh3aXJlLmNvbTAiBgwrBgEEAYKk\nZMYoQAEEEjAQAgEGBAl3aXJlLWFjbWUEADAKBggqhkjOPQQDAgNIADBFAiAbcI1Q\nXadv4gxS0/KI54iOy1d86T1oMFGlyMRv3gGTeAIhAOuJ+b4V0iZBocjy1FTAmSfi\n8jTeDlil6f1sTML4Ayop",
  "MIIBuDCCAV6gAwIBAgIQed+5/kGfM5vfxxEX1t1UGDAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwMTEwMTUz\nMDMyWhcNMzMwMTA3MTUzMDMyWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLA+\n9Dky+wBtuuVr4HhDmpWycxRPF0iv28bqfuM38jLJc8r3Gb0melSimjkZftihVAdk\nm4xOcx/NnQny3jNhmqCjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBRxWPQk9yEn09l89n0nDi5+OXYjxTAfBgNVHSMEGDAW\ngBQPIjaIafwYTbpN50iU9ET8BLkSRjAKBggqhkjOPQQDAgNIADBFAiEAqxR5MV6R\n5QYqw290T4M7DJe7vuhwHVZBxb7TvfDRzt8CIB36nXKJOaf6Hze2BWlvC0srMZxO\nW7WA0XZD//8O2YWQ"
]
```
P384 - SHA384
```mermaid
sequenceDiagram
    autonumber
    wire-client->>+acme-server: GET /acme/wire-acme/directory
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: HEAD /acme/wire-acme/new-nonce
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/new-account
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/new-order
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/authz/y7H6eIj4I3YxBp13gxt2U6hrCKeDBebw
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/authz/h3F1CHo4G0Sok10zNc8ZLekCe6KaX73e
    acme-server->>-wire-client: 200
    wire-client->>+wire-server: GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>+wire-server: POST /clients/5406350086692821367/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/challenge/y7H6eIj4I3YxBp13gxt2U6hrCKeDBebw/aT8q3iZl04y3TqtseFTgdeV8ZL5viWDT
    acme-server->>+wire-server: GET /.well-known/acme-challenge/QHNfHH42DeVIUu803o7z2V8ajLXLlCaM
    wire-server->>-acme-server: empty
    acme-server->>+wire-server: GET /.well-known/acme-challenge/pbqn782i5gkBXAR7iIuUhj0yiBhD1gMm
    wire-server->>-acme-server: empty
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/aVzHtS2ojRT2cIrb3ZYcmsW5KokyoVnF
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/aVzHtS2ojRT2cIrb3ZYcmsW5KokyoVnF/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/certificate/V5yVMwmpElq5Z1xQ2JohEyYSh8r2vMGl
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://localhost:55964/acme/wire-acme/directory

```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://localhost:55964/acme/wire-acme/new-nonce",
  "newAccount": "https://localhost:55964/acme/wire-acme/new-account",
  "newOrder": "https://localhost:55964/acme/wire-acme/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://localhost:55964/acme/wire-acme/new-nonce

```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
replay-nonce: cm5jOEpTeEdYUGJXTERLR01rZ0tGWno2ako5a3prOHk
```
```json
"cm5jOEpTeEdYUGJXTERLR01rZ0tGWno2ako5a3prOHk"
```
#### 5. create a new account
```http request
POST https://localhost:55964/acme/wire-acme/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0IiwieCI6Inl2NlNnMGVXdzFqV3E3cEdIb3RrYWt1ajRwVk1wc2xZZFE5c3VIMDFIYko0UVJJNHdKNVAwT0xVT3kxZXBsWHYiLCJ5IjoiazVTRlZHMW9HdFViWHJMRW5vM2RZRkI2RzFUTkNYMGI1bUFOUWZoWGpDeENjMk5OWE53VXloYmhMczkta09GZSJ9LCJub25jZSI6ImNtNWpPRXBUZUVkWVVHSlhURVJMUjAxclowdEdXbm8yYWtvNWEzcHJPSGsiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9uZXctYWNjb3VudCJ9",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "-KyxlzpTILdvsfBQz_uc89xR-eLaaGf5OH3E4nofVoeWrBpbRxoQag4ZZykVHDdsGEp_n-badpSHu_kYulc5cD1hNp92qYihQED2RDXOy13Z0u-MXqtW76JuzxRKBWUR"
}
...decoded...
{
  "protected": {
    "alg": "ES384",
    "typ": "JWT",
    "jwk": {
      "kty": "EC",
      "crv": "P-384",
      "x": "yv6Sg0eWw1jWq7pGHotkakuj4pVMpslYdQ9suH01HbJ4QRI4wJ5P0OLUOy1eplXv",
      "y": "k5SFVG1oGtUbXrLEno3dYFB6G1TNCX0b5mANQfhXjCxCc2NNXNwUyhbhLs9-kOFe"
    },
    "nonce": "cm5jOEpTeEdYUGJXTERLR01rZ0tGWno2ako5a3prOHk",
    "url": "https://localhost:55964/acme/wire-acme/new-account"
  },
  "payload": {
    "termsOfServiceAgreed": true,
    "contact": [
      "unknown@example.com"
    ],
    "onlyReturnExisting": false
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/account/IxVWnG3MbbZZzchLs5nUF4wneXcJ4YC8
replay-nonce: T1RmUGxNQlVBQnZTZzBVUXFIeGl5S2NKa3JSNmRXbXI
```
```json
{
  "status": "valid",
  "orders": "https://localhost:55964/acme/wire-acme/account/IxVWnG3MbbZZzchLs5nUF4wneXcJ4YC8/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://localhost:55964/acme/wire-acme/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvSXhWV25HM01iYlpaemNoTHM1blVGNHduZVhjSjRZQzgiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlQxUm1VR3hOUWxWQlFuWlRaekJWVVhGSWVHbDVTMk5LYTNKU05tUlhiWEkiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9uZXctb3JkZXIifQ",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoibG9naW4ud2lyZS5jb20ifSx7InR5cGUiOiJkbnMiLCJ2YWx1ZSI6IndpcmUuY29tIn1dLCJub3RCZWZvcmUiOiIyMDIzLTAxLTEwVDE1OjMwOjQyLjI3MTY2NVoiLCJub3RBZnRlciI6IjIwMjMtMDEtMTBUMTY6MzA6NDIuMjcxNjY1WiJ9",
  "signature": "l1u_I71PKWxTWf_R3uxg8vkjgLzSu7D3caAmmiVKHPKOD5oslxwKn4pMD64lzHbVU49uV9nCj-PS0pXwix_CzBsgO6baDcP0ALQzARxapD4HnMt6GvlvYsZBClfpZRTO"
}
...decoded...
{
  "protected": {
    "alg": "ES384",
    "kid": "https://localhost:55964/acme/wire-acme/account/IxVWnG3MbbZZzchLs5nUF4wneXcJ4YC8",
    "typ": "JWT",
    "nonce": "T1RmUGxNQlVBQnZTZzBVUXFIeGl5S2NKa3JSNmRXbXI",
    "url": "https://localhost:55964/acme/wire-acme/new-order"
  },
  "payload": {
    "identifiers": [
      {
        "type": "dns",
        "value": "login.wire.com"
      },
      {
        "type": "dns",
        "value": "wire.com"
      }
    ],
    "notBefore": "2023-01-10T15:30:42.271665Z",
    "notAfter": "2023-01-10T16:30:42.271665Z"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/order/aVzHtS2ojRT2cIrb3ZYcmsW5KokyoVnF
replay-nonce: SXBwelIyVGN3SkNYaGJXaE9EYVh3S0hnZE9SMXhUVEE
```
```json
{
  "status": "pending",
  "finalize": "https://localhost:55964/acme/wire-acme/order/aVzHtS2ojRT2cIrb3ZYcmsW5KokyoVnF/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "login.wire.com"
    },
    {
      "type": "dns",
      "value": "wire.com"
    }
  ],
  "authorizations": [
    "https://localhost:55964/acme/wire-acme/authz/y7H6eIj4I3YxBp13gxt2U6hrCKeDBebw",
    "https://localhost:55964/acme/wire-acme/authz/h3F1CHo4G0Sok10zNc8ZLekCe6KaX73e"
  ],
  "expires": "2023-01-11T15:30:42Z",
  "notBefore": "2023-01-10T15:30:42.271665Z",
  "notAfter": "2023-01-10T16:30:42.271665Z"
}
```
### Display-name and handle already authorized
#### 9. fetch first challenge
```http request
POST https://localhost:55964/acme/wire-acme/authz/y7H6eIj4I3YxBp13gxt2U6hrCKeDBebw
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvSXhWV25HM01iYlpaemNoTHM1blVGNHduZVhjSjRZQzgiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlNYQndlbEl5VkdOM1NrTllhR0pYYUU5RVlWaDNTMGhuWkU5U01YaFVWRUUiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9hdXRoei95N0g2ZUlqNEkzWXhCcDEzZ3h0MlU2aHJDS2VEQmVidyJ9",
  "payload": "",
  "signature": "-AQCHwPK-HEdRrORVMzHXvHLiodX8rqP_l8rbN5OAL0B_ygJycBxwGXjV_czm6V4cbKuaXuKJeq3kmcxew8b4NBP3KBZ6TMWLolsAq40J7GG3yGlbixhwfR6R22pfehE"
}
```
#### 10. get back first challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/authz/y7H6eIj4I3YxBp13gxt2U6hrCKeDBebw
replay-nonce: STVQSGc1RFN3RFFBemhraHY3VDB0Vjl4QkNDSlZKRDM
```
```json
{
  "status": "pending",
  "expires": "2023-01-11T15:30:42Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/y7H6eIj4I3YxBp13gxt2U6hrCKeDBebw/N1Y30c6uyauOfdRjj198Ji42FrfcuV1T",
      "status": "pending",
      "token": "QHNfHH42DeVIUu803o7z2V8ajLXLlCaM"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/y7H6eIj4I3YxBp13gxt2U6hrCKeDBebw/aT8q3iZl04y3TqtseFTgdeV8ZL5viWDT",
      "status": "pending",
      "token": "QHNfHH42DeVIUu803o7z2V8ajLXLlCaM"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/y7H6eIj4I3YxBp13gxt2U6hrCKeDBebw/0jcGVYcJrj8jRxkztJhftevtnHvRTBuO",
      "status": "pending",
      "token": "QHNfHH42DeVIUu803o7z2V8ajLXLlCaM"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "login.wire.com"
  }
}
```
### ACME provides a Wire client ID challenge
#### 11. fetch second challenge
```http request
POST https://localhost:55964/acme/wire-acme/authz/h3F1CHo4G0Sok10zNc8ZLekCe6KaX73e
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvSXhWV25HM01iYlpaemNoTHM1blVGNHduZVhjSjRZQzgiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlNUVlFTR2MxUkZOM1JGRkJlbWhyYUhZM1ZEQjBWamw0UWtORFNsWktSRE0iLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9hdXRoei9oM0YxQ0hvNEcwU29rMTB6TmM4Wkxla0NlNkthWDczZSJ9",
  "payload": "",
  "signature": "xuHZw9Q7rNzcw1g1jn15lSnJpW3MUs2tI5PHXo_MJNnaZ3h2BfppURcSRIWbyKn1MTMVDRVIHua2Uy-8mmcIFoUcrP2FjOAlXAwBNTyqPaWAqMxVEXUQyE4ud5Tmbhu3"
}
```
#### 12. get back second challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/authz/h3F1CHo4G0Sok10zNc8ZLekCe6KaX73e
replay-nonce: azVKcVdYc2R6Y3NBREwyZjNrTVdQSmljbk41QmVTUHU
```
```json
{
  "status": "pending",
  "expires": "2023-01-11T15:30:42Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/h3F1CHo4G0Sok10zNc8ZLekCe6KaX73e/r86qy1YaJrKA9a6HHSRKR87Bd5jvryqN",
      "status": "pending",
      "token": "pbqn782i5gkBXAR7iIuUhj0yiBhD1gMm"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/h3F1CHo4G0Sok10zNc8ZLekCe6KaX73e/ZGUrOVatnn0JNwPWCUyv9SHJac6k3t0Z",
      "status": "pending",
      "token": "pbqn782i5gkBXAR7iIuUhj0yiBhD1gMm"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55964/acme/wire-acme/challenge/h3F1CHo4G0Sok10zNc8ZLekCe6KaX73e/2G17zRYMz6fETqll4Mvz61egmXJnA714",
      "status": "pending",
      "token": "pbqn782i5gkBXAR7iIuUhj0yiBhD1gMm"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "wire.com"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 13. fetch a nonce from wire-server
```http request
GET http://localhost:60412/clients/token/nonce

```
#### 14. get wire-server nonce
```http request
200

```
```json
"MGJTQk5LTTQ2OFNtNWR4dkNRdFU4cFEyRmFXNkQ1bnE"
```
#### 15. create the client Dpop token with both nonces
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFUzM4NCIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0zODQiLCJ4IjoieXY2U2cwZVd3MWpXcTdwR0hvdGtha3VqNHBWTXBzbFlkUTlzdUgwMUhiSjRRUkk0d0o1UDBPTFVPeTFlcGxYdiIsInkiOiJrNVNGVkcxb0d0VWJYckxFbm8zZFlGQjZHMVROQ1gwYjVtQU5RZmhYakN4Q2MyTk5YTndVeWhiaExzOS1rT0ZlIn19.eyJpYXQiOjE2NzMzNjQ2NDIsImV4cCI6MTY3MzQ1MTA0MiwibmJmIjoxNjczMzY0NjQyLCJzdWIiOiJpbTp3aXJlYXBwOk5HTm1NRGt5TkdNek1qQTJOR1JoT0Roa01qQmlaakl6TkRjMU9UWTVNREUvNGIwNzM2YzI4MGJhNTk3N0B3aXJlLmNvbSIsImp0aSI6ImJjN2M1ZjlmLWUwYzktNDhjYS1hYTlkLTljZDBjMmU5N2U5NyIsIm5vbmNlIjoiTUdKVFFrNUxUVFEyT0ZOdE5XUjRka05SZEZVNGNGRXlSbUZYTmtRMWJuRSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vbG9jYWxob3N0OjYwNDEyL2NsaWVudHMvNTQwNjM1MDA4NjY5MjgyMTM2Ny9hY2Nlc3MtdG9rZW4iLCJjaGFsIjoiUUhOZkhINDJEZVZJVXU4MDNvN3oyVjhhakxYTGxDYU0ifQ.j9WBkeNpr9jaPw6gLvDlq7qbhuktWo_5IyHzqlspoocYTh5pS6gWY0O2v-IO4wGtWKOX4mXMUu0JCo72rOvIFVf1taf2Iz5XUbb3O1wBqseV0qNr00csx4r-dHoqkb6P)
```http request
POST http://localhost:60412/clients/5406350086692821367/access-token

```
#### 16. get a Dpop access token from wire-server
```http request
200

```
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFUzM4NCIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0IiwieCI6Ik1KandLRDhrWm52QjQyWW1aX3VNczZoYjB1aGd6VTViSzNtNUhrWi05eDJCS3hXbzRBVnVtVnlDV0l6Q2RWbjAiLCJ5IjoiVzdUQnBHd1hiMzgyRTR2TVM4bS0zcnRwRzlmN1lsckNxbEl6NGd2VS1aSy02aHItXzFqcnlXM1hlU2l3ZVV5UyJ9fQ.eyJpYXQiOjE2NzMzNjQ2NDIsImV4cCI6MTY4MTE0MDY0MiwibmJmIjoxNjczMzY0NjQyLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjYwNDEyL2NsaWVudHMvNTQwNjM1MDA4NjY5MjgyMTM2Ny9hY2Nlc3MtdG9rZW4iLCJzdWIiOiJpbTp3aXJlYXBwOk5HTm1NRGt5TkdNek1qQTJOR1JoT0Roa01qQmlaakl6TkRjMU9UWTVNREUvNGIwNzM2YzI4MGJhNTk3N0B3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NjA0MTIvY2xpZW50cy81NDA2MzUwMDg2NjkyODIxMzY3L2FjY2Vzcy10b2tlbiIsImp0aSI6IjVkMTNiOTQxLWVkZDktNGJmMS05ZGMzLWYzNTI2OTVmN2E0OCIsIm5vbmNlIjoiTUdKVFFrNUxUVFEyT0ZOdE5XUjRka05SZEZVNGNGRXlSbUZYTmtRMWJuRSIsImNoYWwiOiJRSE5mSEg0MkRlVklVdTgwM283ejJWOGFqTFhMbENhTSIsImNuZiI6eyJraWQiOiJ5a0tuanlza1p2dF8xNnE0YW4zRVh4TlluNHEybVVXT0dnNnVwNUZscHM5SU51TXBDbTRsbzJCTnpKNVhrdzU0In0sInByb29mIjoiZXlKaGJHY2lPaUpGVXpNNE5DSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHpPRFFpTENKNElqb2llWFkyVTJjd1pWZDNNV3BYY1Rkd1IwaHZkR3RoYTNWcU5IQldUWEJ6YkZsa1VUbHpkVWd3TVVoaVNqUlJVa2swZDBvMVVEQlBURlZQZVRGbGNHeFlkaUlzSW5raU9pSnJOVk5HVmtjeGIwZDBWV0pZY2t4RmJtOHpaRmxHUWpaSE1WUk9RMWd3WWpWdFFVNVJabWhZYWtONFEyTXlUazVZVG5kVmVXaGlhRXh6T1MxclQwWmxJbjE5LmV5SnBZWFFpT2pFMk56TXpOalEyTkRJc0ltVjRjQ0k2TVRZM016UTFNVEEwTWl3aWJtSm1Jam94Tmpjek16WTBOalF5TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3T2s1SFRtMU5SR3Q1VGtkTmVrMXFRVEpPUjFKb1QwUm9hMDFxUW1sYWFrbDZUa1JqTVU5VVdUVk5SRVV2TkdJd056TTJZekk0TUdKaE5UazNOMEIzYVhKbExtTnZiU0lzSW1wMGFTSTZJbUpqTjJNMVpqbG1MV1V3WXprdE5EaGpZUzFoWVRsa0xUbGpaREJqTW1VNU4yVTVOeUlzSW01dmJtTmxJam9pVFVkS1ZGRnJOVXhVVkZFeVQwWk9kRTVYVWpSa2EwNVNaRVpWTkdOR1JYbFNiVVpZVG10Uk1XSnVSU0lzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2Ykc5allXeG9iM04wT2pZd05ERXlMMk5zYVdWdWRITXZOVFF3TmpNMU1EQTROalk1TWpneU1UTTJOeTloWTJObGMzTXRkRzlyWlc0aUxDSmphR0ZzSWpvaVVVaE9aa2hJTkRKRVpWWkpWWFU0TUROdk4zb3lWamhoYWt4WVRHeERZVTBpZlEuajlXQmtlTnByOWphUHc2Z0x2RGxxN3FiaHVrdFdvXzVJeUh6cWxzcG9vY1lUaDVwUzZnV1kwTzJ2LUlPNHdHdFdLT1g0bVhNVXUwSkNvNzJyT3ZJRlZmMXRhZjJJejVYVWJiM08xd0Jxc2VWMHFOcjAwY3N4NHItZEhvcWtiNlAiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwOk5HTm1NRGt5TkdNek1qQTJOR1JoT0Roa01qQmlaakl6TkRjMU9UWTVNREUvNGIwNzM2YzI4MGJhNTk3N0B3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.CRWUAZiIfAknrEKSBEz-dVp9yMwK5wiEvdAXGPc_WWK0KDT_N75kyf8X4Xy1IH7Xl60gd4gOC9y7cMdnCBNw2w8elv2V7J_3kCiOv73HwctF4d013KHSb0qykxQdqMXt)
### Client provides access token
#### 17. send DPoP access token to acme server to have it validated
```http request
POST https://localhost:55964/acme/wire-acme/challenge/y7H6eIj4I3YxBp13gxt2U6hrCKeDBebw/aT8q3iZl04y3TqtseFTgdeV8ZL5viWDT
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvSXhWV25HM01iYlpaemNoTHM1blVGNHduZVhjSjRZQzgiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImF6VktjVmRZYzJSNlkzTkJSRXd5WmpOclRWZFFTbWxqYms0MVFtVlRVSFUiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9jaGFsbGVuZ2UveTdINmVJajRJM1l4QnAxM2d4dDJVNmhyQ0tlREJlYncvYVQ4cTNpWmwwNHkzVHF0c2VGVGdkZVY4Wkw1dmlXRFQifQ",
  "payload": "",
  "signature": "jXlh0wLiCDSV4oDdoOGdjEIuF1r60DEAQE3-TgKQkQpFnFJemgDrsk372mVP_jqEH2vTB8Vv-NnaLC0R3VJegjFiPmr7aVbQtHudkhLR52e1P7R3JQGotZsAyUBebxIs"
}
```
#### 18. acme server verifies client-id with an http challenge
```http request
GET http://wire.com/.well-known/acme-challenge/QHNfHH42DeVIUu803o7z2V8ajLXLlCaM

```

#### 19. acme server verifies handle + display-name with an OIDC challenge
```http request
GET http://wire.com/.well-known/acme-challenge/pbqn782i5gkBXAR7iIuUhj0yiBhD1gMm

```

#### 20. both challenges are valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
link: <https://localhost:55964/acme/wire-acme/authz/y7H6eIj4I3YxBp13gxt2U6hrCKeDBebw>;rel="up"
location: https://localhost:55964/acme/wire-acme/challenge/y7H6eIj4I3YxBp13gxt2U6hrCKeDBebw/aT8q3iZl04y3TqtseFTgdeV8ZL5viWDT
replay-nonce: TTFQNVp2bVE3N2c4QW4xSnFtTFRYQ1haNkxmS3Izdm0
```
```json
{
  "type": "http-01",
  "url": "https://localhost:55964/acme/wire-acme/challenge/y7H6eIj4I3YxBp13gxt2U6hrCKeDBebw/aT8q3iZl04y3TqtseFTgdeV8ZL5viWDT",
  "status": "valid",
  "token": "QHNfHH42DeVIUu803o7z2V8ajLXLlCaM"
}
```
### Client presents a CSR and gets its certificate
#### 21. verify the status of the order
```http request
POST https://localhost:55964/acme/wire-acme/order/aVzHtS2ojRT2cIrb3ZYcmsW5KokyoVnF
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvSXhWV25HM01iYlpaemNoTHM1blVGNHduZVhjSjRZQzgiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlNUVnFhbkJTV1hCclVFaEhiRkJYVEV0RlEybzVVMXBXTlRNMFR6QTJUbEEiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9vcmRlci9hVnpIdFMyb2pSVDJjSXJiM1pZY21zVzVLb2t5b1ZuRiJ9",
  "payload": "",
  "signature": "XX-oczNWHbxDHbY98-Qo6-txXtPI_NeOvDOaDXd2iGWcKdMT8iXFTc2Y9HlnMqo8dnLu_3wHSf1mILf4gZzcBOVpJ_GUweazCbKuzjvRydviHQyptYBy-P_y4VjLmyBW"
}
```
#### 22. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/order/aVzHtS2ojRT2cIrb3ZYcmsW5KokyoVnF
replay-nonce: eGpMUVFrZWt1Q2p2NXdCdWdwNlBPVnFHZjNBSGJlNm0
```
```json
{
  "status": "ready",
  "finalize": "https://localhost:55964/acme/wire-acme/order/aVzHtS2ojRT2cIrb3ZYcmsW5KokyoVnF/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "login.wire.com"
    },
    {
      "type": "dns",
      "value": "wire.com"
    }
  ],
  "authorizations": [
    "https://localhost:55964/acme/wire-acme/authz/y7H6eIj4I3YxBp13gxt2U6hrCKeDBebw",
    "https://localhost:55964/acme/wire-acme/authz/h3F1CHo4G0Sok10zNc8ZLekCe6KaX73e"
  ],
  "expires": "2023-01-11T15:30:42Z",
  "notBefore": "2023-01-10T15:30:42.271665Z",
  "notAfter": "2023-01-10T16:30:42.271665Z"
}
```
#### 23. create a CSR and call finalize url
```http request
POST https://localhost:55964/acme/wire-acme/order/aVzHtS2ojRT2cIrb3ZYcmsW5KokyoVnF/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvSXhWV25HM01iYlpaemNoTHM1blVGNHduZVhjSjRZQzgiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImVHcE1VVkZyWld0MVEycDJOWGRDZFdkd05sQlBWbkZIWmpOQlNHSmxObTAiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9vcmRlci9hVnpIdFMyb2pSVDJjSXJiM1pZY21zVzVLb2t5b1ZuRi9maW5hbGl6ZSJ9",
  "payload": "eyJjc3IiOiJNSUlCTGpDQnRRSUJBREFBTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUV5djZTZzBlV3cxaldxN3BHSG90a2FrdWo0cFZNcHNsWWRROXN1SDAxSGJKNFFSSTR3SjVQME9MVU95MWVwbFh2azVTRlZHMW9HdFViWHJMRW5vM2RZRkI2RzFUTkNYMGI1bUFOUWZoWGpDeENjMk5OWE53VXloYmhMczkta09GZW9EWXdOQVlKS29aSWh2Y05BUWtPTVNjd0pUQWpCZ05WSFJFRUhEQWFnZ2gzYVhKbExtTnZiWUlPYkc5bmFXNHVkMmx5WlM1amIyMHdDZ1lJS29aSXpqMEVBd01EYUFBd1pRSXhBUHdxV3kxdXdIaDVSaFA5dU1lbzhLMnlqQ00wOFVWOW9EcGx2OVdwT0xkMWdYTDRwcEdmTG5nNFJIYVktZVNITFFJd0dYTndTQzR0dGFST0twNVd0aW5QVjdlMExJQllpZFF0MEtkRnJfeVctTjNXZ1VNanlYVVEzZGxVV3lwbWJxZVIifQ",
  "signature": "mIeTjZgY4Hjn6dsAQfeyC12pb-MzytGQVFCLyn-bJBDcU6RZC2RNn-Hxb3xs5suoyh0vdnElRwBc6Ta7k5A-by5qHDhH8dxTWN6nKpEzoSyA_e7-VUi8G63YI4TNTaae"
}
...decoded...
{
  "protected": {
    "alg": "ES384",
    "kid": "https://localhost:55964/acme/wire-acme/account/IxVWnG3MbbZZzchLs5nUF4wneXcJ4YC8",
    "typ": "JWT",
    "nonce": "eGpMUVFrZWt1Q2p2NXdCdWdwNlBPVnFHZjNBSGJlNm0",
    "url": "https://localhost:55964/acme/wire-acme/order/aVzHtS2ojRT2cIrb3ZYcmsW5KokyoVnF/finalize"
  },
  "payload": {
    "csr": "MIIBLjCBtQIBADAAMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEyv6Sg0eWw1jWq7pGHotkakuj4pVMpslYdQ9suH01HbJ4QRI4wJ5P0OLUOy1eplXvk5SFVG1oGtUbXrLEno3dYFB6G1TNCX0b5mANQfhXjCxCc2NNXNwUyhbhLs9-kOFeoDYwNAYJKoZIhvcNAQkOMScwJTAjBgNVHREEHDAaggh3aXJlLmNvbYIObG9naW4ud2lyZS5jb20wCgYIKoZIzj0EAwMDaAAwZQIxAPwqWy1uwHh5RhP9uMeo8K2yjCM08UV9oDplv9WpOLd1gXL4ppGfLng4RHaY-eSHLQIwGXNwSC4ttaROKp5WtinPV7e0LIBYidQt0KdFr_yW-N3WgUMjyXUQ3dlUWypmbqeR"
  }
}
```
#### 24. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
location: https://localhost:55964/acme/wire-acme/order/aVzHtS2ojRT2cIrb3ZYcmsW5KokyoVnF
replay-nonce: TkxjenBiOUZhM0xGbHZuSm5rNWNHNXNZd1ltUkxvQno
```
```json
{
  "certificate": "https://localhost:55964/acme/wire-acme/certificate/V5yVMwmpElq5Z1xQ2JohEyYSh8r2vMGl",
  "status": "valid",
  "finalize": "https://localhost:55964/acme/wire-acme/order/aVzHtS2ojRT2cIrb3ZYcmsW5KokyoVnF/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "login.wire.com"
    },
    {
      "type": "dns",
      "value": "wire.com"
    }
  ],
  "authorizations": [
    "https://localhost:55964/acme/wire-acme/authz/y7H6eIj4I3YxBp13gxt2U6hrCKeDBebw",
    "https://localhost:55964/acme/wire-acme/authz/h3F1CHo4G0Sok10zNc8ZLekCe6KaX73e"
  ],
  "expires": "2023-01-11T15:30:42Z",
  "notBefore": "2023-01-10T15:30:42.271665Z",
  "notAfter": "2023-01-10T16:30:42.271665Z"
}
```
#### 25. fetch the certificate
```http request
POST https://localhost:55964/acme/wire-acme/certificate/V5yVMwmpElq5Z1xQ2JohEyYSh8r2vMGl
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTY0L2FjbWUvd2lyZS1hY21lL2FjY291bnQvSXhWV25HM01iYlpaemNoTHM1blVGNHduZVhjSjRZQzgiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlRreGplbkJpT1VaaE0weEdiSFp1U201ck5XTkhOWE5aZDFsdFVreHZRbm8iLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk2NC9hY21lL3dpcmUtYWNtZS9jZXJ0aWZpY2F0ZS9WNXlWTXdtcEVscTVaMXhRMkpvaEV5WVNoOHIydk1HbCJ9",
  "payload": "",
  "signature": "T9e7v8sMjnLsH_8J9xuey6i5Dq_j_3AaP2iTvCqNn7-v5uniByLRlPmo0ldIqgzBrfblDU3p2JOFCS8BmZcgb-_ssyKlIn1ye4nTWb0UQ8dxSnFQHn06P88thfFX8B97"
}
```
#### 26. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://localhost:55964/acme/wire-acme/directory>;rel="index"
replay-nonce: bjNkWERFdkRYQmtqWlJYUVJ3T0ZiWmtPNE1HcWczQUo
```
```json
[
  "MIICBzCCAa6gAwIBAgIQf63qt+6c801H52xyuBY+mjAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nMzAxMTAxNTMwNDJaFw0yMzAxMTAxNjMwNDJaMAAwdjAQBgcqhkjOPQIBBgUrgQQA\nIgNiAATK/pKDR5bDWNarukYei2RqS6PilUymyVh1D2y4fTUdsnhBEjjAnk/Q4tQ7\nLV6mVe+TlIVUbWga1RtessSejd1gUHobVM0JfRvmYA1B+FeMLEJzY01c3BTKFuEu\nz36Q4V6jgb4wgbswDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMB\nBggrBgEFBQcDAjAdBgNVHQ4EFgQU6vxlKcwPWRk7T/oELs9X3SduT1AwHwYDVR0j\nBBgwFoAUcVj0JPchJ9PZfPZ9Jw4ufjl2I8UwJgYDVR0RAQH/BBwwGoIObG9naW4u\nd2lyZS5jb22CCHdpcmUuY29tMCIGDCsGAQQBgqRkxihAAQQSMBACAQYECXdpcmUt\nYWNtZQQAMAoGCCqGSM49BAMCA0cAMEQCIGPAxyv8DMbdlHMWsMjfaDDBxkqPnrYS\nrJ8vgsdi8ib/AiBHR1CbvVwc8X3KFClyxkyDbxq+VQV+pJ+NEU7EolGzmg==",
  "MIIBuDCCAV6gAwIBAgIQed+5/kGfM5vfxxEX1t1UGDAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwMTEwMTUz\nMDMyWhcNMzMwMTA3MTUzMDMyWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLA+\n9Dky+wBtuuVr4HhDmpWycxRPF0iv28bqfuM38jLJc8r3Gb0melSimjkZftihVAdk\nm4xOcx/NnQny3jNhmqCjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBRxWPQk9yEn09l89n0nDi5+OXYjxTAfBgNVHSMEGDAW\ngBQPIjaIafwYTbpN50iU9ET8BLkSRjAKBggqhkjOPQQDAgNIADBFAiEAqxR5MV6R\n5QYqw290T4M7DJe7vuhwHVZBxb7TvfDRzt8CIB36nXKJOaf6Hze2BWlvC0srMZxO\nW7WA0XZD//8O2YWQ"
]
```