# rusty-jwt-cli

A cli to prototype JWTs and tryout this project.

## Installation

```bash
cargo install https://github.com/wireapp/rusty-jwt-tools
```

## Generate PEM KeyPairs

### Ed25519

```bash
openssl genpkey -algorithm ed25519 -outform PEM -out kp-ed25519.pem
```

### ES256

```bash
openssl ecparam -genkey -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out kp-p256.pem 
```

### ES384

```bash
openssl ecparam -genkey -name secp384r1 | openssl pkcs8 -topk8 -nocrypt -out kp-p384.pem 
```

## Usage

### `jwt-build`

```bash
cat claims.json | rusty-jwt-cli jwt-build -k kp-ed25519.pem -p vp.json -c vc1.json -c vc2.json
```
