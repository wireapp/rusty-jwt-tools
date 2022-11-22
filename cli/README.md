# rusty-jwt-cli

A cli to prototype JWTs and tryout this project.

## Installation

```bash
cargo install --git https://github.com/wireapp/rusty-jwt-tools.git
```

To update do:
```bash
cargo install --force --git https://github.com/wireapp/rusty-jwt-tools.git
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

Generates a new JWT token. For sample payloads have a look in [this folder](../data).

```bash
cat claims.json | rusty-jwt-cli jwt-build -k kp-ed25519.pem -p vp.json -c vc1.json -c vc2.json
# or
rusty-jwt-cli jwt-build claims.json -k kp-ed25519.pem -p vp.json -c vc1.json -c vc2.json
```

### `jwt-parse`

Introspects and verifies a JWT token

```bash
cat jwt.json | rusty-jwt-cli jwt-parse
# or
rusty-jwt-cli jwt-parse jwt.json
```

### `jwk-parse`

Turns a PEM private into its public key JWK representation and computes its thumbprint according to RFC7638.

```bash
cat kp-p256.pem | rusty-jwt-cli jwk-parse
# or
rusty-jwt-cli jwk-parse kp-p256.pem
```
