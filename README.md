# Rusty JWT Tools

A collection of JWT utilities.

This repository is part of the source code of Wire. You can find more information at [wire.com](https://wire.com) or by
contacting opensource@wire.com.

You can find the published source code at [github.com/wireapp/wire](https://github.com/wireapp/wire).

For licensing information, see the attached LICENSE file and the list of third-party licenses
at [wire.com/legal/licenses/](https://wire.com/legal/licenses/).

No license is granted to the Wire trademark and its associated logos, all of which will continue to be owned exclusively
by Wire Swiss GmbH. Any use of the Wire trademark and/or its associated logos is expressly prohibited without the
express prior written consent of Wire Swiss GmbH.

## Parts

* acme: types that deal with ACME certificate enrollment
* e2e-identity: implementation of the Wire end-to-end identity workflow, built on top of acme and jwt
* ffi: Haskell bindings for rusty-jwt-tools, only used by wire-server
* jwt: a collection of JWT utilities
* x509-check: helpers for X509 certificate validation, only used by acme

## Building

For the build requirements, look at [the information in core-crypto repo](
https://github.com/wireapp/core-crypto?tab=readme-ov-file#general-requirements).

> [!note]
> Building rusty-jwt-tools independently of core-crypto for Android targets is currently not supported due to
> missing configuration bits. However, the necessary bits are in core-crypto so one can build rusty-jwt-tools
> for Android targets as part of a core-crypto build.

Building is as simple as
```bash
cargo build
```

## Testing

Install cargo-nextest to allow running tests in parallel:
```bash
cargo install cargo-nextest
```

### Preparing the container runtime environment

Some tests require a working container runtime, so make sure to prepare one
before running all tests. Platform-specific instructions follow below.

#### On Linux with Docker

Make sure to start the Docker service if it is not already running:
```bash
systemctl start docker.service
```

#### On Linux with Podman

```bash
# start socket activation, which will cause Podman to start once
# anything connects to the socket:
systemctl --user start podman.socket

# check that socket activation works
podman version

# if the above didn't work, depending on the distribution and installed packages,
# it may be necessary to configure the DOCKER_HOST variable to point to Podman's socket
export DOCKER_HOST=unix:///run/user/$UID/podman/podman.sock
```

#### On macOS with Docker

Note: Docker under macOS requires Docker Desktop, which must run as a GUI application.

```bash
# install docker and docker-desktop
brew install docker docker-desktop

# start the Docker daemon by launching docker-desktop as a GUI application

# check if everything went fine
docker version
```

#### On macOS with Podman

```bash
# install Podman
brew install podman

# install podman-mac-helper
sudo podman-mac-helper install

# create new VM based on machine-os:5.5; note that we're explicitly specifying
# an older image version because the newest one seems to be broken
podman machine init --image docker://quay.io/podman/machine-os:5.5

# start the machine
podman machine start

# if everything went well, this should print server version `5.5.x`
podman version

# symlink docker to podman (test scripts and code assume existence
# of the `docker` command)
ln -s /opt/homebrew/bin/podman /opt/homebrew/bin/docker
```

### Choosing the OIDC identity provider

Choose the OIDC identity provider to use in tests by setting the `TEST_IDP` variable:
```bash
# use Keycloak
export TEST_IDP=keycloak

# or Authelia
export TEST_IDP=authelia
```

### Running all tests at once

Simply execute the `run-tests.sh` script:
```bash
bash run-tests.sh
```
The script will take care of cleaning up processes and containers that are started during tests.

### Running specific tests

`run-tests.sh` forwards its arguments to `cargo nextest`, so, to run a specific test, or any
subset of tests, e.g.
```bash
bash run-tests.sh alg::p256
```

### Manually invoking tests

First, you need to start `test-wire-server`:
```bash
$ cargo run test-wire-server
[...]
127.0.0.1:20530
```

Note the IP and port printed by `test-wire-server` and export that as `TEST_WIRE_SERVER_ADDR`:
```bash
export TEST_WIRE_SERVER_ADDR=127.0.0.1:20530
```

Now that the environment is ready, you can run a specific test, or any subset of tests, e.g.
```bash
cargo nextest run --locked alg::p256
```

Once you are done with testing, terminate the IdP container that has been started:
```bash
# if you're using Keycloak
docker kill keycloak && docker rm keycloak

# if you're using Authelia
docker kill authelia.local && docker rm authelia.local
```
as well as the `test-wire-server` instance.

### Testing the Haskell FFI

Make sure you have [Cabal](https://www.haskell.org/cabal/) installed.

Then run:
```bash
cd ffi
cargo make hs-test
```

## Git workflow

See [core-crypto git workflow](https://github.com/wireapp/core-crypto?tab=readme-ov-file#git-workflow).

## Publishing

No crates are published on crates.io or any other Rust crate registry.
The only release artifacts are source archives on github.

### Versioning

The versioning scheme used is [SemVer AKA Semantic Versioning](https://semver.org).

### Making a new release

1. Make a branch based on `main` to prepare for release (`git checkout -b prepare-release/X.Y.Z`)
1. Update the version of all workspace members to `X.Y.Z`, including places that refer to them.
1. Generate a fresh `e2e-identity/README.md.test`:
   ```
    cargo test --package wire-e2e-identity --test e2e demo_should_succeed
   ```
   If there are non-trivial differences between `e2e-identity/README.md` and the generated file,
   update `e2e-identity/README.md` and commit the changes.
1. Generate the relevant changelog section:
   ```
   git cliff --bump --unreleased
   ```
   and add it to the top of `CHANGELOG.md`.
   Make sure the version number generated by `git cliff` matches the release version.
1. If there are any release highlights, add them as the first subsection below release title:
   ```markdown
   ## v0.10.0 - 2024-05-02

   ### Highlights

   - foo
   - bar
   - baz
   ```
1. Push your `prepare-release/X.Y.Z` branch and create a PR for it
1. Get it reviewed, then merge it into `main` and remove the `prepare-release/X.Y.Z` branch from the remote
1. Now, pull your local `main`: `git checkout main && git pull`
1. Create the release tag: `git tag -s vX.Y.Z`
1. Push the new tag: `git push origin tag vX.Y.Z`
1. Create a new release on github, copying the relevant section from `CHANGELOG.md`
1. Voilà!
