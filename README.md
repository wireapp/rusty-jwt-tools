# Rusty JWT Tools

A collection of JWT utilities.

[![Wire logo](https://github.com/wireapp/wire/blob/master/assets/header-small.png?raw=true)](https://wire.com/jobs/)

This repository is part of the source code of Wire. You can find more information at [wire.com](https://wire.com) or by
contacting opensource@wire.com.

You can find the published source code at [github.com/wireapp/wire](https://github.com/wireapp/wire).

For licensing information, see the attached LICENSE file and the list of third-party licenses
at [wire.com/legal/licenses/](https://wire.com/legal/licenses/).

No license is granted to the Wire trademark and its associated logos, all of which will continue to be owned exclusively
by Wire Swiss GmbH. Any use of the Wire trademark and/or its associated logos is expressly prohibited without the
express prior written consent of Wire Swiss GmbH.

## how to cut a release

Currently, the process is manual and involves the following steps:

- Increment the version number for all the crates "e2e-identity", "jwt", "ffi", "cli", "acme", "x509-check" (and their
  use site)
- (optional) if there are changes it's always good to run the e2e test to update the [README](e2e-identity/README.md).
  To do so run `cargo test --package wire-e2e-identity --test e2e demo_should_succeed` (with Docker running)
- Open a PR, merge on the `main` branch and push a git tag e.g. `v0.10.2`

To cut release to be used by the backend you should:

- Do it after the aforementioned step so that the version is already incremented etc..
- Get rid of all [ring](https://crates.io/crates/ring) dependencies. This happens because ring does not build under Nix.
  Our goal is to remove ring from `Cargo.lock`. To do so
    - Comment out all the dependencies pulling ring in all the `Cargo.toml`. To find them you can
      run `cargo tree --invert ring --all-features --edges normal`
    - Make sure the ffi crate compiles `cargo check --package rusty-jwt-tools-ffi`
- Run `cargo update` to refresh `Cargo.lock`
- Just push a branch so that a backender can integrate it. No need to create a PR or merge it.
- Delete the branch once integrated by the backend
