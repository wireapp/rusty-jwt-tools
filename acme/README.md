# Rusty ACME types

This crates provides types to perform the ACME certificate enrollment. However, it does not do any IO which it delegates
to the platform's network stack. It mainly targets [step-ca](https://smallstep.com/docs/step-ca) Certificate Authority.
