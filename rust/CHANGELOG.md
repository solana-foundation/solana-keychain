## 1.0.1 - 2026-04-03


### Documentation

- update rust/README.md with security audit section

- add Accretion audit report and security audit section

## 1.0.0 - 2026-04-03


### Bug Fixes

- align aws-kms package metadata and lockfile with main

- align signer trait and tests with transaction result enum

- address review findings and dfns auth signing compatibility

- redact private key file io errors

- redact private key parse errors

- implement audit remediations across rust and ts


### Refactoring

- avoid expect in pubkey path

- fold http config into signer factory methods

- move signature prefix parser into signer

- standardize signer constructors around config structs

- remove cfg test branches from https enforcement


### Testing

- add signature verification failure coverage

- cover signature verification failure path

- fail integration when required env is missing


### Style

- apply formatting fixes

- hoist test imports to module scope

## 0.5.1 - 2026-03-27

## 0.5.0 - 2026-03-20


### Features

- add rust and typescript crossmint signers (#70)

- add signature verification to all signer backends (#68)

## 0.4.0 - 2026-03-06


### Bug Fixes

- pin solana-shred-version to =3.0.0 for sdk-v3 feature (#46)


### Features

- add DFNS signer integration (#51)

- Add CDP (Coinbase Developer Platform) signer integration (#44)

- add Para MPC signer (#45)

## 0.3.0 - 2026-01-28


### Documentation

- update READMEs and add missing package documentation (#33)


### Features

- add GCP signer integration (#29)


### Refactoring

- rename from_kms to from_aws_kms for consistency (#32)

- Rename KmsSigner to AwsKmsSigner since other third party use the KMS acronym as well (#30)

## 0.2.1 - 2026-01-06

## 0.2.0 - 2025-12-19


### Features

- add Fireblocks signer integration (#20)


### Impl

- aws kms for ts + rust (#18)

## 0.1.1 - 2025-11-24


### Bug Fixes

- Improved release script


### Refactoring

- rename solana-signers to solana-keychain (#14)

