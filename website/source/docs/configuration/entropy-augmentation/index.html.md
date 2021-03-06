---
layout: "docs"
page_title: "Entropy Augmentation - Configuration"
sidebar_title: "<code>Entropy Augmentation</code> <sup>ENT</sup>"
sidebar_current: "docs-configuration-entropy-augmentation"
description: |-
  Entropy augmentation enables Vault to sample entropy from external cryptographic modules.
---

# `Entropy Augmentation` Seal

  Entropy augmentation enables Vault to sample entropy from an external cryptographic modules.
  Currently, sourcing external entropy is done through a configured [PKCS11 seal](/docs/configuration/seal/pkcs11.html).
  Vault Enterprises's external entropy support is activated by the presence of an `entropy "seal"`
  block in Vault's configuration file.

## Requirements

The following software packages are required for Vault Enterprise Entropy Augmentation:

- PKCS#11 compatible HSM integration library. Vault targets version 2.2 or
  higher of PKCS#11. Depending on any given HSM, some functions (such as key
  generation) may have to be performed manually.
- The [GNU libltdl library](https://www.gnu.org/software/libtool/manual/html_node/Using-libltdl.html)
  — ensure that it is installed for the correct architecture of your servers
- Governance and Policy module of a Vault Enterprise license

## `entropy` Example

This example shows configuring entropy augmentation through a PKCS11 HSM seal from Vault's configuration
file:

```hcl
seal "pkcs11" {
    ...
}

entropy "seal" {
    mode = "augmentation"
}
```

## `entropy augmentation` Parameters

These parameters apply to the `entropy` stanza in the Vault configuration file:

- `mode` `(string: <required>)`: The mode determines which Vault operations requiring
entropy will sample entropy from the external source. Currently, the only mode supported
is `augmentation` which sources entropy for [Critical Security Parameters (CSPs)](/docs/enterprise/entropy-augmentation/index.html#Critical-Security-Parameters-(CSPs)).
