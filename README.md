# Cryptoki Bridge

Implementation of the Cryptoki library defined by the [PKCS#11 standard](https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.0/os/pkcs11-profiles-v3.0-os.html) that utilizes [Meesign](https://meesign.crocs.fi.muni.cz/) for asymmetric cryptography.

## Usage

- Build the library

```bash
cargo build --release
```

- The library can be found in `./target/release/libmeesign_pkcs11.so`.

## Configuration

Currently, there are multiple ways to configure and control the library.

1. [Controller server](https://github.com/KristianMika/bridge-controller)
2. Environment variables
   - _COMMUNICATOR_URL_ - sets the meesign URL
   - _GROUP_ID_ - sets the signing group
   - _COMMUNICATOR_CERTIFICATE_PATH_ - provides the library with the path to the CA certificate.
