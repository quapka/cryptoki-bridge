# Cryptoki Bridge

[![PKCS#11](https://github.com/KristianMika/cryptoki-bridge/actions/workflows/pkcs11.yaml/badge.svg)](https://github.com/KristianMika/cryptoki-bridge/actions/workflows/pkcs11.yaml)

Implementation of the Cryptoki library defined by the [PKCS#11 standard](https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.0/os/pkcs11-profiles-v3.0-os.html) that utilizes [Meesign](https://meesign.crocs.fi.muni.cz/) for asymmetric cryptography.

## Development

### Build Requirements

- [rust](https://www.rust-lang.org/tools/install)
- [protocol buffer compiler](https://grpc.io/docs/protoc-installation/)

### Dev Container

The [devcontainer](./.devcontainer) folder contains a configuration of a development Docker environment.

1. Install the `ms-vscode-remote.remote-containers` VS Code extension.
2. Press `Ctrl + Shift + P`, select `>Dev Containers: Open folder in Container...`, and select the root repository directory. (_this may take some time for the the first run_)

### Build

- Update submodules

  ```bash
  git submodule update --init --recursive
  ```

- Build the library

  ```bash
  cargo build --release
  ```

## Usage

- The library can be found in `./target/release/libmeesign_pkcs11.so`. You can import it into your tool of choice.

## Configuration

Currently, there are multiple ways to configure and control the library.

1. [Controller server](https://github.com/KristianMika/bridge-controller)
2. Environment variables
   - _COMMUNICATOR_URL_ - sets the meesign URL
   - _GROUP_ID_ - sets the signing group
   - _COMMUNICATOR_CERTIFICATE_PATH_ - provides the library with the path to the CA certificate
