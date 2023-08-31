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

## Configuration

Currently, there are multiple ways to configure and control the library.

1. [Controller server](https://github.com/KristianMika/bridge-controller)
2. Environment variables
   - _COMMUNICATOR_URL_ - sets the meesign URL
   - _GROUP_ID_ - sets the signing group
   - _COMMUNICATOR_CERTIFICATE_PATH_ - provides the library with the path to the CA certificate

## Usage

- The library can be found in `./target/release/libmeesign_pkcs11.so`. You can import it into your tool of choice.

### SSH

_Note: Please, read the [configuration](#configuration) section to be able to select the authentication group_

1. Get the available group public keys in the OpenSSH format.

```bash
ssh-keygen -D <meesign_cryptoki_path.so> -e
```

2. Select the key corresponding to your target group and store it in a file

```bash
echo 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBdg292CUPY0xjjLziR6wkHlPP0yKRF8DYjxMllkphQozXth+Eo12t5vuia8GELe3OFECEeb+Ou34yYL07I2afQ= meesign' > id_ecdsa.pub
```

3. Authorize logins using the acquired public key on a remote server

```bash
ssh-copy-id -f -i id_ecdsa.pub <user@server>
```

4. Authenticate using meesign

```bash
ssh -I <meesign_cryptoki_path.so> <user@server>
```

5. (Optional) Configure the ssh meesign entry by customizing and appending the following entry to `~/.ssh/config`.

```txt
Host <entry_host_name>
    HostName <hostname>
    User <user>
    PKCS11Provider <meesign_cryptoki_path.so>
```

6. (Optional) Authenticate using the meesign ssh entry

```bash
ssh <entry_host_name> # e.g., ssh production_meesign
```
