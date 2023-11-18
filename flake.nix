{
  description = "Cryptoki Bridge";

  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/23.05";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url  = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
      in
      with pkgs;
      {
        devShells.default = mkShell {
          buildInputs = [
            ltrace
            libclang
            pkcs11helper
            openssl
            protobuf
            pkg-config
            rust-bin.beta.latest.default
            opensc
          ];
          # COMMUNICATOR_HOSTNAME - sets the meesign hostname, e.g., meesign.crocs.fi.muni.cz (required)
# COMMUNICATOR_CERTIFICATE_PATH - provides the library with the path to the CA certificate (required)
# GROUP_ID - sets the signing group (optional). If not set, all groups present on the communicator are available.

          # MeeSign config
          COMMUNICATOR_HOSTNAME = "meesign.local"; #- sets the meesign hostname, e.g., meesign.crocs.fi.muni.cz (required)
          COMMUNICATOR_CERTIFICATE_PATH = "/home/qup/projects/meesign-server/keys/meesign-ca-cert.pem"; # - provides the library with the path to the CA certificate (required)
          GROUP_ID = "304802410090f7600cbdca772e8471f31c7fb84823d3ed5434ef3a657704ddf7aa2bdb284e7a347afc09da0d108bdaac0645008f4b072957dca628f66865641c1555355af50203010001";

          # Specifies the path to the original PKCS#11 library. Value needs to be provided without the enclosing quotes. When this variable is not defined all logger functions return CKR_GENERAL_ERROR and print information about missing environment variable to the stderr.
          PKCS11_LOGGER_LIBRARY_PATH = "/home/qup/projects/cryptoki-bridge/target/release/libcryptoki_bridge.so";


          PKCS11_LOGGER_LOG_FILE_PATH = "meesign.log";

          # Specifies the path to the log file. Value needs to be provided without the enclosing quotes.

          PKCS11_LOGGER_FLAGS = "48";


          CPATH = with pkgs; lib.concatStringsSep ":" [
            "${pkcs11helper.outPath}/include/pkcs11-helper-1.0/"
             (with stdenv.cc; "${cc.outPath}/lib/gcc/x86_64-unknown-linux-gnu/${cc.version}/include")
          ];
          LIBCLANG_PATH = with pkgs; lib.makeLibraryPath [ libclang ];
        };
      }
    );
}
