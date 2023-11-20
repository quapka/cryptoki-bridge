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
          GROUP_ID = "308201090282010067adff7c8b80271cb1f085958a854684a092d10b8c9fd44dbec67dfe5fe4f251ff1bf36ebb9ebff86ac742340769da037ca523440ceafca1308a0fee7559d3a3322161ee163aa734c32fe8fdc70756cb26130ced5d30e3ddf37fe4344b107fd7f85f0a81c0020178b818af1f14ebef796ae9a10b4529a1f931aa2342818342285e34077a1b18e8a443bb98efcf8f713748d2156ac759d529421f2bd0fca03230b34e8f9592a58cf8c886fc3128ca863159f5826b6412de83b72fbc2197896662b36feeab9c88cf827414ab2d00cc13b89d719886b7bee8697f0f9ad409501ad07fbcadbc5a87403113527125ef9b2920b5ce63b68d97cd000946f665bccb3ef50203010001";

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
