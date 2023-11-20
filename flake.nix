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
          GROUP_ID = "3082010a0282010100b8d1702ae16e9197abae7fd5c609dbfcfa2f52e021958e32d1ec5e53ff41c76daeaa3e4e89d0bed01de28f5234d7ccaab0ca2e573ac8f61e3ec91bdfe7ede73004ee2e8839bdbb21a85e70e06dc9e63f031e69b33de01790a608fa00b4cb2a6866e5fbe665573ed4f0037e6e1c22d6b0f9d5160e3fbf93cb5047ae7340debabee2ebe9af4b875ca3aff6b786b73f714b1003bc61e843facae6f31cc4804ce3571640dcbe826e752c723b3b198f6bc345035c14bbe59812bab260f2ba4167e6c6b627b1ae63d6a985954fbb8cf8c5fd99dbf574a1ce1e17abc9aab769c5e559b349c57f559eea5832558fab0070b7e505e17234f48c8813de44c81bab213c91d50203010001";

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
