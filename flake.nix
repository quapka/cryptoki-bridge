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


          CPATH = with pkgs; lib.concatStringsSep ":" [
            "${pkcs11helper.outPath}/include/pkcs11-helper-1.0/"
             (with stdenv.cc; "${cc.outPath}/lib/gcc/x86_64-unknown-linux-gnu/${cc.version}/include")
          ];
          LIBCLANG_PATH = with pkgs; lib.makeLibraryPath [ libclang ];
        };
      }
    );
}
