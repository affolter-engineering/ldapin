{
  description = "ldapin — discover valid LDAP fields from a server's schema";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        ldapin = pkgs.rustPlatform.buildRustPackage {
          pname = "ldapin";
          version = "0.1.0";

          src = ./.;

          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.openssl ];

          # propagate openssl for runtime linking on Linux
          env.OPENSSL_NO_VENDOR = "1";
        };
      in
      {
        packages.default = ldapin;
        packages.ldapin = ldapin;

        apps.default = {
          type = "app";
          program = "${ldapin}/bin/ldapin";
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ ldapin ];
          packages = [ pkgs.rust-analyzer pkgs.rustfmt pkgs.clippy ];
        };
      });
}
