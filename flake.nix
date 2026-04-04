{
  description = "Herald — DNS control plane service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    crane.url = "github:ipetkov/crane";

    flake-utils.url = "github:numtide/flake-utils";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    crane,
    flake-utils,
    rust-overlay,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [(import rust-overlay)];
      };

      rustToolchain = pkgs.rust-bin.stable.latest.default.override {
        extensions = ["rust-src" "rust-analyzer"];
        targets = ["x86_64-unknown-linux-musl"];
      };

      craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

      # Common source filtering
      src = craneLib.cleanCargoSource ./.;

      # Common arguments for builds
      commonArgs = {
        inherit src;
        strictDeps = true;

        nativeBuildInputs = with pkgs; [
          pkg-config
        ];

        buildInputs = with pkgs;
          [
            openssl
          ]
          ++ lib.optionals pkgs.stdenv.isDarwin [
            pkgs.libiconv
            pkgs.darwin.apple_sdk.frameworks.Security
            pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
          ];
      };

      # Build just the cargo dependencies for caching
      cargoArtifacts = craneLib.buildDepsOnly commonArgs;

      # Build the actual crate
      herald = craneLib.buildPackage (commonArgs
        // {
          inherit cargoArtifacts;
        });

      # Static musl build for deployment
      muslCc = pkgs.pkgsCross.musl64.stdenv.cc;

      staticArgs = {
        inherit src;
        strictDeps = true;

        CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
        CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";

        # musl C compiler for bundled C dependencies (SQLite)
        nativeBuildInputs = [pkgs.pkg-config muslCc];
        buildInputs = [];

        CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${muslCc}/bin/x86_64-unknown-linux-musl-cc";
        CC_x86_64_unknown_linux_musl = "${muslCc}/bin/x86_64-unknown-linux-musl-cc";
      };

      staticCargoArtifacts = craneLib.buildDepsOnly staticArgs;

      heraldStatic = craneLib.buildPackage (staticArgs
        // {
          cargoArtifacts = staticCargoArtifacts;
        });
    in {
      checks = {
        inherit herald;

        herald-clippy = craneLib.cargoClippy (commonArgs
          // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });

        herald-fmt = craneLib.cargoFmt {
          inherit src;
        };
      };

      packages = {
        default = herald;
        inherit herald heraldStatic;
      };

      apps.default = flake-utils.lib.mkApp {
        drv = herald;
      };

      devShells.default = craneLib.devShell {
        checks = self.checks.${system};

        packages = with pkgs; [
          alejandra
          cargo-watch
          cargo-edit
        ];
      };

      # NixOS module
      nixosModules.default = {
        config,
        lib,
        pkgs,
        ...
      }: {
        imports = [./nix/module.nix];
        config.services.herald.package = lib.mkDefault herald;
      };
    })
    // {
      overlays.default = final: prev: {
        herald = self.packages.${prev.system}.default;
      };
    };
}
