{
  description = "midnight-zk dev shell: Rust (native + wasm32) and node for the circuit visualiser";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      nixpkgs,
      fenix,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Stable toolchain with the wasm32 target std, so both native tests and
        # browser-side proving builds work from the same shell. Pinned via
        # flake.lock (fenix input revision); rust-toolchain.toml pins 1.90.0
        # for rustup users, fenix stable tracks its own lock.
        rustToolchain = fenix.packages.${system}.combine (
          with fenix.packages.${system};
          [
            stable.rustc
            stable.cargo
            stable.rustfmt
            stable.clippy
            stable.rust-src
            stable.rust-analyzer
            targets.wasm32-unknown-unknown.stable.rust-std
          ]
        );
      in
      {
        devShells.default = pkgs.mkShell {
          name = "midnight-zk";

          buildInputs = [
            rustToolchain
            pkgs.pkg-config
            pkgs.openssl
            # wasm C toolchain (for blst when targeting wasm32)
            pkgs.llvmPackages.clang-unwrapped
            pkgs.llvmPackages.bintools-unwrapped
            # wasm packaging + JS tooling for the visualiser frontend
            pkgs.wasm-bindgen-cli
            pkgs.nodejs
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.libiconv
          ];

          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";

          # Use clang (not host gcc) to compile C deps for the wasm32 target.
          CC_wasm32_unknown_unknown = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang";
          AR_wasm32_unknown_unknown = "${pkgs.llvmPackages.bintools-unwrapped}/bin/llvm-ar";
        };
      }
    );

  nixConfig = {
    extra-substituters = [
      "https://cache.iog.io"
      "https://nix-community.cachix.org"
    ];
    extra-trusted-public-keys = [
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
      "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCUSfjI="
    ];
  };
}
