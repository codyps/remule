{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    crate2nix = {
      url = "github:kolloch/crate2nix";
      flake = false;
    };
    flake-utils.url = "github:numtide/flake-utils";
    # included for `default.nix` support
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, crate2nix, flake-utils, flake-compat }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        crateName = "remule";

        inherit (import "${crate2nix}/tools.nix" { inherit pkgs; })
          generatedCargoNix;

        project = import (generatedCargoNix {
          name = crateName;
          src = ./.;
        }) {
          inherit pkgs;
          defaultCrateOverrides = pkgs.defaultCrateOverrides // {
            sqlx-macros = attrs: {
              buildInputs =
                nixpkgs.lib.optionals
                pkgs.stdenv.isDarwin
                [ pkgs.darwin.apple_sdk.frameworks.SystemConfiguration ];
            };
            collect-peers = attrs: {
              buildInputs =
                nixpkgs.lib.optionals
                pkgs.stdenv.isDarwin
                [ pkgs.darwin.apple_sdk.frameworks.SystemConfiguration ];
            };
          };
        };

      in {
        packages.${crateName} = project.workspaceMembers.collect-peers.build;

        defaultPackage = self.packages.${system}.${crateName};

        devShell = pkgs.mkShell {
          inputsFrom = builtins.attrValues self.packages.${system};
          buildInputs = [ pkgs.cargo pkgs.rust-analyzer pkgs.clippy ];
        };
      });
}
