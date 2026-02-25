{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    crate2nix = {
      url = "github:kolloch/crate2nix";
      flake = false;
    };
    flake-utils.url = "github:numtide/flake-utils";
    # included for `default.nix`/`shell.nix`/`nix-build`/`nix-shell` support
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

        inherit (pkgs.darwin.apple_sdk.frameworks) SystemConfiguration;

        linkInputs = nixpkgs.lib.optionals pkgs.stdenv.isDarwin [ SystemConfiguration ];

        # I _think_ these are from linking libsqlite3. Placing them just on
        # `libsqlite3-sys` crate doesn't work though, it seems they aren't
        # present at the link step. Might need some munging to get SC to show
        # up as a dep for link targets that depend on libsqlite3-sys (rather
        # than just showing up as a build dep for exactly `libsqlite3-sys`
        # and nothing else.
        #
        # Part of the issue here is likely that we're not actually using
        # nix's sqlite because the `bundled` feature is enabled by
        # `sqlx-core` on `libsqlite3-sys`, which should cause it to try to
        # build a local sqlite within the libsqlite3-sys build process.
        #
        # see https://github.com/launchbadge/sqlx/issues/191 for some
        # discussion
        linkDeps = attrs: {
            buildInputs = linkInputs;
        };

        project = import (generatedCargoNix {
          name = crateName;
          src = ./.;
        }) {
          inherit pkgs;
          defaultCrateOverrides = pkgs.defaultCrateOverrides // {
            #libsqlite3-sys = attrs: {
            #  propagatedBuildInputs = linkInputs;
            #  extraLinkFlags = [ "-L" "native=${SystemConfiguration.out}/Library/Frameworks" ];
            #};
            sqlx-macros = attrs: {
              buildInputs = linkInputs;
            #  extraLinkFlags = [ "-lfake-labrary-that-doesnot-exist" ];
            };
            collect-peers = linkDeps;
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
