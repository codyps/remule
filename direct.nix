with import <nixpkgs> {};

rustPlatform.buildRustPackage {
  pname = "remule";
  version = "1.0.0";

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  src = ./.;

  nativeBuildInputs = [] ++ 
        lib.optionals stdenv.isDarwin [
            darwin.apple_sdk.frameworks.SystemConfiguration
        ];
}
