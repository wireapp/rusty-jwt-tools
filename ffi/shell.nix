let
  nixpkgs = fetchTarball "https://github.com/NixOS/nixpkgs/archive/release-24.11.tar.gz";
  pkgs = import nixpkgs { config = {}; overlays = []; };
  hsShell = pkgs.haskellPackages.shellFor {
      packages = hpkgs: [(hpkgs.callCabal2nix "rusty-jwt-haskell-bindings" ./bindings/haskell {
          rusty_jwt_tools_ffi = null;
      })];
  };
in

pkgs.mkShellNoCC {
  nativeBuildInputs = with pkgs; [
    cargo
    cargo-make
    rustc
    gcc
    cabal-install
    ghcid
  ] ++ hsShell.nativeBuildInputs;
}
