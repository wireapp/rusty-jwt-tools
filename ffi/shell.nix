let
  nixpkgs = fetchTarball "https://github.com/NixOS/nixpkgs/archive/e236b838c71d2aff275356ade8104bbdef422117.tar.gz";
  pkgs = import nixpkgs { config = {}; overlays = []; };
in

pkgs.mkShellNoCC {
  nativeBuildInputs = with pkgs; [
    cargo
    cargo-make
    rustc
    gcc
    cabal-install
    ghc
    ghcid
  ];
}
