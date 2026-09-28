{ pkgs ? import <nixpkgs> {}, helperDirectory ? "/usr/lib/polkit-1" }:

let
  hostPolkit = import ./host-polkit.nix { inherit pkgs helperDirectory; };
in
pkgs.stdenv.mkDerivation {
  pname = "agent-keyring-approval";
  version = (builtins.fromTOML (builtins.readFile ../Cargo.toml)).package.version;
  src = pkgs.lib.cleanSourceWith {
    src = ../gui;
    filter = path: type:
      type == "directory" || builtins.elem (baseNameOf path) [
        "Makefile" "approval.c" "test-approval.c"
      ];
  };

  nativeBuildInputs = [ pkgs.pkg-config pkgs.wrapGAppsHook3 ];
  buildInputs = [ pkgs.gtk3 pkgs.glib hostPolkit ];
  nativeCheckInputs = [ pkgs.xvfb-run ];
  doCheck = true;
  checkPhase = ''
    runHook preCheck
    export HOME="$TMPDIR" GDK_BACKEND=x11 NO_AT_BRIDGE=1
    make check
    runHook postCheck
  '';
  installPhase = ''
    runHook preInstall
    make install PREFIX="$out"
    runHook postInstall
  '';
  meta = {
    description = "Process-scoped single-window Agent Keyring approval listener";
    platforms = pkgs.lib.platforms.linux;
  };
}
