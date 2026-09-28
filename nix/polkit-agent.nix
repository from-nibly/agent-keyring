{ pkgs, helperDirectory ? "/usr/lib/polkit-1" }:

let
  hostPolkit = import ./host-polkit.nix { inherit pkgs helperDirectory; };
in
pkgs.polkit_gnome.override { polkit = hostPolkit; }
