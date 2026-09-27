{ pkgs, helperDirectory ? "/usr/lib/polkit-1" }:

let
  # Standalone Home Manager on Debian/Ubuntu must use the host's setuid PAM
  # helper, not NixOS's nonexistent /run/wrappers/bin helper. The GUI stays an
  # ordinary user process; no setuid executable is installed by this package.
  hostPolkit = (pkgs.polkit.override {
    withIntrospection = false;
    doCheck = false;
  }).overrideAttrs (old: {
    postPatch = (old.postPatch or "") + ''
      substituteInPlace src/polkitagent/polkitagentsession.c \
        --replace-fail '/run/wrappers/bin/' '${helperDirectory}/'
    '';
  });
in
pkgs.polkit_gnome.override { polkit = hostPolkit; }
