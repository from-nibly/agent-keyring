{ pkgs, helperDirectory ? "/usr/lib/polkit-1" }:

# Use the existing host PAM helper. This package never installs a setuid helper
# or changes the host authority/policy; the calling GUI remains unprivileged.
(pkgs.polkit.override {
  withIntrospection = false;
  doCheck = false;
}).overrideAttrs (old: {
  postPatch = (old.postPatch or "") + ''
    substituteInPlace src/polkitagent/polkitagentsession.c \
      --replace-fail '/run/wrappers/bin/' '${helperDirectory}/'
  '';
})
