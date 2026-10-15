# NixOS module: `programs.ipsak.enable = true;` installs ipsak with
# CAP_NET_RAW, as the deb and rpm packages do.
{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.ipsak;
in
{
  options.programs.ipsak = {
    enable = lib.mkEnableOption "ipsak, the IP Swiss Army Knife, with raw-socket access for all users";
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "ipsak.packages.\${pkgs.stdenv.hostPlatform.system}.default";
      description = "The ipsak package to install.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];
    # AIDEV-NOTE: /run/wrappers/bin precedes the system profile on PATH, so
    # `ipsak` runs through this wrapper. The wrapper passes CAP_NET_RAW to
    # ipsak as an ambient capability, which is why "+p" suffices.
    security.wrappers.ipsak = {
      owner = "root";
      group = "root";
      capabilities = "cap_net_raw+p";
      source = lib.getExe cfg.package;
    };
  };
}
