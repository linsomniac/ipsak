{
  description = "ipsak, the IP Swiss Army Knife: network diagnostics for addresses, domains and subnets";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      # Flakes cannot see tags, so builds report the commit date and revision.
      version = "unstable-${builtins.substring 0 8 (self.lastModifiedDate or "19700101")}-${
        self.shortRev or self.dirtyShortRev or "unknown"
      }";
    in
    {
      packages = forAllSystems (pkgs: rec {
        ipsak = pkgs.callPackage ./nix/package.nix { inherit version; };
        default = ipsak;
      });

      overlays.default = final: prev: {
        ipsak = final.callPackage ./nix/package.nix { inherit version; };
      };

      nixosModules.default = import ./nix/module.nix { inherit self; };

      checks = forAllSystems (
        pkgs:
        {
          ipsak = self.packages.${pkgs.stdenv.hostPlatform.system}.ipsak;
        }
        // nixpkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          nixos-module = import ./nix/test.nix {
            inherit pkgs;
            module = self.nixosModules.default;
          };
        }
      );

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
