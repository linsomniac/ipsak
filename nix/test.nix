# NixOS VM test: with the module enabled, an ordinary user can run a
# raw-socket command, and only because of the module's wrapper.
{ pkgs, module }:
pkgs.testers.runNixOSTest (
  { nodes, ... }:
  let
    unwrapped = pkgs.lib.getExe nodes.machine.programs.ipsak.package;
  in
  {
    name = "ipsak";
    nodes.machine = {
      imports = [ module ];
      programs.ipsak.enable = true;
      users.users.alice.isNormalUser = true;
    };
    testScript = ''
      machine.wait_for_unit("multi-user.target")
      machine.succeed("su - alice -c 'ipsak --version'")
      machine.succeed("su - alice -c 'ipsak mtu 127.0.0.1 --plain'")
      machine.fail("su - alice -c '${unwrapped} mtu 127.0.0.1 --plain'")
    '';
  }
)
