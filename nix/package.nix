{
  lib,
  stdenv,
  buildGoModule,
  installShellFiles,
  version ? "dev",
}:

buildGoModule {
  pname = "ipsak";
  inherit version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../go.mod
      ../go.sum
      ../cmd
      ../internal
    ];
  };

  # AIDEV-NOTE: vendorHash pins the modules in go.sum. After any dependency
  # change, set it to lib.fakeHash, run `nix build`, and copy the hash from
  # the mismatch error. CI's nix job fails until it matches.
  vendorHash = "sha256-yjwGqBK3sxdNbsd3Su+kXiUh1H1bdcevJmpgfd8ZFkQ=";

  env.CGO_ENABLED = 0;
  ldflags = [
    "-s"
    "-w"
    "-X main.version=${version}"
  ];

  # The DNS test fixtures listen on loopback.
  __darwinAllowLocalNetworking = true;

  nativeBuildInputs = [ installShellFiles ];
  postInstall = lib.optionalString (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
    installShellCompletion --cmd ipsak \
      --bash <($out/bin/ipsak completion bash) \
      --fish <($out/bin/ipsak completion fish) \
      --zsh <($out/bin/ipsak completion zsh)
  '';

  meta = {
    description = "IP Swiss Army Knife: network diagnostics for addresses, domains and subnets";
    homepage = "https://github.com/linsomniac/ipsak";
    license = lib.licenses.cc0;
    mainProgram = "ipsak";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
