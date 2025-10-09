{
  description = "";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{ self, flake-parts, ... }:

    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
      ];

      perSystem =
        {
          config,
          pkgs,
          system,
          ...
        }:

        let
          pythonEnv = pkgs.python3.withPackages (
            ps: with pkgs.python3Packages; [
              flask
            ]
          );
        in
        {
          devShells.default = pkgs.mkShell {
            packages = [ pythonEnv ];
          };

          _module.args.rootPath = ./.;
        };
    };
}
