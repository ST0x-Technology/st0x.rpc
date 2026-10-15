{
  description = "st0x-rpc — alloy JSON-RPC client with KMS-signed Alchemy JWTs";

  inputs = {
    rainix.url = "github:rainlanguage/rainix";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      flake-utils,
      rainix,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (system: {
      devShells.default = rainix.devShells.${system}.rust-shell;
    });
}
