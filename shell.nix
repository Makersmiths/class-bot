{pkgs ? import <nixpkgs> {}}:
pkgs.mkShell {
  buildInputs = [
    pkgs.rustup # Rust toolchain manager
    pkgs.openssl
    pkgs.pkg-config
    pkgs.just # Task runner
    pkgs.bacon # Live compiler/test runner
    pkgs.cargo
    pkgs.lld # Alternative linker
    pkgs.zlib
    pkgs.glibc # Sometimes needed for linking
  ];

  # OpenSSL environment variables for crates like `openssl-sys`
  OPENSSL_DIR = "${pkgs.openssl.dev}";
  OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
  OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
  PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";

  # Optional: enable core dumps, nicer prompts, etc.
  shellHook = ''
    export RUSTUP_HOME="$HOME/.rustup"
    export CARGO_HOME="$HOME/.cargo"
    export PATH="$CARGO_HOME/bin:$PATH"
  '';
}
