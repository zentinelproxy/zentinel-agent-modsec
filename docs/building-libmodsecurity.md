# Building libmodsecurity

The agent links libmodsecurity 3 dynamically through the `modsecurity-sys` crate, which finds it with `pkg-config` (package `modsecurity`, version 3.0.13 or newer) and cannot build it itself. So the library, its headers and `modsecurity.pc` must be installed to build the agent, and the shared library must be installed wherever the agent runs.

CI and the release workflow build ModSecurity **v3.0.14** against **PCRE2**. Use the same unless you have a reason not to.

## Linux (Debian, Ubuntu)

This is what `.github/workflows/ci.yml` and `release.yml` do on `ubuntu-latest`.

```bash
sudo apt-get update
sudo apt-get install -y protobuf-compiler build-essential libtool autoconf automake \
  pkg-config libcurl4-openssl-dev libpcre2-dev libyajl-dev libxml2-dev

git clone --depth 1 --branch v3.0.14 https://github.com/owasp-modsecurity/ModSecurity.git
cd ModSecurity
git submodule init && git submodule update
./build.sh
./configure --prefix=/usr/local --without-lmdb --with-pcre2
make -j"$(nproc)"
sudo make install
sudo ldconfig
```

- `libyajl-dev` gives libmodsecurity its JSON body processor and `libxml2-dev` its XML one. Without them, JSON and XML request bodies are not parsed into `ARGS` and the CRS injection rules do not see them.
- `protobuf-compiler` is not needed by libmodsecurity; the agent's build needs `protoc` for the protocol crate.
- The library installs into `/usr/local`. If `pkg-config --modversion modsecurity` does not find it, set `PKG_CONFIG_PATH=/usr/local/lib/pkgconfig`; if the agent cannot load it at run time, run `sudo ldconfig` or set `LD_LIBRARY_PATH=/usr/local/lib`. CI sets both variables.

Check the result:

```bash
pkg-config --modversion modsecurity     # 3.0.14
pkg-config --libs modsecurity           # -L/usr/local/lib -lmodsecurity
```

### Why `--with-pcre2`, and why not `libpcre3-dev`

libmodsecurity can use either PCRE (PCRE1, the `libpcre3-dev` package) or PCRE2 for `@rx`. Its `configure` probes for PCRE1 unless `--with-pcre2` is given, and then needs PCRE1's headers.

PCRE1 is end of life, and the `ubuntu-26.04` runner image no longer packages `libpcre3-dev`: every Linux job failed in "Install system deps" with `Package 'libpcre3-dev' has no installation candidate` before building anything. #10 dropped `libpcre3-dev`, passed `--with-pcre2` (PCRE2 was already installed but unused), and changed the libmodsecurity cache key so a runner would not reuse a library cached from the PCRE1 build.

If you change how libmodsecurity is built in a workflow, change its cache key too (the `key:` of the `Cache libmodsecurity` step), or runners keep using the old build.

### Distribution packages

Some distributions package libmodsecurity (`libmodsecurity-dev` to build, `libmodsecurity3` to run). That is fine if `pkg-config --modversion modsecurity` reports 3.0.13 or newer; the build fails otherwise with a `pkg-config` version error from `modsecurity-sys`. The release binaries are built against the v3.0.14 source build above, and need a `libmodsecurity.so.3` on the host at run time.

## macOS

```bash
brew install modsecurity protobuf
pkg-config --modversion modsecurity
```

Homebrew's `modsecurity` is built with PCRE2 and yajl and is usually newer than 3.0.13. The release workflow uses it for the `darwin-aarch64` build. Neither CI nor the release workflow builds libmodsecurity from source on macOS.

## Using the agent's build afterwards

```bash
cargo build --release --locked
ldd target/release/zentinel-modsec-agent | grep modsecurity      # Linux
otool -L target/release/zentinel-modsec-agent | grep modsecurity  # macOS
```

The binary records the library's install name, so a host that runs it needs libmodsecurity at a path the dynamic loader searches.
