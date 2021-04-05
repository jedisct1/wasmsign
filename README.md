[![Build Status](https://travis-ci.org/jedisct1/wasmsign.svg?branch=master)](https://travis-ci.org/jedisct1/wasmsign?branch=master)

![Wasmsign](https://raw.github.com/jedisct1/wasmsign/master/logo.png)

A tool to add and verify digital signatures to/from WASM binaries.

# WASM signatures

Unlike typical desktop and mobile applications, WebAssembly binaries do not embed any kind of digital signatures to verify that they come from a trusted source, and haven't been tampered with.

Wasmsign takes an existing wasm binary, computes an EdDSA signature, and builds a new binary embedding that signature as a global, exported symbol.

The resulting binary remains a standalone, valid wasm binary, but its signature can be verified prior to executing it.

# Installation

`wasmsign` requires rust, which can be installed using [`rustup`](https://rustup.rs/).

`cargo install` is then all it takes to compile and install the command-line `wasmsign` tool.

# Usage

```text
    wasmsign [FLAGS] [OPTIONS] --symbol-name <symbol-name>

FLAGS:
    -h, --help                  Prints help information
    -G, --keygen                Generate a key pair
    -S, --sign                  Sign a file
    -C, --use-custom-section    Sign/verify signature in a Custom Section
        --version               Prints version information
    -V, --verify                Verify a file

OPTIONS:
    -a, --ad <ad>                                      Additional content to authenticate
    -c, --custom-section-name <custom-section-name>    Name of the Custom Section containing the signature
    -i, --input <input-path>                           Path to the wasm input file
    -o, --output <output-path>                         Path to the wasm output file
    -p, --pk-path <pk-path>                            Path to the public key file
    -s, --sk-path <sk-path>                            Path to the secret key file
    -n, --symbol-name <symbol-name>
            Name of the exported symbol containing the signature [default: ___SIGNATURE]
```

## Create a key pair

```sh
wasmsign --keygen --pk-path key.public --sk-path key.secret
```

## Sign an existing wasm binary

```sh
wasmsign --sign --pk-path key.public --sk-path key.secret \
  --input unsigned.wasm --output signed.wasm
```

Additional data can be authenticated, so that the signature is only valid for a given user, group, or machine:

```sh
wasmsign --sign --pk-path key.public --sk-path key.secret \
  --input unsigned.wasm --output signed.wasm --ad user19238
```

## Verify an existing wasm binary

```sh
wasmsign --verify --pk-path key.public --input signed.wasm
```

or with additional data:

```sh
wasmsign --verify --pk-path key.public --input signed.wasm --ad user19238
```

The command exits with `0` if the embedded signature is valid for the given public key, content and additional data, or with a non-`0` value on error.
