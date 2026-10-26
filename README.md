# Open ePort SKF

`eportskf` provides C11 shared and static libraries and a command-line tool for China ePort smart cards and ePort USB tokens. It reads certificate identities, verifies user PINs, and signs messages with private keys held by the device. PC/SC smart cards produce SM2 signatures over SM3; USB HID tokens produce RSA-1024 signatures over SHA1.

## Environment

- Windows x64 or arm64, with the smart-card service and device drivers installed.
- Linux x64 or arm64, with the system PC/SC service and read/write permission for the token's `/dev/hidrawN` node.
- CMake 3.20 or later and a C11 compiler for source builds.

The library uses C and operating-system interfaces only. The medium determines the signature algorithm.

## Builds

Builds run in GitHub Actions. Each release builds Windows x64, Windows arm64, Linux x64, and Linux arm64, and attaches one archive per platform. The workflow also runs on demand for an existing release tag.

## First signatures

List every readable device and its identity:

```sh
eportskf list
```

Show one identity. Quote the exact name printed by `list`:

```sh
eportskf identity "[PCSC] reader name"
eportskf identity "[HID] /dev/hidraw0"
```

Sign command-line text or a file:

```sh
eportskf sign --device "[PCSC] reader name" --text "hello"
eportskf sign --device "[HID] /dev/hidraw0" --file ./message.bin
```

The `--device` option can be omitted when exactly one device is enumerable. The tool reads the eight-byte PIN from standard input and hides interactive entry. It prints verification status, algorithm, signature length, hexadecimal, and Base64. File messages are processed in bounded chunks.

The exit status is `0` for success, `2` for a command usage error, and `1` for a runtime failure. Runtime descriptions are `Unusable argument`, `Device unavailable`, `PIN rejected`, `Verification required`, and `Failure`.

## Library calls

Include `include/eportskf.h` and link either the shared or static library. Enumerate with `eportskf_enumerate`, open an enumerated name with `eportskf_open`, then call `eportskf_verify_pin` and `eportskf_sign`. Release results with `eportskf_free_device_list`, `eportskf_free_identity`, and `eportskf_close`.

For a streaming message, replace `eportskf_sign` with `eportskf_sign_start`, ordered calls to `eportskf_sign_update`, and `eportskf_sign_finish`. Call `eportskf_sign_abort` to discard an unfinished signature. One device has at most one active streaming signature. Device names are UTF-8, and identity fields are NUL-free seven-bit ASCII.

See `DESIGN.md` for ownership, state transitions, and component contracts, and `PROTOCOL.md` for card commands and data formats.

## Install

The Windows archive is a ZIP bundle and the Linux archive is a tar bundle. Each bundle contains the CLI, shared and static libraries, public header, licence, and CMake package configuration. The static library is named `eportskf_static.lib` on Windows and `libeportskf_static.a` on Linux.

An unpacked bundle is an installation prefix: `bin` holds the CLI, `lib` the libraries and the CMake package configuration, and `include` the public header.

An installed native CMake project consumes the shared library with:

```cmake
find_package(eportskf CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE eportskf::eportskf)
```

Use `eportskf::eportskf_static` instead to link the static library. When linking `eportskf_static.lib` directly on Windows without the CMake target, define `EPORTSKF_STATIC` for the consuming source files and link `hid`, `setupapi`, and `winscard`.

On Linux, grant the calling user access to the specific HID token through the distribution's device-permission mechanism. The user also needs access to the system smart-card service.

## GitHub Packages

The release workflow publishes one `eportskf` NuGet package containing all four platform prefixes. GitHub Packages requires an authenticated NuGet source, including for public packages. Configure `https://nuget.pkg.github.com/OWNER/index.json` with a token that has the `read:packages` scope.

A native Windows C++ project declares the package in `packages.config`:

```xml
<package id="eportskf" version="1.0.0" targetFramework="native" />
```

Import the props from the restored package into the project:

```xml
<Import Project="packages\eportskf.1.0.0\build\native\eportskf.props" />
```

The props add the include and library directories for the project's x64 or ARM64 platform. The shared and static linking rules above apply unchanged.

For CMake, add the matching `win-x64`, `win-arm64`, `linux-x64`, or `linux-arm64` directory in the restored package to `CMAKE_PREFIX_PATH`, then use `find_package(eportskf CONFIG REQUIRED)` and the imported targets shown above.

## Release

Create a GitHub release for a tag. The tag, with an optional leading `v` removed, is the version of the generated packages and of the NuGet package. The workflow builds Windows x64, Windows arm64, Linux x64, and Linux arm64 packages, attaches them to the release, and publishes the combined NuGet package to GitHub Packages.

## Licence

Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com>.

This project is licensed under `AGPL-3.0-only`. See `LICENSE`.
