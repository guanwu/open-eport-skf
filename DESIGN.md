# System design

## Components

The system provides the shared library `eportskf`, the static library `eportskf_static`, and the command-line program `eportskf`. The public C ABI accepts UTF-8 device names, returns ASCII identity fields, verifies eight-byte user PINs, and signs memory buffers or incrementally supplied messages.

| Component | Responsibility |
| --- | --- |
| Public API and device session | Device lifetime, result mapping, identity caching, PIN authorization, signature sequencing |
| PC/SC medium | Reader discovery, card connection, application and container selection, SM2 card commands |
| HID medium | Token discovery, eight-byte report framing, transport unlock, RSA token commands |
| Certificate reader | Bounded DER traversal, serial and extension extraction, SM2 public-point extraction |
| Cryptographic core | Incremental SHA1 and SM3, SM2 ZA construction, single-block SM4 encryption |
| CLI | Device selection, identity display, PIN input, text and file signing, signature formatting |
| Build and release | Shared-library, static-library and executable builds, installation, CMake package export, platform bundles and native packages |

## Public ABI

The public declarations are in `include/eportskf.h`. All operational functions return `eportskf_result`. `eportskf_result_description` maps every result to its fixed description: `Success`, `Unusable argument`, `Device unavailable`, `PIN rejected`, `Verification required`, or `Failure`.

`eportskf_device` is opaque. An open device owns its transport, parsed certificate cache, PIN authorization, and streaming hash. Distinct device handles have independent state. Calls on one handle are externally serialized by the caller.

`eportskf_enumerate` fills a caller-provided list structure with library-allocated entries. Each entry contains an openable device name and the two identity strings. Candidates that cannot be opened or identified are omitted. An empty candidate set produces an empty successful list. `eportskf_free_device_list` releases all nested allocations and resets the list.

`eportskf_open` accepts `[PCSC] ` followed by a reader name or `[HID] ` followed by a platform descriptor. Prefix matching is exact and the descriptor is nonempty. A null name or other null required pointer produces `EPORTSKF_UNUSABLE_ARGUMENT`. A nonnull name with an unknown prefix or empty descriptor produces `EPORTSKF_DEVICE_UNAVAILABLE`. A name produced by enumeration is passed to the medium unchanged after prefix removal.

`eportskf_read_identity` returns an independently allocated identity through `eportskf_identity`; `eportskf_free_identity` releases its strings. A successful parse is cached on the device. A failed read leaves the handle open and a later call retries the certificate exchange. The public identity contains `cert_id` and `device_id`.

`eportskf_close` abandons an unfinished streaming signature, clears authorization, closes the transport, and releases the handle. The handle is invalid after every close call on a nonnull handle. Transport close errors are reported after local cleanup.

`eportskf_signature` contains an algorithm, a byte length, and 128 bytes of storage. The medium supplies the algorithm: PC/SC produces `EPORTSKF_ALGORITHM_SM2_SM3` and 64 bytes; HID produces `EPORTSKF_ALGORITHM_RSA_SHA1` and 128 bytes.

## Device session and signature state

A device opens without user authorization. Successful user-PIN verification sets authorization. Close, removal, disconnect, reset, timeout, and an unusable transport handle clear it. A `6982` signing response clears it. PIN verification can run before a signature or between streaming updates.

An idle device accepts `eportskf_sign_start` or `eportskf_sign`. Starting a second streaming signature or updating an idle device produces `EPORTSKF_FAILURE`. An empty update is valid, including an update with a null data pointer and zero length. A nonempty update requires a readable data pointer.

Finishing an active streaming signature consumes the active state on every return path. It produces `EPORTSKF_VERIFICATION_REQUIRED` without a signature when authorization is inactive. Otherwise it finalizes the digest and invokes the medium operation. `eportskf_sign_abort` clears an active signature without a card command and returns success; aborting an idle device returns `EPORTSKF_FAILURE`.

The one-shot operation is the sequence start, one update, and finish. Its internal failure paths abandon any active state created by that call. The one-shot and streaming paths use the same hash initialization and update routines.

SM2 initialization computes `ZA` from the fixed user identifier and cached certificate public point, then initializes the message hash with `ZA`. A missing certificate or SM2 point is retried through the certificate operation when signing starts. SHA1 initialization for HID requires no identity data. Message storage consists of the fixed hash state and at most one partial 64-byte hash block.

## Medium operations

Both media implement the same internal operations: read DER certificate, verify an eight-byte PIN, sign a completed digest, and close. Digest length and signature representation are fixed by the medium. Internal status interpretation follows the operation context in `PROTOCOL.md`.

PC/SC enumeration obtains reader names from the system smart-card service. Opening connects to the named reader with T=0 or T=1 and selects the ePort application. The container is selected lazily before the first certificate or signature command. PIN verification obtains a fresh challenge, derives the SM4 key from the PIN, encrypts the challenge block, and submits the verify command. Certificate export validates both length prefixes and the DER boundary. SM2 signing accepts a 32-byte digest and returns the 64 bytes following the four-byte response header.

HID enumeration filters USB interfaces by vendor `1A56` and product `DD01`. Opening verifies the same IDs on the opened handle, performs wake-up and information exchanges, unlocks the fixed transport PIN, and selects the certificate file. Every read and write has an eight-second timeout. Output streams are divided into seven-byte report payloads and zero-padded. Input framing follows the one-byte declared stream length and ignores trailing report padding.

The HID certificate reader obtains the DER header, validates the declared total length, and reads from offset zero in chunks of at most 128 bytes. RSA signing reverses the 20-byte SHA1 digest, handles `61xx`, issues `GET RESPONSE`, requires exactly 128 response bytes, and reverses the signature into standard big-endian form.

Windows uses WinSCard, SetupAPI, HID, wide-character device interfaces, overlapped HID I/O, and cancellation on timeout. Linux uses the system PC/SC service and `/dev/hidrawN` with nonblocking bounded waits. Public UTF-8 names cross the Windows interface through UTF-16 conversion.

## Certificate processing

The certificate parser accepts definite short, `81`, and `82` lengths within the 2048-byte DER limit. It rejects truncation, indefinite lengths, trailing bytes, and values outside their containing objects. It reads the TBSCertificate serial INTEGER as lowercase hexadecimal content bytes and locates extension `1.3.6.1.4.1.5315.100.5.9`.

The device-number extension contains an OCTET STRING of at most 512 encoded bytes and exactly one text TLV tagged as UTF8String, PrintableString or IA5String. A leading two-ASCII-digit `NN-` prefix is removed. Every remaining byte must be in the range `01` through `7F` hexadecimal; a NUL or high-bit byte makes parsing fail. Accepted bytes are returned unchanged. A missing device-number extension yields an empty string.

The subject public-key algorithm recognizes SM2 OID `1.2.156.10197.1.301` as the algorithm or named-curve parameter. An SM2 subject bit string has zero unused bits and contains `04`, a 32-byte x coordinate, and a 32-byte y coordinate. The cache retains the two coordinates for ZA construction. Other key types retain the two identity fields without an SM2 point.

## Command-line interface

The commands are:

```text
eportskf list
eportskf identity [DEVICE]
eportskf sign [--device DEVICE] (--text TEXT | --file PATH)
```

An omitted device selects the sole enumerable device. Multiple candidates require `--device` for signing or an explicit `DEVICE` for identity. The tool prints selected device names and identity fields, or the identity failure description while leaving signing available.

Signing reads the PIN from standard input, reports verification separately, and signs either the UTF-8 command-line text or a file read in bounded chunks. Standard-input PINs are not accepted as command-line arguments. Interactive PIN entry disables local echo. Normal output goes to standard output; prompts and errors go to standard error.

Signature output includes device, algorithm, decimal length, continuous lowercase hexadecimal, and Base64. Process status is zero for success, two for command usage errors, and one for runtime failures.

## Build, installation, and release

CMake builds C11 shared and static libraries and a CLI with the public include directory and explicit platform sources. The shared library is named `eportskf`; its Windows DLL import library is `eportskf.lib`. The static library is named `eportskf_static.lib` on Windows and `libeportskf_static.a` on Linux. The install layout contains both libraries, the executable, public header, licence, and CMake package configuration. Native consumers use `find_package(eportskf CONFIG REQUIRED)` and link `eportskf::eportskf` or `eportskf::eportskf_static`.

On Windows, public function declarations use DLL import or export annotations unless `EPORTSKF_STATIC` is defined. The static CMake target supplies that definition and the required operating-system link libraries to its consumers. Direct static-link consumers define `EPORTSKF_STATIC` and supply the same system libraries.

The `eportskf` NuGet package contains `win-x64`, `win-arm64`, `linux-x64`, and `linux-arm64` CMake installation prefixes. Its `build/native/eportskf.props` file selects the Windows include and library directories from the MSBuild platform. The props do not select the linkage form.

Release archives use the name `eportskf-VERSION-OS-ARCHITECTURE` and cover Windows x64, Windows arm64, Linux x64, and Linux arm64. A Windows archive is a ZIP bundle and a Linux archive is a tar bundle. The release workflow runs when a release is created or on demand for an existing tag, builds the architecture matrix, and attaches the generated archives to that release. It then assembles the four installation prefixes into one NuGet package and publishes it to GitHub Packages. Its JavaScript actions run on Node 24. The release tag, with an optional leading `v` removed, is the package version used in archive names and in the NuGet package.
