# Requirements

## Purpose

The system gives host software a library and a command-line tool for China ePort smart cards and ePort USB tokens. It reads the card certificate identity, verifies the user PIN, and signs data with the private key on the card. Private-key operations take place on the card; the host parses the certificate, forms the PIN block and the digests, and exchanges commands with the card.

## Supported media

| Medium | Access | Signature |
| --- | --- | --- |
| ePort smart card | Contact smart-card reader | SM2 over an SM3 digest; 64 bytes, `r‖s` |
| ePort USB token | USB HID | RSA-1024 over SHA1; PKCS#1 v1.5; 128 bytes |

The medium determines the algorithm; the algorithm is not selected by the caller.

## Operations

- Enumerate every medium that is present and readable, returning a device name and the two identity fields for each. A medium that cannot be opened or whose certificate cannot be read is skipped without failing the call; no medium yields an empty list, not an error.
- Open the device that enumeration named, and close it again.
- Read the identity of an open device without a PIN. A failed identity read leaves the device open and usable for PIN verification and signing.
- Verify the user PIN so that the device accepts a signature.
- Sign a whole buffer already in memory and report the algorithm and the signature bytes.
- Sign a message of any size that arrives in pieces: start a signature, feed chunks in order, finish to obtain the signature, or abandon the signature before finishing. The message is absorbed chunk by chunk and only a bounded part of it is ever held, so its length has no limit. For the same message bytes, the one-shot call and the streaming calls produce the same signature.

## Device names

An enumeration result names a device in a form the open call accepts unchanged, so a name round-trips from enumeration to open. An unknown or malformed name reports the device as unavailable; a missing name reports an unusable argument.

## Identity

| Field | Meaning |
| --- | --- |
| `cert_id` | Certificate serial number, lowercase hexadecimal |
| `device_id` | NUL-free seven-bit ASCII text of the device-number extension, OID 1.3.6.1.4.1.5315.100.5.9 |

The device-number extension may be a UTF8String, PrintableString or IA5String. A leading two-ASCII-digit `NN-` prefix is removed, after which every byte must be in the range `01` through `7F` hexadecimal. Any other byte makes certificate parsing fail. A missing device-number extension yields an empty string. A certificate whose public key is SM2 also yields the uncompressed public point for digest construction; a certificate with another key type still yields the two identity fields and its key bits are not used.

## Signing session rules

- The PIN is exactly eight bytes, NUL-terminated. Any other length reports an unusable argument and no command reaches the card.
- A signature completes only while a PIN session is active; otherwise it reports that verification is required.
- A PIN session ends when the device is closed or the card resets. Verification may be repeated, including between signing updates.
- One open device carries at most one unfinished signature at a time, and stays open until that signature ends or is abandoned.
- Finishing a signature consumes it whether it succeeds or fails; abandoning it releases it without a signature. An empty update is accepted.
- The USB token is unlocked with a fixed transport PIN before its first command; a refused unlock reports the device as unavailable.
- The SM2 digest mixes the fixed user identifier and the public key into `ZA` before the message, and the USB token path moves the digest and the signature bytes in reverse order. Both follow the card side's convention so that the card accepts the input and the signature verifies.

## Results

Every call ends with one outcome and one fixed description of it.

| Outcome | Reported when |
| --- | --- |
| Success | The call succeeded |
| Unusable argument | An argument cannot be used, such as a PIN of the wrong length |
| Device unavailable | The card is absent, removed, unresponsive, unopenable, or not the named device |
| PIN rejected | The card rejected the PIN |
| Verification required | A signature was requested without an active PIN session |
| Failure | The card returned any other error or an unrecognised status |

## Limits

- Certificate: DER, at most 2048 bytes. The returned length equals the DER header's declared length.
- Certificate extension value: at most 512 bytes before decoding.
- Signature: at most 128 bytes; RSA 128 bytes, SM2 64 bytes.
- Message: no size limit. The streaming path holds only a bounded part of the message, whatever its length.
- PIN: exactly 8 bytes.
- A certificate shorter than 2048 bytes is returned at its actual length.

## Implementation

- The library is written in C11 and exposes a C ABI that other languages can call directly.
- The library uses only the C standard library and the operating-system interfaces of each supported platform.
- No third-party library is used, including for cryptography, text conversion and transport.

## Platforms

- Windows and Linux: Windows on x64 and arm64; Linux on x64 and arm64.
- Windows uses the system smart-card service and the system HID and device-enumeration interfaces.
- Linux uses the system smart-card service; USB HID access goes through `/dev/hidrawN`, which the calling user needs read and write rights on.
- Any operation that reaches hardware needs the card and a reader or token.

## Command-line tool

- List every present device with its identity, and show the identity of a single device.
- Sign a piece of text supplied on the command line, and sign the contents of a file of any size by reading it in pieces rather than holding it whole.
- Let the user choose which device to use when several are present.
- Read the PIN from standard input for every operation that signs.
- Report what it did: the device, the identity fields or the reason they are unavailable, whether the PIN passed, and the signature with its algorithm, length and bytes in a readable form and in a form meant to be copied into other tools.
- Report success, a usage error and a runtime failure distinguishably.

## Documentation

- Design documents are kept directly in the project root.
- `README.md` holds the quick start: what the system is, the environment it needs, how it is built, and the first commands or calls that produce a signature.
- `PROTOCOL.md` holds the protocol details: the command sequences each card family accepts, the digest and PIN block it expects, the framing of the link, certificate parsing, and the data formats exchanged with the card.
- `DESIGN.md` holds the system architecture and the detailed design: the parts of the system, their responsibilities and contracts, and the flows that join them.

## Releases and licence

- A release publishes one bundle per supported platform and architecture, attached to the release.
- Each bundle contains shared and static libraries and CMake targets for both linkage forms.
- A single NuGet package named `eportskf` contains all four platform prefixes and is published to GitHub Packages after every platform build succeeds.
- Builds run only in GitHub Actions, which produces the complete release matrix.
- JavaScript actions in the release workflow use Node 24.
- The release tag, with an optional leading `v` removed, is the package version.
- The licence is AGPL-3.0-only. The copyright holder is Jiaowei <wei.jiao@guanwu.com>.
