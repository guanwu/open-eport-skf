# Protocol

## 1. Device selection and names

The PC/SC transport uses the reader name returned by `SCardListReaders` and negotiates T=0 or T=1. The HID transport accepts only USB devices with vendor ID `1A56` and product ID `DD01`.

A public device name is `[PCSC] ` followed by the reader name, or `[HID] ` followed by the platform descriptor. The Windows HID descriptor is the complete device-interface path. The Linux HID descriptor is `/dev/hidrawN`. Descriptors are non-empty and are passed to open without normalization.

An APDU response shorter than two bytes is invalid. Every other response is split into a payload and a two-byte big-endian status word before the status is interpreted.

## 2. SM2 smart card over PC/SC

### 2.1 Commands

The application is selected once when a device is opened. The container is selected once before its first certificate or signature operation.

| Operation | Command bytes | Successful response |
| --- | --- | --- |
| Select application | `80 26 00 00 00 00 0A` + ASCII `CHINAEPORT` + `00 0A` | Payload followed by `9000` |
| Select container | `80 42 00 00 00 00 0A 2F 01` + ASCII `EportRSA` + `00 02` | Payload followed by `9000` |
| Export certificate | `80 4E 01 00 00 00 04 2F 01 2E 01 00 00` | Four-byte certificate length, DER certificate, `9000` |
| Get PIN challenge | `80 50 00 00 00 00 08` | Eight challenge bytes, `9000` |
| Verify user PIN | `80 18 00 01 00 00 12 2F 01` + 16-byte encrypted PIN block | `9000` |
| Sign digest | `80 74 02 00 00 00 24 2F 01 2E 01` + 32-byte digest + `00 00` | Four-byte signature header, 64-byte signature, `9000` |

The certificate length prefix is an unsigned four-byte big-endian integer. It equals the number of DER bytes following it. The DER certificate starts with `30 82`, and its two-byte length plus four equals the certificate length. The total certificate length is at most 2048 bytes.

The four-byte signature header is not part of the signature. A value of `00 00 01 00` has been observed; the reader requires exactly 64 following bytes and does not interpret the header as signature data. The signature is `r‖s`, with unsigned 32-byte big-endian integers.

### 2.2 PIN block

The user PIN contains exactly eight bytes. Construct the block as follows:

1. Append eight zero bytes to the PIN and compute SHA1 over the resulting 16 bytes.
2. Use the first 16 SHA1 bytes as the SM4 key.
3. Form the 16-byte plaintext `08 00 ‖ challenge[8] ‖ 80 ‖ 00 00 00 00 00`.
4. Encrypt that single block with SM4 in ECB mode without padding.
5. Send the 16-byte ciphertext in the verify command.

A fresh challenge is obtained for every verification. Verification can be repeated while a device remains open.

### 2.3 Digest

The card accepts the 32-byte digest `SM3(ZA ‖ message)`. The fixed user identifier is the 16 ASCII bytes `1234567812345678`, so `ENTL` is `00 80`.

`ZA = SM3(ENTL ‖ uid ‖ a ‖ b ‖ Gx ‖ Gy ‖ x ‖ y)`, where `x` and `y` are the 32-byte coordinates of the certificate's uncompressed SM2 public point.

| Parameter | Bytes, hexadecimal |
| --- | --- |
| `a` | `FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC` |
| `b` | `28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93` |
| `Gx` | `32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7` |
| `Gy` | `BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0` |

The streaming hash is initialized, absorbs the 32-byte `ZA`, and then absorbs message chunks in order. The one-shot and streaming operations therefore submit the same digest for the same message.

## 3. RSA token over USB HID

### 3.1 HID stream framing

Each USB report is eight bytes. Byte zero is report ID zero and is not part of the payload stream. Each report carries at most seven stream bytes in report order, and the final output report is zero-padded.

A session starts with these two streams, each followed by one response frame:

| Stream | Bytes |
| --- | --- |
| Wake-up | `01 00 02 10 00` |
| Information | `01 00 02 20 00` |

A command stream is `02 ‖ length[2] ‖ APDU`, where the unsigned two-byte big-endian length is the APDU byte count. A response stream starts with a one-byte length `N`, followed by exactly `N` response bytes. The response bytes include the final status word. Padding after the declared response is ignored. A response length that produces fewer than two response bytes is invalid.

The information response contains token-specific data. The wake-up and information frames are exchanged once per open session before the first APDU. HID reads and writes have an eight-second timeout.

### 3.2 Session and certificate commands

The fixed transport PIN is the eight ASCII bytes `13572468`. It is sent immediately after the wake-up and information exchanges, before certificate selection or any other APDU. A rejected transport unlock makes the device unavailable.

| Operation | Command bytes | Successful response |
| --- | --- | --- |
| Transport unlock | `00 20 00 8A 08` + ASCII `13572468` | `9000` |
| Select certificate file | `00 A4 00 00 02 10 07` | `9000` |
| Read certificate header | `00 B0 00 00 04` | Four DER header bytes, `9000` |
| Read certificate bytes | `00 B0` + two-byte big-endian offset + one-byte requested length | Requested bytes, `9000` |
| Verify user PIN | `00 20 00 82 08` + eight PIN bytes | `9000` |
| Sign digest | `80 F2 83 00 14` + 20-byte reversed SHA1 digest | `61xx` |
| Get signature | `00 C0 00 00` + one-byte expected length | 128-byte little-endian signature, `9000` |

The certificate file is selected once per open session. The first read returns `30 82` and a two-byte big-endian DER content length. The total certificate length is that value plus four, must be greater than four, and must not exceed 2048 bytes. Certificate data is then read from offset zero in chunks of at most 128 bytes until exactly that total has been collected.

### 3.3 PIN and signature

The user PIN is the same eight bytes supplied to the public verification call. No challenge or encryption is used on this transport.

The host computes SHA1 over the complete message, reverses the 20 digest bytes, and sends them in the sign command. A signing response with status `61xx` has `xx` bytes pending; `xx = 00` requests 128 bytes. The following `GET RESPONSE` uses `xx` as its expected length. Exactly 128 signature bytes are required. Reversing those bytes produces the standard big-endian RSA-1024 signature over a PKCS#1 v1.5 SHA1 `DigestInfo`.

## 4. Status handling

| Status or condition | Meaning |
| --- | --- |
| `9000` | Success |
| `63xx` during user-PIN verification | PIN rejected |
| `6982` during verification or signing | Verification required |
| `61xx` after RSA signing | Retrieve the pending signature with `GET RESPONSE` |
| Any non-`9000` status during transport unlock | Device unavailable |
| Card removal, disconnect, reset, timeout, or an unusable device handle | Device unavailable and local PIN-session state cleared |
| Any other status or malformed response | Failure |

A successful PIN verification sets local authorization for that open device. Closing the device or observing a reset clears it. A `6982` signing response also clears it. Starting or updating a signature does not require authorization; finishing does.

## 5. Certificate identity

The certificate is a bounded DER `Certificate` containing a `TBSCertificate`. The reader accepts definite short, `81`, and `82` length forms and rejects truncated values, indefinite lengths, trailing certificate bytes, and certificates larger than 2048 bytes.

The certificate ID is the lowercase hexadecimal representation of the serial-number INTEGER content bytes. The device ID is read from extension `1.3.6.1.4.1.5315.100.5.9`.

The device-number extension contains an OCTET STRING of at most 512 bytes whose content is one text TLV tagged as UTF8String, PrintableString or IA5String. A leading two-ASCII-digit `NN-` prefix is removed. Every remaining byte must be in the range `01` through `7F` hexadecimal. A NUL or a byte with its high bit set makes certificate parsing fail. The accepted bytes are returned unchanged. A missing device-number extension yields an empty string.

The SM2 public-key OID is `1.2.156.10197.1.301`. It can occur in the `AlgorithmIdentifier` of `subjectPublicKeyInfo`, including as the named-curve parameter. For an SM2 key, the subject bit string has zero unused bits and contains exactly `04 ‖ x[32] ‖ y[32]`. Other public-key types still yield the identity fields and do not yield an SM2 point.

## 6. Public data limits

| Data | Limit or representation |
| --- | --- |
| Certificate | DER, at most 2048 bytes |
| Extension value | At most 512 encoded bytes |
| User PIN | Exactly eight bytes before the terminating NUL in a C caller |
| SM2 signature | 64 bytes, `r‖s` |
| RSA-SHA1 signature | 128 bytes, big-endian PKCS#1 v1.5 signature |
| Message | Arbitrary length; incremental hashing retains only its fixed state and at most one partial hash block |
