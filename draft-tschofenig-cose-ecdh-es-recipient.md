---
title: Strengthening COSE ECDH-ES Against Downgrading Attacks
abbrev: COSE ECDH-ES Recipient Structure
docname: draft-tschofenig-cose-ecdh-es-recipient-latest
category: std
consensus: true
submissiontype: IETF

ipr: trust200902
area: "Security"
workgroup: "CBOR Object Signing and Encryption"
keyword: Internet-Draft

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: o-*+
  compact: yes
  subcompact: yes
  consensus: false

author:
  -
    name: Hannes Tschofenig
    organization: University of Applied Sciences Bonn-Rhein-Sieg
    abbrev: H-BRS
    email: Hannes.Tschofenig@gmx.net
    country: Germany

  -
    name: Russ Housley
    organization: Vigil Security, LLC
    abbrev: Vigil Security
    email: housley@vigilsec.com
    country: United States
  -
    name: Ken Takayama
    organization: SECOM CO., LTD.
    email: ken.takayama.ietf@gmail.com
    country: Japan
  -
    name: Laurence Lundblade
    organization: Security Theory LLC
    email: lgl@securitytheory.com
    country: United States

normative:
  RFC9052:
  RFC9053:
  RFC8949:

informative:
  RFC9709:
  I-D.ietf-cose-hpke:
  I-D.ietf-suit-firmware-encryption:

--- abstract

This document updates use of the COSE Ephemeral-Static Diffie–Hellman (ECDH‑ES) algorithms by replacing the COSE_KDF_Context with the HPKE-inspired Recipient_structure when deriving keys for COSE recipients. This binds recipient‑protected header parameters and the next‑layer algorithm into the key derivation, mitigating downgrade and algorithm‑substitution attacks that can arise from unauthenticated recipient metadata.

The construction reuses the Recipient_structure defined for COSE‑HPKE, changing only the context string. New COSE algorithm identifiers are registered for interoperability.

--- middle

# Introduction

[RFC9052] and [RFC9053] define COSE and the use of ECDH‑ES with HKDF and AES Key Wrap. The key material for content encryption (CEK) or key‑encryption keys (KEK) is derived via a KDF context that does not cover all recipient metadata. As discussed on the COSE mailing list and in work on CMS [RFC9709], unauthenticated recipient metadata can enable algorithm‑substitution and downgrade attacks.

COSE‑HPKE [I-D.ietf-cose-hpke] introduced a Recipient_structure that is deterministically encoded and used as the HPKE `info` parameter to bind the next‑layer algorithm identifier and recipient‑protected headers into the key derivation. This document specifies an analogous change for COSE ECDH‑ES: when an ECDH‑ES algorithm is used in a COSE_recipient, the COSE_KDF_Context is replaced with a Recipient_structure and the derived key is computed accordingly.

This specification is intended for use cases including firmware encryption, see [I-D.ietf-suit-firmware-encryption], where ECDH‑ES is  used.

# Terminology

{::boilerplate bcp14-tagged}

CBOR and COSE terminology are as in [RFC9052] and [RFC9053].

# Overview

This document defines the ECDH‑ES Recipient_structure, a deterministic CBOR structure modeled after the HPKE Recipient_structure. Implementations use it in place of COSE_KDF_Context for ECDH‑ES recipients. The construction provides integrity for recipient‑protected headers and cryptographically binds the next‑layer algorithm to the derived key. It is applicable both when ECDH‑ES derives a CEK directly (ECDH‑ES+HKDF-*) and when ECDH‑ES derives a KEK for AES‑KW (ECDH‑ES+A*KW).

To avoid interoperability failures with existing deployments, this document registers new COSE algorithm identifiers that signal use of this construction.

# ECDH‑ES Recipient_structure {#structure}

The structure is identical to the one in COSE‑HPKE except for the `context` string. The deterministic CBOR encoding defined in [RFC8949] Section 4.2.1 MUST be used.

~~~
ECDH-ES-Recipient-structure = [
  context: "ECDH-ES Recipient",
  next_layer_alg: int / tstr,
  recipient_protected_header: empty_or_serialize_map,
  recipient_extra_info: bstr
]
~~~

* context contains the fixed text string "ECDH-ES Recipient" to distinguish this structure from the COSE-HPKE-defined recipient_structure
* next_layer_alg is the algorithm identifier for the next lower COSE layer (the content‑encryption algorithm used with the CEK or the key‑wrap algorithm). This value MUST equal the `alg` parameter in that lower layer.
* recipient_protected_header is the deterministic CBOR encoding of the protected header parameters of the COSE_recipient.
* recipient_extra_info allows applications to include additional context into key derivation (e.g., identifiers). If unused, set to the zero‑length byte string.

# Processing Rules

When an ECDH‑ES algorithm defined in this document is used in a COSE_recipient, the following rules apply.

## Inputs

* Let `Z` be the ECDH shared secret computed per [RFC9053].
* Let `salt` be the value of the COSE header parameter `salt` (if present) or absent otherwise, as defined by [RFC9053].
* Let `RS` be the deterministic CBOR encoding of the ECDH‑ES Recipient_structure defined in {{structure}}.

## Deriving a CEK {#deriving-cek}

Use HKDF (with the hash function indicated by the algorithm) as follows:

* IKM = `Z`.
* salt = the `salt` header parameter value if present; otherwise absent (per HKDF).
* info = `RS`.
* L = length of the CEK required by the next‑layer AEAD algorithm.

Output is the CEK.

This replaces the use of COSE_KDF_Context. The derived key will differ from [RFC9053] for the same inputs.

## Deriving a KEK

For algorithms that wrap a randomly generated CEK using AES‑KW, derive the KEK via HKDF as in {{deriving-cek}} but with L equal to the AES‑KW key length (128, 192, or 256 bits). Use the resulting key as the KEK for AES‑KW.

## Recipient Construction and Verification

* The `alg` parameter for the COSE_recipient MUST be one of the algorithms defined in {{algorithm-ids}}.
* If the `alg` parameter is present at the content‑encryption layer (layer 0), it MUST be the algorithm named by `next_layer_alg`.
* The value of `recipient_protected_header` in `RS` MUST exactly match the recipient’s protected header in the message.
* Applications SHOULD include a `kid` identifying the static recipient public key in the protected headers of the recipient; this ensures it is covered by `RS`. Parameters other than the `kid` may be used to identify the static recipient public key.

# New COSE Algorithm Identifiers {#algorithm-ids}

This document registers new COSE algorithms that mirror the existing ECDH‑ES algorithms but signal the use of the Recipient_structure in key derivation. The semantics and key types are otherwise unchanged from [RFC9053].

| Name | Value | Description | Key Type | Hash | Capabilities | Recommended |
|-----|------|-------------|----------|------|--------------|-------------|
| ECDH-ES-RS+HKDF-256 | TBD1 | ECDH‑ES with HKDF‑SHA‑256 using Recipient_structure | EC2 / OKP | SHA‑256 | derive | Yes |
| ECDH-ES-RS+HKDF-512 | TBD2 | ECDH‑ES with HKDF‑SHA‑512 using Recipient_structure | EC2 / OKP | SHA‑512 | derive | No |
| ECDH-ES-RS+A128KW | TBD3 | ECDH‑ES deriving 128‑bit KEK via HKDF‑SHA‑256 and using Recipient_structure | EC2 / OKP | SHA‑256 | derive | Yes |
| ECDH-ES-RS+A192KW | TBD4 | ECDH‑ES deriving 192‑bit KEK via HKDF‑SHA‑256 and using Recipient_structure | EC2 / OKP | SHA‑256 | derive | No |
| ECDH-ES-RS+A256KW | TBD5 | ECDH‑ES deriving 256‑bit KEK via HKDF‑SHA‑256 and using Recipient_structure | EC2 / OKP | SHA‑256 | derive | Yes |

Rationale:* Aligns with existing COSE registrations and keeps HKDF hash choices consistent with [RFC9053]. If a future need arises, variants using HKDF‑SHA‑512 for AES‑KW MAY be registered.

# CDDL

The following CDDL augments [RFC9052] and [RFC9053].

~~~
empty_or_serialize_map = bstr .cbor map / bstr .size 0

ECDH-ES-Recipient-structure = [
  context: "ECDH-ES Recipient",
  next_layer_alg: int / tstr,
  recipient_protected_header: empty_or_serialize_map,
  recipient_extra_info: bstr
]
~~~

# Backward Compatibility

The construction in this document intentionally changes the KDF `info` input compared to [RFC9053], and therefore produces different keys. Messages created using the algorithms in Section 6 are not interoperable with messages produced using the legacy ECDH‑ES algorithms. This is by design and prevents silent downgrade.

Implementations that need to accept legacy messages MAY support both sets of algorithms. Senders SHOULD prefer the new `-RS` algorithms when a recipient advertises support.

# Security Considerations

This specification provides two main security benefits:

* Header Binding: By incorporating the deterministically encoded `recipient_protected_header` into the HKDF `info`, protected header parameters (including `kid` and any algorithm signals) are cryptographically bound to the derived key. An attacker cannot flip recipient‑protected parameters without causing decryption failure.

* Algorithm Binding: Binding `next_layer_alg` prevents algorithm‑substitution and downgrade of the content‑encryption or key‑wrap algorithm. This addresses attack classes discussed in [RFC9709] and analogous to LAMPS findings applied to other formats.

Applications SHOULD continue to place all security‑critical recipient parameters into the protected header. Applications SHOULD NOT place large or bulk external data into `recipient_extra_info`; use `external_aad` at layer 0 if such data needs integrity protection.

# IANA Considerations

IANA is requested to register the algorithms in {{algorithm-ids}} in the "COSE Algorithms" registry under the following template:

* Name: as in {{algorithm-ids}}
* Value: TBD (to be assigned by IANA)
* Description: as in {{algorithm-ids}}
* Change Controller: IESG
* Reference: This document
* Recommended: as in {{algorithm-ids}}
* Capabilities: [derive]
* Key Type: EC2, OKP

No new header parameters are defined by this document.

# Example

This section provides an abbreviated example for `ECDH-ES-RS+HKDF-256` protecting a single recipient. Hex strings are illustrative.

~~~
RS := [
  "ECDH-ES Recipient",
  1,                                     ; A128GCM at layer 0
  << {1: -100, 4: h'11aa22bb'} >>,        ; { alg: ECDH-ES-RS+HKDF-256, kid: ... }
  h''
]

IKM = Z
salt = (absent)
info = encode_deterministic(RS)
CEK  = HKDF-Expand(HKDF-Extract(salt, IKM), info, 16)
~~~

--- back

# Acknowledgments
{:numbered="false"}

Thanks to Ilari Liusvaara and the COSE working group for discussions and to the SUIT and TEEP working group participants for motivating use cases.
