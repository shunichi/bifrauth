# Project Naming: BifrAuth

> **Scope of this document.** This document explains the project's *name*, branding,
> and naming conventions. It is not a design specification. Where anything here
> conflicts with the authoritative design document
> ([`iphone-faceid-linux-pam-design.md`](./iphone-faceid-linux-pam-design.md)),
> the design document governs. In particular, the design document defines the
> **current initial scope** (iPhone Face ID over a local LAN); the broader,
> platform-independent framing below describes intended *direction*, not what the
> initial version implements.

## Project Name

**BifrAuth**

Repository and package names use lowercase:

* `bifrauth`
* `bifrauthd`
* `bifrauthctl`
* `pam_bifrauth.so`

For documentation, the preferred branding is **BifrAuth** (camel case).

---

## Name Origin

The name is derived from **Bifröst**, the bridge in Norse mythology that connects different worlds.

This project acts as a secure bridge between:

* Linux authentication (PAM / polkit)
* A trusted mobile device
* Secure Enclave–backed biometric authentication

Rather than authenticating users directly, BifrAuth bridges authentication requests from Linux to a trusted cryptographic device.

---

## Meaning

The name intentionally combines:

* **Bifr** — inspired by *Bifröst*, representing a secure bridge.
* **Auth** — authentication.

The bridge metaphor represents trust delegation rather than password replacement.

Linux asks a trusted device:

> "Please cryptographically approve this authentication request."

The mobile device verifies the user using Face ID (or another platform-specific biometric method), signs a challenge using a hardware-protected private key, and Linux verifies that signature.

---

## Pronunciation

Preferred pronunciation:

**BIF-rawth**

The project should consistently document this pronunciation to avoid ambiguity.

Example:

> BifrAuth (pronounced "BIF-rawth")

---

## Design Philosophy

BifrAuth is **not** intended to be:

* *merely* an iPhone utility
* a Face ID clone
* a password manager
* a biometric library

Instead, it is a general authentication bridge.

The **authenticator side** is intended not to stay tied to iOS / Face ID, so that
additional authenticators can be added over time. Note that the **current
protocol is not platform-neutral**: its signed challenge includes Linux/PAM-specific
context (`pam_service`, `pam_tty`, `pam_rhost`, PAM-service-derived purpose), and the
relying party is Linux/PAM. Platform-independence is a goal for the *authenticator*,
not a property of today's protocol or relying-party context. Possible **future**
authenticators include:

* iPhone (Face ID)
* Android (BiometricPrompt + StrongBox)
* FIDO2 authenticators
* TPM-backed authenticators
* future hardware security modules

> **Alignment with the current design.** The authoritative design's initial scope
> is deliberately narrow: a single Linux host and a single **iPhone** using Face ID,
> over the same LAN, with the iPhone app in the foreground (see the design
> document's "推奨初期スコープ" and non-goals). The multi-platform authenticators
> listed above are a future direction, enabled by keeping the **authenticator
> boundary** extensible and independent of a specific biometric platform — not by
> the current protocol being platform-neutral (it is not; see above). They are
> **not** part of the initial version. Treat this section as branding intent, not
> as an implemented capability.

---

## Naming Conventions

The following names align with the components defined in the design document
(root verifier daemon, unprivileged transport helper, PAM module) and with the
approved implementation plan ([`implementation-plan.md`](./implementation-plan.md)).

| Role | Name |
|---|---|
| Project / brand | **BifrAuth** |
| Root verifier daemon | `bifrauthd` |
| Unprivileged transport helper | `bifrauth-transport` |
| Admin CLI | `bifrauthctl` |
| PAM module | `pam_bifrauth.so` |
| Protocol (optional) | **BifrAuth Protocol** |
| iOS application | **BifrAuth Mobile** (iOS) |
| Android application (future) | **BifrAuth Mobile** (Android) |

> The `bifrauth-transport` helper is part of the design's trust model (an
> unprivileged, user-session component that carries challenges but is never
> trusted to decide authentication). It was not listed in the original naming
> note and is added here so the naming set matches the design's component set.
>
> The PAM module name intentionally drops any platform/biometric term
> (`pam_bifrauth.so`, not `pam_iphone_faceid.so`), consistent with the
> platform-neutral branding goal.

---

## Branding Goals

The project name was selected with the following goals:

* unique enough to be easily searchable
* not tied to Apple
* not tied to Face ID
* not tied to PAM
* suitable for future expansion
* memorable to developers
* inspired by mythology without directly using the heavily reused name "Bifrost"

These are branding goals for the name itself. The **initial implementation** is
nonetheless specific to PAM/polkit on Linux and to an iPhone Face ID
authenticator, per the design document; "not tied to Apple / Face ID / PAM"
describes the intended trajectory of the protocol, not the initial scope.

---

## Project Identity

One-sentence description:

> **BifrAuth is a mobile-backed authentication bridge for Linux that uses hardware-protected cryptographic keys instead of passwords.**

Long description:

> BifrAuth allows Linux authentication systems such as PAM and polkit to delegate authentication to a trusted mobile device. The mobile device authenticates the user locally using platform biometrics and securely signs a cryptographic challenge with a hardware-protected private key. Linux verifies the signature and completes the authentication without transmitting the account password to the mobile device or through BifrAuth, and without using the account password in a successful BifrAuth flow.

> Note: the design document keeps the Linux account / 1Password password
> available as a recovery path (fallback), so BifrAuth does **not** remove or
> replace those passwords. "Instead of passwords" refers to the normal
> authentication flow, not to eliminating password storage or the fallback.

---

## Core Concept

The project should always be described as a **cryptographic authentication bridge**, not as a remote biometric authentication system.

The biometric subsystem (Face ID, Touch ID, Android Biometrics, etc.) is only responsible for authorizing access to a hardware-protected private key.

Trust is established through public-key cryptography, challenge-response authentication, and secure device pairing—not through transmitting biometric results.

This matches the design document's core security principle: never send a "Face ID
succeeded" boolean over the network; use Face ID only to gate a Secure Enclave
signing operation, and verify the signature on the Linux side.
