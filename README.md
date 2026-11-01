# ClearGuard Definitions

Malware signature database for ClearGuard (澄盾).

## Data

| File | Size | Contents |
|---|---|---|
| `data/sha256-bloom.bin` | ~6.6 MB | Bloom filter containing ~1.18M known-malicious SHA-256 file hashes |

The bloom filter uses 2200000 bits (53.7% fill) with an expected false-positive rate of ~3e-9.
Membership test: given a file's SHA-256, if the bloom filter says "yes" it is very likely malicious;
if it says "no" the file has never been reported to the aggregated sources.

## Sources

The database is built from public open-source threat-intel feeds:

| Source | License | What we take |
|---|---|---|
| [ESET malware-ioc](https://github.com/ESET/malware-ioc) | BSD-2-Clause | Per-investigation SHA-256 lists |
| [MalwareBazaar](https://bazaar.abuse.ch/) | abuse.ch ToS | Crowdsourced malware sample hashes |
| [ThreatFox](https://threatfox.abuse.ch/) | abuse.ch ToS | IOC feed with hash entries |
| [ClamAV](https://www.clamav.net/) | Public domain / GPL-2.0 | Hash-based signatures (.hdb/.hsb) |
| [SaneSecurity](https://sanesecurity.com/) | Various | Additional hash feeds |

Initial bloom filter is re-hosted from [MaintainTeam/HypatiaDatabases](https://github.com/MaintainTeam/HypatiaDatabases)
(AGPL-3.0) with attribution. We are building our own generation pipeline on top of these sources.

## Update flow

1. GitHub Actions weekly (or manual) regenerates the bloom filter from upstream sources.
2. The generated `.bin` is signed with a GPG key (private key stored in GitHub Secrets, not in repo).
3. The APK downloads `manifest.json` → verifies signature → downloads new bloom filter → atomically replaces the cached one.
4. If signature verification fails or download fails, the APK keeps the last known-good database.

## Verification

- `data/sha256-bloom.bin.sig` is a GPG detached signature of the bloom filter.
- `trusted-signing.key` is the public GPG key used to verify signatures.
- The APK embeds a SHA-256 hash of the trusted public key for boot-time identity verification.

## License

This repository contains aggregated data from multiple sources. See individual source links above for their terms.
The bloom filter data is re-hosted from HypatiaDatabases (AGPL-3.0). Original generation scripts and manifest files
in this repo are released under MIT.
