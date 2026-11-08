# Sovereign AI Training Data Marketplace & Multi-Layer Anti-Exfiltration Guard

## 1. Executive Summary

QuorumRAG provides an **Opt-In Sovereign AI Training Data Marketplace** that enables subscribers to package and monetize their private, off-internet domain expertise as sanitized **SFT (Supervised Fine-Tuning)** and **DPO (Direct Preference Optimization)** reasoning trajectories while enforcing:

1. **Strictly Disabled by Default (`opt_in_enabled = false`)**: All marketplace harvesting, catalog previewing, bounty matching, and `.jsonl` download routes fail closed with `403 Forbidden` unless the local node owner explicitly enables the Marketplace in Settings and approves a batch.
2. **`["US"]`-Only Default Sovereign Lock (`US_ONLY_DOJ_28_CFR_PART_202`)**: Out of the box, only buyers incorporated and physically operating on pinned corporate networks inside `"US"` (or optionally Five Eyes `["US", "CA", "GB", "AU", "NZ"]` if enabled by the subscriber) are permitted.
3. **5-Layer Core Sovereign Guard + Domestic U.S. Evasion Hardening (`SovereignJurisdictionGuard`)**: Blocks both direct foreign adversary traffic (`CN`, `HK`, `MO`, `RU`, `IR`, `KP`, `BY`, `CU`, `VE`) and domestic U.S. evasion via U.S. Points of Presence (PoPs) of Chinese cloud/telecom providers, rented anonymous U.S. VPS/residential proxies, or foreign-controlled Delaware shell LLCs (*Covered Persons* under the U.S. Department of Justice Bulk Sensitive Data Rule, **28 CFR Part 202**).

---

## 2. Five-Layer Sovereign Anti-Exfiltration Guard + Domestic-Evasion Controls

Implemented in [`crates/quorum-coordinator/src/marketplace_engine.rs`](../crates/quorum-coordinator/src/marketplace_engine.rs) and [`crates/quorum-contract/src/marketplace.rs`](../crates/quorum-contract/src/marketplace.rs):

### Layer 1: Zero Raw Documents, Three-Engine Airlock De-Identification & Semantic Trade-Secret Filter
- **Never Exports Raw Files**: Raw PDFs, Word documents, spreadsheets, and local file paths are never sold or transmitted.
- **Three-Engine Airlock De-Identification (`MarketplaceSanitizer::scrub_text`)**:
  - **Tier 1 (Microsoft Presidio)**: Rule, regex, and lemma-based pattern recognition (`ContextEnhancer`) for standard syntactic entities (SSNs, phone numbers, emails, IP addresses, credit cards).
  - **Tier 2 (GLiNER `urchade/gliner_multi_pii-v1`)**: Bi-encoder span transformer for open-vocabulary named entity recognition covering clinical conditions, medications, hospital systems, and identities (`[REDACTED:GLINER_*]`).
  - **Tier 3 (VaultGemma-1B / RedactX-v3 Policy Engine)**: Differential Privacy $(\epsilon, \delta)$ de-identification, boundary quasi-identifier detection (`scan_quasi_identifiers` -> `[REDACTED:VAULTGEMMA_QUASI_ID]`), and abstractive takeaway synthesis for intermediate RLM steps (`synthesize_abstracted_takeaway`) to prevent verbatim code or sensitive file leakage.
  - **Local Path & Contact Scrubbers**: Eliminates Windows drive paths (`C:\...`, `D:\...`), UNC paths, POSIX paths (`/Users/...`, `/home/...`), and subscriber-specific organization aliases (`[REDACTED:LOCAL_PATH]`, `[REDACTED:SUBSCRIBER]`).
- **Semantic Trade-Secret & Proprietary Code Filter (`contains_trade_secret_or_proprietary_code`)**: Deterministically blocks any trajectory containing:
  - Fenced or syntactic source code blocks exceeding `15` lines,
  - Internal RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or IPv6 ULA (`fc00::/7`) network topology addresses,
  - Internal corporate FQDNs (`.internal`, `.corp`, `.lan`, `.localdomain`, `.priv`),
  - PEM/OpenSSH private keys, cloud tokens (`AKIA...`, `ghp_...`, `sk-...`), or high-entropy secrets (Shannon entropy `> 4.70 bits/char`).
- **100% Verbatim Citation Grounding (`grounding_score_bps == 10_000`)**: Every citation must pass `slice_text.contains(verbatim_quote)` and every trajectory must contain `>= 64` tokens before signing with the node's `Ed25519` private key.
- **Parent-Window Trajectory Harvesting (`DatasetBuilder`)**: Extracts parent document byte windows (0..10,000 bytes) and anchors verbatim citation quotes from stored chunks in `crates/quorum-storage/src/dataset_builder.rs`.
- **Autonomous Bounty Runner (`BountyRunner`)**: Autonomous bounty evaluation with zero-touch safety gating in `crates/quorum-coordinator/src/bounty_runner.rs`, matching active bounties against sovereign policies and airlock sanitization.

### Layer 2: Foreign GeoIP + Chinese Cloud U.S.-PoP & Anonymous VPS/VPN ASN Firewall
- **Direct Foreign Adversary CIDR & GeoIP Block**: Rejects connections and proxy hops (`X-Forwarded-For`, `CF-Connecting-IP`, `X-Real-IP`) originating from `CN`, `HK`, `MO`, `RU`, `IR`, `KP`, `BY`, `CU`, `VE` (`FOREIGN_ADVERSARY_IPV4_CIDRS` and `BLOCKED_ADVERSARY_JURISDICTIONS`).
- **Domestic U.S.-PoP & Anonymous VPS/VPN ASN Blocklist (`HIGH_RISK_DATACENTER_PROXY_ASNS`)**: Rejects requests from U.S. Points of Presence of Chinese clouds/telecoms and unverified VPS/VPN providers frequently rented by scrapers inside the United States:
  - `AS4134`, `AS4809` (Chinanet / China Telecom / CTAmericas)
  - `AS4837` (China Unicom), `AS9808` (China Mobile), `AS4538` (CERNET)
  - `AS37963`, `AS45102` (Alibaba Cloud domestic, international & U.S. PoPs)
  - `AS45090`, `AS132203` (Tencent Cloud domestic, international & U.S. PoPs)
  - `AS55990`, `AS136907` (Huawei Cloud), `AS38365` (Baidu)
  - `AS14061` (DigitalOcean), `AS20473` (Vultr / Choopa), `AS63949` (Linode / Akamai Connected Cloud), `AS16276` (OVHcloud), `AS24940` (Hetzner), `AS9009` (M247 VPN backbone), `AS60068` (Datacamp / CDN77 VPN backbone).

### Layer 3: Ed25519 `BuyerJurisdictionCertificate` + FOCI/UBO & DOJ 28 CFR Part 202 Attestation
- Every buyer must present a `BuyerJurisdictionCertificate` signed by the Marketplace Licensing Authority (`Ed25519`) attesting:
  - `incorporation_country_iso`: Must match `allowed_jurisdictions` (default `["US"]`) and never match `BLOCKED_ADVERSARY_JURISDICTIONS`.
  - `lei_or_duns_id`: Verified Legal Entity Identifier (LEI), DUNS number, or SAM.gov CAGE code.
  - `foci_ubo_verified_clean == true`: Attests `0%` (`< 10%` threshold) voting shares or board control by parent entities in prohibited jurisdictions.
  - `doj_part202_non_covered_person == true`: Attests compliance with the U.S. DOJ Bulk Sensitive Data Rule (**28 CFR Part 202** Non-Covered Person).
  - `non_redistribution_covenant_accepted == true`: Binding covenant prohibiting resale, re-export, or overseas cluster mirroring.

### Layer 4: Certificate-Pinned Corporate Egress CIDRs & Hardware TPM 2.0 Cluster Binding
- **Corporate Egress CIDR Pinning (`authorized_egress_cidrs`)**: A U.S. IP address alone is never trusted. Both `caller_ip` and every proxy hop in `X-Forwarded-For` / `CF-Connecting-IP` / `X-Real-IP` must match the static corporate IPv4/IPv6 CIDR ranges signed inside the buyer's `BuyerJurisdictionCertificate` (`cidr_contains_ip`, including IPv4-mapped IPv6 canonicalization).
- **Hardware TPM 2.0 / HSM Key Binding (`bound_tpm_pubkey_blake3`)**: `/api/v1/marketplace/unlock` and `/api/v1/marketplace/download` verify in constant time (`subtle::ConstantTimeEq`) that `X-Quorum-TPM-Pubkey-Blake3` matches `cert.bound_tpm_pubkey_blake3` so a valid token cannot be forwarded to an overseas machine.

### Layer 5: Anti-Scraping Tiered Previews, Commit-and-Reveal Escrow & Per-Buyer Canary Watermarking
- **Tier 1 Unauthenticated Preview (`to_unauthenticated_preview`)**: Returns aggregate record/token counts and `merkle_root_blake3` **only** (`canary_sample: []`).
- **Tier 2 Cert-Authenticated Canary Preview (`to_authenticated_watermarked_preview`)**: Requires a valid `BuyerJurisdictionCertificate`, enforces an hourly rate limit per buyer and subnet (`429 Too Many Requests`), and returns `<= 5` canary records watermarked with `blake3::keyed_hash(node_seed, buyer_id || "preview_canary" || record_hash)`.
- **Commit-and-Reveal Cryptographic Escrow (`EscrowReceiptToken`)**: Verified in constant time via a 256-bit keyed BLAKE3 MAC before decrypting the batch and streaming `.jsonl` records watermarked with `buyer_id || "full_unlock"`.

---

## 3. REST API Reference (`crates/quorum-daemon/src/handlers/marketplace.rs`)

| Method & Path | Access | Description |
|---|---|---|
| `GET /api/v1/marketplace/status` | Local Node | Returns `opt_in_enabled` (default `false`), `allowed_jurisdictions` (default `["US"]`), `sovereign_lock_mode`, `latest_manifest`, `latest_ledger`, and active bounties. |
| `POST /api/v1/marketplace/opt-in` | Local Node | Toggles `opt_in_enabled`, `five_eyes_enabled`, `allowed_jurisdictions` (rejects adversary countries with `403`), and floor pricing. |
| `POST /api/v1/marketplace/harvest` | Opt-In Required | Runs `MarketplaceSanitizer` + Trade-Secret Filter + 100% citation grounding check, encrypts the staged `.jsonl` batch at rest, and signs a `DataCatalogManifest`. |
| `POST /api/v1/marketplace/approve-batch` | Opt-In Required | Marks a staged batch as HITL-approved & sealed (`approved = 1`) and updates `ContributionLedger`. |
| `GET/POST /api/v1/marketplace/preview` | Public / Cert-Auth | Unauthenticated returns metadata + `merkle_root_blake3` only (`canary_sample: []`); cert-authenticated returns `<= 5` rate-limited, watermarked canary lines. |
| `POST /api/v1/marketplace/unlock` | Sovereign Guard | Validates all 5 layers + domestic-evasion checks and issues a constant-time-MAC `EscrowReceiptToken`. |
| `GET/POST /api/v1/marketplace/download` | Sovereign Guard + Escrow | Verifies `BuyerJurisdictionCertificate`, corporate CIDR, TPM 2.0 hash, and `EscrowReceiptToken` MAC, then streams buyer-watermarked `.jsonl` trajectories. |
| `POST /api/v1/marketplace/pool-merge` | Opt-In Required | Deduplicates pooled `SanitizedTrainingRecord` items across mesh peers by `blake3_record_hash` and computes `10,000 bps` revenue shares in `ContributionLedger`. |
| `GET /api/v1/marketplace/ledger` | Opt-In Required | Returns the latest and historical `ContributionLedger` payout tables. |
| `GET /api/v1/marketplace/bounties` | Opt-In Required | Lists active sovereign AI training data bounties matching `allowed_jurisdictions`. |

---

## 4. Verification Suite

```bash
cargo test -p quorum-coordinator --lib marketplace_engine -j 2
cargo test -p quorum-coordinator --lib bounty_runner -j 2
cargo test -p quorum-storage --lib dataset_builder -j 2
cargo test -p quorum-daemon --test marketplace_sovereign_escrow_tests -j 2
```
