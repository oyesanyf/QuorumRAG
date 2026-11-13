## Empirical Verification: Milestone M9 Challenge Suite

Adds `scripts/challenge_m9_empirical.js` containing 13 automated adversarial stress tests verifying:
1. DNS queries (`WHAT PROCESS IS USING DNS TRAFFIC`, `WHAT FORENSIC PROCESS IS USING DNS TRAFFIC`) correctly route to `ForensicQueryIntent::DnsTraffic` with metadata pre-filtering.
2. CodeIntegrity logs (Event 3077) and generic EULAs are 100% prevented from drifting into DNS forensic answers, with process attribution (name, PID, protocol, port, domain) returned in a structured Markdown summary table.
3. Socket fallback and Dnscache/resolver cache queries execute on hosts without Sysmon.
4. `clean_chunk_text` preserves IPv4 addresses (`192.168.1.50`, `93.184.216.34:53`, etc.) across 50+ adversarial edge cases.
5. Homonym entity disambiguation (Angela Davis) cleanly separates 1981 scholar from New Orleans lessor, rejects remote distractors, and enforces zero pretraining backfill.
6. WiX MSI zero-touch PATH invariant (0 `<Environment>` tags).
7. Workspace version consistency at `0.6.6`.
