## Why

The in-memory limiter caps the stamps it keeps per key, but not the number of keys it holds within one window. An attacker who rotates source addresses creates one key per address, or per IPv6 /64.

Measured on the current code:
- 1,000,000 distinct /64 keys cost about 149 MiB of heap;
- the next inline sweep then held the limiter's single lock for about 105 ms, stalling every guarded request in the process.

End sites are typically assigned a /56 or a /48, which is 256 to 65,536 /64 prefixes. An attacker with a larger allocation has far more. Grouping by /64 alone also lets such an attacker get a fresh allowance per /64.

## What Changes

- **An optional cap on keys held by the in-memory limiter.**
  - At the cap, new keys fail closed (they are refused as throttled).
  - The cap is stated, and so is its cost: an attacker at the cap refuses new sources.
  - The default is decided in design: 250,000 keys per limiter (design decision 1).
- **An aggregate IPv6 limit.** A second, coarser prefix (for example /48), counted alongside the /64, with its own limit. A single allocation cannot then multiply its allowance by rotating /64s.
- **Lock contention:** the in-memory limiter's sweep no longer stalls checks for the whole key set. The design chooses 64 shards with compaction, measured with a benchmark (design decision 3).
- **Unchanged:** inline pruning never removes a key whose newest failure is inside the window.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `rate-limiting`: the key cap, the aggregate prefix limit, and sweep latency bounds.
- `http-security-chain`: chain source guards count an IPv6 aggregate by default, with options to change or turn it off.

## Impact

- **Changed code:** `ratelimit` (memory limiter, keyer, guard), and an aggregate option in `httpsec`.
- **Evidence:** the 149 MiB and 105 ms figures are from an exploratory measurement during the `shared-rate-limiting` evaluation. They must be re-measured as this change's first benchmark.
- **Depends on:** `shared-rate-limiting`, which wires the IPv6 prefix through the chain.

## References

**Researched (accessed 2026-10-03):**
- [RFC 6177](https://www.rfc-editor.org/rfc/rfc6177): end sites are typically assigned /56 or /48 and at least one /64.
- [OWASP Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html): attackers rotate addresses through proxy networks.
